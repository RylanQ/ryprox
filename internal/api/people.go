// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"github.com/rylanq/ryprox/internal/auth"
	"github.com/rylanq/ryprox/internal/config"
	"github.com/rylanq/ryprox/internal/proxy"
	"github.com/rylanq/ryprox/internal/store"
)

type personView struct {
	ID          int64     `json:"id"`
	Username    string    `json:"username"`
	Email       string    `json:"email"`
	Role        string    `json:"role"`
	Disabled    bool      `json:"disabled"`
	CreatedAt   time.Time `json:"createdAt"`
	LastLoginAt time.Time `json:"lastLoginAt,omitzero"`
	Sites       []string  `json:"sites"`
}

func (s *Server) handleListPeople(w http.ResponseWriter, r *http.Request, me *store.User, _ *store.Session) {
	users, err := s.Store.ListUsers(r.Context())
	if err != nil {
		s.writeErr(w, err)
		return
	}
	invites, err := s.Store.ListInvites(r.Context())
	if err != nil {
		s.writeErr(w, err)
		return
	}
	routes, err := s.Store.ListRoutes(r.Context())
	if err != nil {
		s.writeErr(w, err)
		return
	}
	out := make([]personView, 0, len(users))
	for _, u := range users {
		p := personView{ID: u.ID, Username: u.Username, Email: u.Email, Role: u.Role, Disabled: u.Disabled,
			CreatedAt: u.CreatedAt, LastLoginAt: u.LastLoginAt, Sites: []string{}}
		for _, rt := range routes {
			if !rt.Config.Access.IsPublic() && rt.Config.Access.Allows(u.ID) {
				p.Sites = append(p.Sites, rt.Hostname)
			}
		}
		out = append(out, p)
	}
	writeJSON(w, http.StatusOK, map[string]any{"people": out, "invites": invites, "me": me.ID})
}

// inviteBase picks the HTTPS address where someone can accept an invite.
func (s *Server) inviteBase() string {
	// Invites are only ever opened on RyProx's own sign-in domain, never on
	// a route's domain, where the backend could read the token.
	if h := s.Settings().SignInHostname(); h != "" && s.Certs.Enabled() {
		return s.siteURL(h)
	}
	return ""
}

func (s *Server) handleCreateInvite(w http.ResponseWriter, r *http.Request, me *store.User, _ *store.Session) {
	var in struct {
		Username string  `json:"username"`
		Role     string  `json:"role"`
		Routes   []int64 `json:"routes"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	in.Username = strings.TrimSpace(in.Username)
	if err := validUsername(in.Username); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error(), Field: "username"})
		return
	}
	if in.Role != store.RoleAdmin && in.Role != store.RoleMember {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "choose a role", Field: "role"})
		return
	}
	routes, err := s.Store.ListRoutes(r.Context())
	if err != nil {
		s.writeErr(w, err)
		return
	}
	known := map[int64]bool{}
	for _, rt := range routes {
		known[rt.ID] = true
	}
	grant := []int64{}
	for _, id := range in.Routes {
		if !known[id] {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "one of the chosen sites no longer exists", Field: "routes"})
			return
		}
		grant = append(grant, id)
	}
	token, err := auth.NewToken()
	if err != nil {
		s.writeErr(w, err)
		return
	}
	now := time.Now()
	inv := &store.Invite{TokenHash: auth.HashToken(token), Username: in.Username, Role: in.Role, Routes: grant,
		CreatedBy: me.Username, CreatedAt: now, ExpiresAt: now.Add(inviteTTL)}
	if err := s.Store.CreateInvite(r.Context(), inv); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeJSON(w, http.StatusConflict, apiError{Error: "someone already has that username", Field: "username"})
			return
		}
		s.writeErr(w, err)
		return
	}
	// The token goes after # so it never reaches server logs or Referer headers.
	path := proxy.PortalPrefix + "invite#" + token
	full := ""
	if base := s.inviteBase(); base != "" {
		full = base + path
	}
	s.audit(r, me.Username, "user.invite", fmt.Sprintf("%s (%s)", inv.Username, inv.Role))
	// Without an HTTPS address, "url" is empty and the dashboard uses its own.
	writeJSON(w, http.StatusCreated, map[string]any{"invite": inv, "path": path, "url": full, "https": full != ""})
}

func (s *Server) handleDeleteInvite(w http.ResponseWriter, r *http.Request, me *store.User, _ *store.Session) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad id")
		return
	}
	if err := s.Store.DeleteInvite(r.Context(), id); err != nil {
		s.writeErr(w, err)
		return
	}
	s.audit(r, me.Username, "user.invite_cancel", fmt.Sprintf("invite %d", id))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleUpdatePerson(w http.ResponseWriter, r *http.Request, me *store.User, _ *store.Session) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad id")
		return
	}
	var in struct {
		Role     string `json:"role"`
		Disabled bool   `json:"disabled"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if id == me.ID {
		writeError(w, http.StatusBadRequest, "you can't change your own role or disable yourself; ask another admin")
		return
	}
	if in.Role != store.RoleAdmin && in.Role != store.RoleMember {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "choose a role", Field: "role"})
		return
	}
	target, err := s.Store.GetUser(r.Context(), id)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	if err := s.Store.UpdateUserAccess(r.Context(), id, in.Role, in.Disabled); err != nil {
		if errors.Is(err, store.ErrLastAdmin) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.writeErr(w, err)
		return
	}
	what := "role " + in.Role
	if in.Disabled {
		what += ", disabled and signed out"
	}
	s.audit(r, me.Username, "user.update", target.Username+": "+what)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleDeletePerson(w http.ResponseWriter, r *http.Request, me *store.User, _ *store.Session) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad id")
		return
	}
	if id == me.ID {
		writeError(w, http.StatusBadRequest, "you can't remove yourself; ask another admin")
		return
	}
	target, err := s.Store.GetUser(r.Context(), id)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	if err := s.Store.DeleteUser(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrLastAdmin) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.writeErr(w, err)
		return
	}
	// The user was also taken off every access list; make that live.
	if all, err := s.Store.ListRoutes(r.Context()); err == nil {
		s.apply(all, "")
	}
	s.audit(r, me.Username, "user.delete", target.Username)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// checkAccessUsers makes sure every person on a route's access list exists.
func (s *Server) checkAccessUsers(r *http.Request, rt *store.Route) error {
	if len(rt.Config.Access.Users) == 0 {
		return nil
	}
	users, err := s.Store.ListUsers(r.Context())
	if err != nil {
		return err
	}
	known := map[int64]bool{}
	for _, u := range users {
		known[u.ID] = true
	}
	for _, id := range rt.Config.Access.Users {
		if !known[id] {
			return &config.FieldError{Field: "access.users", Message: "one of the chosen people no longer exists; reload and try again"}
		}
	}
	return nil
}

// handleSetEmail sets the email used to match someone's single sign-on
// account. Changing it unlinks any sign-on account matched by the old one.
func (s *Server) handleSetEmail(w http.ResponseWriter, r *http.Request, me *store.User, _ *store.Session) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad id")
		return
	}
	var in struct {
		Email string `json:"email"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	in.Email = strings.TrimSpace(in.Email)
	if in.Email != "" {
		a, err := mail.ParseAddress(in.Email)
		if err != nil || a.Address != in.Email || len(in.Email) > 254 {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "enter a valid email address, or leave it empty", Field: "email"})
			return
		}
	}
	target, err := s.Store.GetUser(r.Context(), id)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	if err := s.Store.SetEmail(r.Context(), id, in.Email); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeJSON(w, http.StatusConflict, apiError{Error: "someone else already uses this email address", Field: "email"})
			return
		}
		s.writeErr(w, err)
		return
	}
	s.audit(r, me.Username, "user.email", target.Username+": "+in.Email)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
