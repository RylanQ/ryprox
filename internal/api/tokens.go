// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/rylanq/ryprox/internal/auth"
	"github.com/rylanq/ryprox/internal/proxy"
	"github.com/rylanq/ryprox/internal/store"
)

// Access tokens let scripts and API clients use RyProx without a browser:
// a "sites" token opens the private sites its owner may open, and an
// "admin" token (admins only) uses the dashboard's API. Only a hash is kept.

const maxTokensPerUser = 50

// bearerToken returns a RyProx token from an Authorization header, or "".
func bearerToken(r *http.Request) string {
	a := r.Header.Get("Authorization")
	if len(a) > 7 && strings.EqualFold(a[:7], "bearer ") {
		if t := strings.TrimSpace(a[7:]); strings.HasPrefix(t, proxy.TokenPrefix) {
			return t
		}
	}
	return ""
}

// tokenUser checks a raw token for scope and returns its owner. Failed
// guesses count against the caller's address.
func (s *Server) tokenUser(ctx context.Context, r *http.Request, raw, scope string) (*store.User, *store.Token) {
	if !strings.HasPrefix(raw, proxy.TokenPrefix) || len(raw) > 100 {
		return nil, nil
	}
	ipKey := "token:" + clientKey(r)
	if ok, _ := s.ipLimit.Check(ipKey); !ok {
		return nil, nil
	}
	t, err := s.Store.GetTokenByHash(ctx, auth.HashToken(raw))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.ipLimit.Fail(ipKey)
		}
		return nil, nil
	}
	if t.Scope != scope || (!t.ExpiresAt.IsZero() && time.Now().After(t.ExpiresAt)) {
		return nil, nil
	}
	u, err := s.Store.GetUser(ctx, t.UserID)
	if err != nil || u.Disabled || (scope == store.ScopeAdmin && u.Role != store.RoleAdmin) {
		return nil, nil
	}
	_ = s.Store.TouchToken(ctx, t.ID)
	return u, t
}

// authorizeToken lets an API client open a private route with a sites token.
func (s *Server) authorizeToken(r *http.Request, route *store.Route, raw string) (string, func() bool, bool) {
	u, t := s.tokenUser(r.Context(), r, raw, store.ScopeSites)
	if u == nil || !route.Config.Access.Allows(u.ID) {
		return "", nil, false
	}
	tokenHash, userID, host := t.Hash, u.ID, route.Hostname
	stillAllowed := func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cur, err := s.Store.GetTokenByHash(ctx, tokenHash)
		if err != nil || (!cur.ExpiresAt.IsZero() && time.Now().After(cur.ExpiresAt)) {
			return false
		}
		usr, err := s.Store.GetUser(ctx, userID)
		if err != nil || usr.Disabled {
			return false
		}
		rt, ok := s.Engine.Route(host)
		return ok && (rt.Config.Access.IsPublic() || rt.Config.Access.Allows(userID))
	}
	return u.Username, stillAllowed, true
}

func (s *Server) listTokens(w http.ResponseWriter, r *http.Request, u *store.User) {
	ts, err := s.Store.ListTokens(r.Context(), u.ID)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": ts})
}

func (s *Server) createToken(w http.ResponseWriter, r *http.Request, u *store.User, allowAdmin bool) {
	var in struct {
		Name    string `json:"name"`
		Scope   string `json:"scope"`
		Expires int    `json:"expiresDays"` // 0: never
	}
	if !readJSON(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || utf8.RuneCountInString(in.Name) > 60 || strings.ContainsAny(in.Name, "\r\n\x00") {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "give the token a short name, like \"backup script\"", Field: "name"})
		return
	}
	switch in.Scope {
	case store.ScopeSites:
	case store.ScopeAdmin:
		if !allowAdmin || u.Role != store.RoleAdmin {
			writeJSON(w, http.StatusForbidden, apiError{Error: "only admins can create admin tokens", Field: "scope"})
			return
		}
	default:
		writeJSON(w, http.StatusBadRequest, apiError{Error: "choose what the token can do", Field: "scope"})
		return
	}
	if in.Expires < 0 || in.Expires > 3650 {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "expiry must be between 0 (never) and 3650 days", Field: "expiresDays"})
		return
	}
	existing, err := s.Store.ListTokens(r.Context(), u.ID)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	if len(existing) >= maxTokensPerUser {
		writeError(w, http.StatusBadRequest, "you have too many tokens; delete some you no longer use")
		return
	}
	raw, err := auth.NewToken()
	if err != nil {
		s.writeErr(w, err)
		return
	}
	raw = proxy.TokenPrefix + raw
	t := &store.Token{UserID: u.ID, Name: in.Name, Hash: auth.HashToken(raw), Scope: in.Scope}
	if in.Expires > 0 {
		t.ExpiresAt = time.Now().AddDate(0, 0, in.Expires).Truncate(time.Second)
	}
	if err := s.Store.CreateToken(r.Context(), t); err != nil {
		s.writeErr(w, err)
		return
	}
	s.audit(r, u.Username, "token.create", in.Name+" ("+in.Scope+")")
	writeJSON(w, http.StatusOK, map[string]any{"token": raw, "info": t})
}

func (s *Server) deleteToken(w http.ResponseWriter, r *http.Request, u *store.User) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusNotFound, "token not found")
		return
	}
	if err := s.Store.DeleteToken(r.Context(), u.ID, id); err != nil {
		s.writeErr(w, err)
		return
	}
	s.audit(r, u.Username, "token.delete", strconv.FormatInt(id, 10))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
