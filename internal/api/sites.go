// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/rylanq/ryprox/internal/auth"
	"github.com/rylanq/ryprox/internal/config"
	"github.com/rylanq/ryprox/internal/store"
	"github.com/rylanq/ryprox/internal/tunnel"
)

type siteView struct {
	store.Site
	Online bool                 `json:"online"`
	Agents []tunnel.AgentStatus `json:"agents"`
}

func (s *Server) handleListSites(w http.ResponseWriter, r *http.Request, _ *store.User, _ *store.Session) {
	sites, err := s.Store.ListSites(r.Context())
	if err != nil {
		s.writeErr(w, err)
		return
	}
	status := map[int64][]tunnel.AgentStatus{}
	if s.Tunnels != nil {
		status = s.Tunnels.Status()
	}
	out := make([]siteView, 0, len(sites))
	for _, x := range sites {
		v := siteView{Site: x, Agents: status[x.ID]}
		if v.Agents == nil {
			v.Agents = []tunnel.AgentStatus{}
		}
		v.Online = len(v.Agents) > 0
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{"sites": out, "server": s.tunnelServerURL()})
}

// tunnelServerURL is the address agents connect to.
func (s *Server) tunnelServerURL() string {
	if h := s.Settings().SignInHostname(); h != "" {
		return s.siteURL(h)
	}
	return ""
}

func newSiteToken() (string, []byte, error) {
	raw, err := auth.NewToken()
	if err != nil {
		return "", nil, err
	}
	raw = tunnel.TokenPrefix + raw
	return raw, auth.HashToken(raw), nil
}

func (s *Server) handleCreateSite(w http.ResponseWriter, r *http.Request, u *store.User, _ *store.Session) {
	var in struct {
		Name string `json:"name"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || utf8.RuneCountInString(in.Name) > 60 || strings.ContainsAny(in.Name, "\r\n\x00") {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "give the site a short name, like \"Home\"", Field: "name"})
		return
	}
	raw, hash, err := newSiteToken()
	if err != nil {
		s.writeErr(w, err)
		return
	}
	site := &store.Site{Name: in.Name, TokenHash: hash}
	if err := s.Store.CreateSite(r.Context(), site); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeJSON(w, http.StatusConflict, apiError{Error: "a site with this name already exists", Field: "name"})
			return
		}
		s.writeErr(w, err)
		return
	}
	s.audit(r, u.Username, "site.create", in.Name)
	writeJSON(w, http.StatusCreated, map[string]any{"site": site, "token": raw, "server": s.tunnelServerURL()})
}

func (s *Server) handleSiteToken(w http.ResponseWriter, r *http.Request, u *store.User, _ *store.Session) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusNotFound, "site not found")
		return
	}
	raw, hash, err := newSiteToken()
	if err != nil {
		s.writeErr(w, err)
		return
	}
	if err := s.Store.SetSiteToken(r.Context(), id, hash); err != nil {
		s.writeErr(w, err)
		return
	}
	if s.Tunnels != nil {
		s.Tunnels.Disconnect(id)
	}
	s.audit(r, u.Username, "site.new_token", strconv.FormatInt(id, 10))
	writeJSON(w, http.StatusOK, map[string]any{"token": raw, "server": s.tunnelServerURL()})
}

func (s *Server) handleDeleteSite(w http.ResponseWriter, r *http.Request, u *store.User, _ *store.Session) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusNotFound, "site not found")
		return
	}
	if err := s.Store.DeleteSite(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrSiteInUse) {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		s.writeErr(w, err)
		return
	}
	if s.Tunnels != nil {
		s.Tunnels.Disconnect(id)
	}
	s.audit(r, u.Username, "site.delete", strconv.FormatInt(id, 10))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleTunnel accepts an agent's connection on the sign-in domain.
func (s *Server) handleTunnel(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.portalRealm(r); !ok || s.Tunnels == nil {
		http.NotFound(w, r)
		return
	}
	ipKey := "tunnel:" + clientKey(r)
	if ok, _ := s.ipLimit.Check(ipKey); !ok {
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return
	}
	raw := ""
	if a := r.Header.Get("Authorization"); len(a) > 7 && strings.EqualFold(a[:7], "bearer ") {
		raw = strings.TrimSpace(a[7:])
	}
	if !strings.HasPrefix(raw, tunnel.TokenPrefix) || len(raw) > 100 {
		http.Error(w, "token required", http.StatusUnauthorized)
		return
	}
	site, err := s.Store.GetSiteByToken(r.Context(), auth.HashToken(raw))
	if err != nil {
		s.ipLimit.Fail(ipKey)
		http.Error(w, "token not valid", http.StatusUnauthorized)
		return
	}
	_ = s.Store.TouchSite(r.Context(), site.ID)
	s.audit(r, "connector", "site.connect", site.Name)
	// The tunnel outlives this request's handler deadline; it ends when the
	// agent disconnects or the site is deleted.
	s.Tunnels.Serve(r.Context(), w, r, site.ID)
}

// checkSites makes sure every site a route refers to exists.
func (s *Server) checkSites(r *http.Request, rt *store.Route) error {
	ids := map[int64]string{}
	for i, t := range rt.Config.Targets {
		if t.Site != 0 {
			ids[t.Site] = "targets." + strconv.Itoa(i)
		}
	}
	for i, p := range rt.Config.Paths {
		for j, t := range p.Targets {
			if t.Site != 0 {
				ids[t.Site] = "paths." + strconv.Itoa(i) + ".targets." + strconv.Itoa(j)
			}
		}
	}
	if k := rt.Config.Console; rt.Config.IsConsole() && k.Site != 0 {
		if rt.Config.Kind != store.KindSSH {
			return &config.FieldError{Field: "console.site", Message: "remote desktops through a site connector aren't supported yet; use a terminal, or reach the PC directly"}
		}
		ids[k.Site] = "console.site"
	}
	for id, field := range ids {
		ok, err := s.Store.SiteExists(r.Context(), id)
		if err != nil {
			return err
		}
		if !ok {
			return &config.FieldError{Field: field, Message: "that site doesn't exist any more"}
		}
	}
	return nil
}
