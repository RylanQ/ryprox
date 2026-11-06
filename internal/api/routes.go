// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rylanq/ryprox/internal/certs"
	"github.com/rylanq/ryprox/internal/config"
	"github.com/rylanq/ryprox/internal/console"
	"github.com/rylanq/ryprox/internal/proxy"
	"github.com/rylanq/ryprox/internal/store"
)

// routeView is a route plus its live status, for the dashboard.
type routeView struct {
	store.Route
	Health []proxy.TargetStatus `json:"health"`
	Cert   certs.Status         `json:"cert"`
}

func (s *Server) handleListRoutes(w http.ResponseWriter, r *http.Request, _ *store.User, _ *store.Session) {
	routes, err := s.Store.ListRoutes(r.Context())
	if err != nil {
		s.writeErr(w, err)
		return
	}
	health := s.Engine.Health()
	out := make([]routeView, 0, len(routes))
	for _, rt := range routes {
		out = append(out, routeView{Route: scrub(rt), Health: health[rt.ID], Cert: s.Certs.Status(rt.Hostname)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"routes": out, "httpsEnabled": s.Certs.Enabled()})
}

// check is passed to the store so a change is only saved if the resulting
// configuration is valid as a whole.
func (s *Server) check(all []store.Route) error {
	if err := config.CheckRoutes(all, s.Settings()); err != nil {
		return err
	}
	return s.Engine.Check(all)
}

// apply makes a saved change live.
func (s *Server) apply(all []store.Route, newHost string) {
	if err := s.Engine.Apply(all); err != nil {
		// Shouldn't happen: the same routes passed check() inside the transaction.
		s.Log.Error("could not apply routes", "err", err)
		return
	}
	if newHost != "" {
		s.Certs.Obtain(newHost)
	}
}

// scrub removes secrets before a route is sent to the browser.
func scrub(rt store.Route) store.Route {
	rt.Config.Console.HasPassword = rt.Config.Console.Password != ""
	rt.Config.Console.Password = ""
	return rt
}

// sealConsolePassword encrypts a newly entered console password, or keeps
// the saved one when the field was left empty.
func (s *Server) sealConsolePassword(rt, old *store.Route) error {
	k := &rt.Config.Console
	if !rt.Config.IsConsole() || k.Auth != store.ConsoleAuthStored {
		k.Password = ""
		return nil
	}
	switch {
	case k.Password != "":
		if len(k.Password) > 500 {
			return &config.FieldError{Field: "console.password", Message: "password is too long"}
		}
		sealed, err := s.Box.Seal(k.Password, console.PasswordPurpose)
		if err != nil {
			return err
		}
		k.Password = sealed
	case old != nil && old.Config.Console.Password != "" && old.Config.Console.Address == k.Address:
		k.Password = old.Config.Console.Password
	default:
		return &config.FieldError{Field: "console.password", Message: "enter the password to save"}
	}
	return nil
}

func (s *Server) readRoute(w http.ResponseWriter, r *http.Request) (*store.Route, bool) {
	var in struct {
		Hostname string            `json:"hostname"`
		Enabled  bool              `json:"enabled"`
		Config   store.RouteConfig `json:"config"`
	}
	if !readJSON(w, r, &in) {
		return nil, false
	}
	rt := &store.Route{Hostname: in.Hostname, Enabled: in.Enabled, Config: in.Config}
	if err := config.NormalizeRoute(rt); err != nil {
		s.writeErr(w, err)
		return nil, false
	}
	if err := s.checkAccessUsers(r, rt); err != nil {
		s.writeErr(w, err)
		return nil, false
	}
	if err := s.checkSites(r, rt); err != nil {
		s.writeErr(w, err)
		return nil, false
	}
	return rt, true
}

func (s *Server) handleCreateRoute(w http.ResponseWriter, r *http.Request, u *store.User, _ *store.Session) {
	rt, ok := s.readRoute(w, r)
	if !ok {
		return
	}
	if err := s.sealConsolePassword(rt, nil); err != nil {
		s.writeErr(w, err)
		return
	}
	all, err := s.Store.CreateRoute(r.Context(), rt, s.check)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	s.apply(all, rt.Hostname)
	s.audit(r, u.Username, "route.create", fmt.Sprintf("%s → %s", rt.Hostname, targetList(rt)))
	writeJSON(w, http.StatusCreated, scrub(*rt))
}

func (s *Server) handleUpdateRoute(w http.ResponseWriter, r *http.Request, u *store.User, _ *store.Session) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad id")
		return
	}
	rt, ok := s.readRoute(w, r)
	if !ok {
		return
	}
	rt.ID = id
	old, err := s.Store.GetRoute(r.Context(), id)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	if err := s.sealConsolePassword(rt, old); err != nil {
		s.writeErr(w, err)
		return
	}
	all, err := s.Store.UpdateRoute(r.Context(), rt, s.check)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	s.apply(all, rt.Hostname)
	s.audit(r, u.Username, "route.update", fmt.Sprintf("%s → %s", rt.Hostname, targetList(rt)))
	writeJSON(w, http.StatusOK, scrub(*rt))
}

func (s *Server) handleDeleteRoute(w http.ResponseWriter, r *http.Request, u *store.User, _ *store.Session) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad id")
		return
	}
	old, err := s.Store.GetRoute(r.Context(), id)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	all, err := s.Store.DeleteRoute(r.Context(), id, s.check)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	s.apply(all, "")
	s.audit(r, u.Username, "route.delete", old.Hostname)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleSetEnabled(w http.ResponseWriter, r *http.Request, u *store.User, _ *store.Session) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad id")
		return
	}
	var in struct {
		Enabled bool `json:"enabled"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	all, err := s.Store.SetRouteEnabled(r.Context(), id, in.Enabled, s.check)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	host := ""
	for _, rt := range all {
		if rt.ID == id {
			host = rt.Hostname
		}
	}
	if in.Enabled {
		s.apply(all, host)
	} else {
		s.apply(all, "")
	}
	action := "route.disable"
	if in.Enabled {
		action = "route.enable"
	}
	s.audit(r, u.Username, action, host)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func targetList(r *store.Route) string {
	if r.Config.IsConsole() {
		return r.Config.Kind + " " + r.Config.Console.Address
	}
	if r.Config.IsRedirect() {
		return "redirect to " + r.Config.Redirect.To
	}
	var t []string
	for _, x := range r.Config.AllTargets() {
		t = append(t, x.URL)
	}
	return strings.Join(t, ", ")
}

func (s *Server) handleTestTarget(w http.ResponseWriter, r *http.Request, _ *store.User, _ *store.Session) {
	var in struct {
		URL           string `json:"url"`
		TLSSkipVerify bool   `json:"tlsSkipVerify"`
		Path          string `json:"path"`
		Site          int64  `json:"site"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	u, err := config.NormalizeTargetURL("url", in.URL)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	path := "/"
	if in.Path != "" && strings.HasPrefix(in.Path, "/") && !strings.HasPrefix(in.Path, "//") {
		path = in.Path
	}
	writeJSON(w, http.StatusOK, s.Engine.TestTarget(r.Context(), u+path, in.TLSSkipVerify, in.Site))
}

func (s *Server) handleCertificates(w http.ResponseWriter, r *http.Request, _ *store.User, _ *store.Session) {
	routes, err := s.Store.ListRoutes(r.Context())
	if err != nil {
		s.writeErr(w, err)
		return
	}
	type row struct {
		certs.Status
		Purpose string `json:"purpose"`
	}
	out := []row{}
	st := s.Settings()
	if st.AdminHostname != "" {
		out = append(out, row{s.Certs.Status(st.AdminHostname), "Admin dashboard"})
	}
	if st.AuthHostname != "" && st.AuthHostname != st.AdminHostname {
		out = append(out, row{s.Certs.Status(st.AuthHostname), "Sign-in page"})
	}
	for _, rt := range routes {
		if rt.Enabled {
			out = append(out, row{s.Certs.Status(rt.Hostname), "Route"})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Purpose < out[j].Purpose })
	writeJSON(w, http.StatusOK, map[string]any{"certificates": out, "httpsEnabled": s.Certs.Enabled(), "staging": s.Settings().ACMEStaging})
}

func (s *Server) handleCertRetry(w http.ResponseWriter, r *http.Request, u *store.User, _ *store.Session) {
	host := r.PathValue("host")
	s.Certs.Obtain(host) // no-op unless host is configured
	s.audit(r, u.Username, "certificate.retry", host)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleGetSettings(w http.ResponseWriter, _ *http.Request, _ *store.User, _ *store.Session) {
	writeJSON(w, http.StatusOK, s.Settings())
}

func (s *Server) handlePutSettings(w http.ResponseWriter, r *http.Request, u *store.User, _ *store.Session) {
	var in store.Settings
	if !readJSON(w, r, &in) {
		return
	}
	if err := config.NormalizeSettings(&in); err != nil {
		s.writeErr(w, err)
		return
	}
	routes, err := s.Store.ListRoutes(r.Context())
	if err != nil {
		s.writeErr(w, err)
		return
	}
	for _, rt := range routes {
		if in.AdminHostname != "" && rt.Hostname == in.AdminHostname {
			writeJSON(w, http.StatusBadRequest, apiError{Error: in.AdminHostname + " is already used by a route", Field: "adminHostname"})
			return
		}
		if in.AuthHostname != "" && rt.Hostname == in.AuthHostname {
			writeJSON(w, http.StatusBadRequest, apiError{Error: in.AuthHostname + " is already used by a route", Field: "authHostname"})
			return
		}
	}
	if err := s.Store.SaveSettings(r.Context(), in); err != nil {
		s.writeErr(w, err)
		return
	}
	s.settings.Store(&in)
	s.Certs.Configure(in)
	if in.AdminHostname != "" {
		s.Certs.Obtain(in.AdminHostname)
	}
	if in.AuthHostname != "" {
		s.Certs.Obtain(in.AuthHostname)
	}
	for _, rt := range routes {
		if rt.Enabled {
			s.Certs.Obtain(rt.Hostname)
		}
	}
	mode := "HTTP only"
	if in.TLSMode == store.TLSModeACME {
		mode = "automatic HTTPS"
		if in.ACMEStaging {
			mode += " (test certificates)"
		}
	}
	s.audit(r, u.Username, "settings.update", mode)
	writeJSON(w, http.StatusOK, in)
}

func (s *Server) handleActivity(w http.ResponseWriter, r *http.Request, _ *store.User, _ *store.Session) {
	list, err := s.Store.ListAudit(r.Context(), 200)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// handleActivityExport downloads the audit log as CSV or JSON.
func (s *Server) handleActivityExport(w http.ResponseWriter, r *http.Request, u *store.User, _ *store.Session) {
	list, err := s.Store.ListAudit(r.Context(), 100000)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	stamp := time.Now().UTC().Format("2006-01-02")
	s.audit(r, u.Username, "activity.export", r.URL.Query().Get("format"))
	if r.URL.Query().Get("format") == "json" {
		w.Header().Set("Content-Disposition", `attachment; filename="ryprox-activity-`+stamp+`.json"`)
		writeJSON(w, http.StatusOK, list)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="ryprox-activity-`+stamp+`.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"time", "actor", "action", "detail", "ip"})
	for _, e := range list {
		_ = cw.Write([]string{e.At.UTC().Format(time.RFC3339), csvSafe(e.Actor), csvSafe(e.Action), csvSafe(e.Detail), csvSafe(e.IP)})
	}
	cw.Flush()
}

// csvSafe stops spreadsheet apps treating a cell as a formula.
func csvSafe(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}
