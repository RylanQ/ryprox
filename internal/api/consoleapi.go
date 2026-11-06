// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"net/http"
	"strconv"

	"github.com/rylanq/ryprox/internal/console"
	"github.com/rylanq/ryprox/internal/store"
)

func (s *Server) handleGetConsole(w http.ResponseWriter, r *http.Request, _ *store.User, _ *store.Session) {
	if s.Console == nil {
		writeError(w, http.StatusServiceUnavailable, "consoles aren't available")
		return
	}
	pub, err := s.Console.PublicKey(r.Context())
	if err != nil {
		s.writeErr(w, err)
		return
	}
	addr := s.Console.Guacd(r.Context())
	out := map[string]any{"publicKey": pub, "guacd": addr, "guacdOk": true}
	if err := console.CheckGuacd(r.Context(), addr); err != nil {
		out["guacdOk"], out["guacdError"] = false, err.Error()
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handlePutConsole(w http.ResponseWriter, r *http.Request, u *store.User, _ *store.Session) {
	var in struct {
		Guacd string `json:"guacd"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if s.Console == nil {
		writeError(w, http.StatusServiceUnavailable, "consoles aren't available")
		return
	}
	if err := s.Console.SetGuacd(r.Context(), in.Guacd); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error(), Field: "guacd"})
		return
	}
	s.audit(r, u.Username, "settings.guacd", in.Guacd)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleRouteHostKey(w http.ResponseWriter, r *http.Request, _ *store.User, _ *store.Session) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || s.Console == nil {
		writeError(w, http.StatusNotFound, "route not found")
		return
	}
	rt, err := s.Store.GetRoute(r.Context(), id)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"learned": s.Console.LearnedHostKey(r.Context(), rt)})
}

func (s *Server) handleForgetHostKey(w http.ResponseWriter, r *http.Request, u *store.User, _ *store.Session) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || s.Console == nil {
		writeError(w, http.StatusNotFound, "route not found")
		return
	}
	if err := s.Console.ForgetHostKey(r.Context(), id); err != nil {
		s.writeErr(w, err)
		return
	}
	s.audit(r, u.Username, "route.forget_host_key", strconv.FormatInt(id, 10))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
