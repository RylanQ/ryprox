// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/rylanq/ryprox/internal/auth"
	"github.com/rylanq/ryprox/internal/cluster"
	"github.com/rylanq/ryprox/internal/store"
)

func (s *Server) handleListNodes(w http.ResponseWriter, r *http.Request, _ *store.User, _ *store.Session) {
	out := map[string]any{"primary": s.tunnelServerURL()}
	if s.Follower != nil {
		out["follower"] = s.Follower.Status()
		out["nodes"] = []store.Node{}
		writeJSON(w, http.StatusOK, out)
		return
	}
	nodes, err := s.Store.ListNodes(r.Context())
	if err != nil {
		s.writeErr(w, err)
		return
	}
	out["nodes"] = nodes
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleCreateNode(w http.ResponseWriter, r *http.Request, u *store.User, _ *store.Session) {
	var in struct {
		Name string `json:"name"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || utf8.RuneCountInString(in.Name) > 60 || strings.ContainsAny(in.Name, "\r\n\x00") {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "give the server a short name, like \"backup\"", Field: "name"})
		return
	}
	raw, err := auth.NewToken()
	if err != nil {
		s.writeErr(w, err)
		return
	}
	raw = cluster.TokenPrefix + raw
	n := &store.Node{Name: in.Name, TokenHash: auth.HashToken(raw)}
	if err := s.Store.CreateNode(r.Context(), n); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeJSON(w, http.StatusConflict, apiError{Error: "a server with this name already exists", Field: "name"})
			return
		}
		s.writeErr(w, err)
		return
	}
	s.audit(r, u.Username, "node.create", in.Name)
	writeJSON(w, http.StatusCreated, map[string]any{"node": n, "token": raw, "primary": s.tunnelServerURL()})
}

func (s *Server) handleDeleteNode(w http.ResponseWriter, r *http.Request, u *store.User, _ *store.Session) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusNotFound, "server not found")
		return
	}
	if err := s.Store.DeleteNode(r.Context(), id); err != nil {
		s.writeErr(w, err)
		return
	}
	s.audit(r, u.Username, "node.delete", strconv.FormatInt(id, 10))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleNodeSync sends a follower the configuration, secret key and
// certificates. It needs the follower's token and HTTPS.
func (s *Server) handleNodeSync(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.portalRealm(r); !ok || s.Follower != nil || s.DataDir == "" {
		http.NotFound(w, r)
		return
	}
	ipKey := "node:" + clientKey(r)
	if ok, _ := s.ipLimit.Check(ipKey); !ok {
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return
	}
	raw := ""
	if a := r.Header.Get("Authorization"); len(a) > 7 && strings.EqualFold(a[:7], "bearer ") {
		raw = strings.TrimSpace(a[7:])
	}
	if !strings.HasPrefix(raw, cluster.TokenPrefix) || len(raw) > 100 {
		http.Error(w, "token required", http.StatusUnauthorized)
		return
	}
	n, err := s.Store.GetNodeByToken(r.Context(), auth.HashToken(raw))
	if err != nil {
		s.ipLimit.Fail(ipKey)
		http.Error(w, "token not valid", http.StatusUnauthorized)
		return
	}
	_ = s.Store.TouchNode(r.Context(), n.ID, clientIP(r))
	certDir := ""
	if s.Certs != nil {
		certDir = s.Certs.CacheSubdir()
	}
	p, err := cluster.BuildPayload(r.Context(), s.Store, s.DataDir, certDir)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	if r.Header.Get("If-None-Match") == p.Hash {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, p)
}

// Reload re-reads settings and routes from the store and makes them live
// (after a follower imported a snapshot).
func (s *Server) Reload(ctx context.Context) error {
	st, err := s.Store.GetSettings(ctx)
	if err != nil {
		return err
	}
	s.settings.Store(&st)
	routes, err := s.Store.ListRoutes(ctx)
	if err != nil {
		return err
	}
	if s.Certs != nil {
		s.Certs.Configure(st)
	}
	return s.Engine.Apply(routes)
}

// followerWrites lists changes a follower still allows: signing in and out.
// Everything else is made on the primary and would be overwritten here.
func followerAllows(method, path string) bool {
	if method == http.MethodGet || method == http.MethodHead {
		return true
	}
	for _, p := range []string{"/api/login", "/api/logout", "/.ryprox/api/login", "/.ryprox/api/logout", "/.ryprox/api/continue"} {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

func (s *Server) readOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.Follower != nil && !followerAllows(r.Method, r.URL.Path) {
			writeError(w, http.StatusConflict, "this server mirrors "+s.Follower.Primary+"; make changes there")
			return
		}
		next.ServeHTTP(w, r)
	})
}
