// SPDX-License-Identifier: AGPL-3.0-only

// Package api serves the admin dashboard: its JSON API and its web pages.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rylanq/ryprox/internal/auth"
	"github.com/rylanq/ryprox/internal/certs"
	"github.com/rylanq/ryprox/internal/config"
	"github.com/rylanq/ryprox/internal/proxy"
	"github.com/rylanq/ryprox/internal/secrets"
	"github.com/rylanq/ryprox/internal/store"
	"github.com/rylanq/ryprox/internal/version"
)

// Session lifetimes.
const (
	sessionIdle     = 12 * time.Hour
	sessionAbsolute = 7 * 24 * time.Hour
	pendingLoginTTL = 5 * time.Minute
	maxBodyBytes    = 1 << 20
)

// Server is the admin API and UI.
type Server struct {
	Store  *store.Store
	Engine *proxy.Engine
	Certs  *certs.Manager
	Box    *secrets.Box
	Log    *slog.Logger
	UI     fs.FS // the web/static directory

	settings atomic.Pointer[store.Settings]

	limiter *auth.Limiter // per username
	ipLimit *auth.Limiter // per client IP

	mu        sync.Mutex
	setupHash []byte // hash of the one-time setup code; nil once set up
	pending   map[string]pendingLogin
}

type pendingLogin struct {
	userID  int64
	ip      string
	expires time.Time
}

// New prepares the server: loads settings and, on a fresh install,
// creates a one-time setup code which it returns (empty if already set up).
func New(ctx context.Context, s *Server) (setupCode string, err error) {
	s.limiter = auth.NewLimiter()
	s.ipLimit = auth.NewLimiter()
	s.pending = map[string]pendingLogin{}
	st, err := s.Store.GetSettings(ctx)
	if err != nil {
		return "", err
	}
	s.settings.Store(&st)
	n, err := s.Store.CountUsers(ctx)
	if err != nil {
		return "", err
	}
	if n == 0 {
		codes, _, err := auth.NewRecoveryCodes(1)
		if err != nil {
			return "", err
		}
		setupCode = strings.ToUpper(codes[0])
		s.setupHash = auth.HashToken(normalizeSetupCode(setupCode))
	}
	return setupCode, nil
}

func normalizeSetupCode(c string) string {
	return strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(c)))
}

// Settings returns the current settings.
func (s *Server) Settings() store.Settings { return *s.settings.Load() }

// Handler returns the admin HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Public endpoints.
	mux.HandleFunc("GET /api/state", s.handleState)
	mux.HandleFunc("POST /api/setup/begin", s.handleSetupBegin)
	mux.HandleFunc("POST /api/setup/finish", s.handleSetupFinish)
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/login/verify", s.handleLoginVerify)

	// Endpoints that need a logged-in admin.
	priv := func(pattern string, h func(http.ResponseWriter, *http.Request, *store.User, *store.Session)) {
		mux.Handle(pattern, s.requireSession(h))
	}
	priv("POST /api/logout", s.handleLogout)
	priv("GET /api/routes", s.handleListRoutes)
	priv("POST /api/routes", s.handleCreateRoute)
	priv("PUT /api/routes/{id}", s.handleUpdateRoute)
	priv("DELETE /api/routes/{id}", s.handleDeleteRoute)
	priv("POST /api/routes/{id}/enabled", s.handleSetEnabled)
	priv("POST /api/test-target", s.handleTestTarget)
	priv("GET /api/certificates", s.handleCertificates)
	priv("POST /api/certificates/{host}/retry", s.handleCertRetry)
	priv("GET /api/settings", s.handleGetSettings)
	priv("PUT /api/settings", s.handlePutSettings)
	priv("GET /api/activity", s.handleActivity)
	priv("POST /api/account/password", s.handleChangePassword)
	priv("GET /api/account/sessions", s.handleListSessions)
	priv("DELETE /api/account/sessions/{id}", s.handleDeleteSession)
	priv("POST /api/account/sessions/revoke-others", s.handleRevokeOthers)
	priv("POST /api/account/recovery-codes", s.handleNewRecoveryCodes)

	mux.HandleFunc("/api/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "unknown API endpoint")
	})

	// The dashboard itself: static files, with index.html for the root.
	files := http.FileServerFS(s.UI)
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Cache-Control", "no-cache")
		files.ServeHTTP(w, r)
	}))

	return s.securityHeaders(s.csrfProtect(mux))
}

// securityHeaders hardens every admin response against common attacks.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "+
			"connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

// csrfProtect blocks cross-site requests that try to change things.
// Browsers won't send a custom header cross-site without permission (which
// we never grant), and Sec-Fetch-Site/Origin confirm the request's source.
func (s *Server) csrfProtect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		if r.Header.Get("X-RyProx") != "1" {
			writeError(w, http.StatusForbidden, "missing request header")
			return
		}
		if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
			writeError(w, http.StatusForbidden, "cross-site request blocked")
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			o := strings.TrimPrefix(strings.TrimPrefix(origin, "https://"), "http://")
			if !strings.EqualFold(o, r.Host) {
				writeError(w, http.StatusForbidden, "cross-origin request blocked")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// --- sessions ----------------------------------------------------------

type ctxUser struct{}

func cookieName(r *http.Request) string {
	if r.TLS != nil {
		return "__Host-ryprox" // __Host- cookies must be Secure and host-only
	}
	return "ryprox"
}

func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName(r),
		Value:    token,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: cookieName(r), Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
}

// currentSession returns the logged-in user, or nil.
func (s *Server) currentSession(r *http.Request) (*store.User, *store.Session) {
	c, err := r.Cookie(cookieName(r))
	if err != nil || c.Value == "" || len(c.Value) > 100 {
		return nil, nil
	}
	ctx := r.Context()
	sess, err := s.Store.GetSessionByHash(ctx, auth.HashToken(c.Value))
	if err != nil {
		return nil, nil
	}
	now := time.Now()
	if now.After(sess.ExpiresAt) || now.Sub(sess.LastSeenAt) > sessionIdle {
		_ = s.Store.DeleteSession(ctx, sess.UserID, sess.ID)
		return nil, nil
	}
	u, err := s.Store.GetUser(ctx, sess.UserID)
	if err != nil {
		return nil, nil
	}
	if now.Sub(sess.LastSeenAt) > time.Minute {
		_ = s.Store.TouchSession(ctx, sess.ID, now)
	}
	return u, sess
}

func (s *Server) requireSession(h func(http.ResponseWriter, *http.Request, *store.User, *store.Session)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, sess := s.currentSession(r)
		if u == nil {
			writeError(w, http.StatusUnauthorized, "please log in")
			return
		}
		h(w, r, u, sess)
	})
}

func (s *Server) startSession(w http.ResponseWriter, r *http.Request, userID int64) error {
	token, err := auth.NewToken()
	if err != nil {
		return err
	}
	now := time.Now()
	ua := r.UserAgent()
	if len(ua) > 300 {
		ua = ua[:300]
	}
	sess := &store.Session{TokenHash: auth.HashToken(token), UserID: userID, CreatedAt: now, LastSeenAt: now,
		ExpiresAt: now.Add(sessionAbsolute), IP: clientIP(r), UserAgent: ua}
	if err := s.Store.CreateSession(r.Context(), sess); err != nil {
		return err
	}
	s.setSessionCookie(w, r, token, sess.ExpiresAt)
	return nil
}

// Cleanup removes expired sessions and pending logins. Call periodically.
func (s *Server) Cleanup(ctx context.Context) {
	_ = s.Store.DeleteExpiredSessions(ctx, time.Now(), sessionIdle)
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, p := range s.pending {
		if time.Now().After(p.expires) {
			delete(s.pending, k)
		}
	}
}

// --- helpers -------------------------------------------------------------

// clientIP is the connecting address. X-Forwarded-For is deliberately
// ignored: RyProx is the edge, so anyone could forge it.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func isLoopback(r *http.Request) bool {
	ip := net.ParseIP(clientIP(r))
	return ip != nil && ip.IsLoopback()
}

// openedAsLocalhost reports whether the browser's address bar says
// localhost (e.g. through an SSH tunnel, possibly into a container).
func openedAsLocalhost(r *http.Request) bool {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, "expected JSON")
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid request: trailing data")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

type apiError struct {
	Error string `json:"error"`
	Field string `json:"field,omitempty"`
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, apiError{Error: msg})
}

// writeErr maps internal errors to friendly responses.
func (s *Server) writeErr(w http.ResponseWriter, err error) {
	var fe *config.FieldError
	switch {
	case errors.As(err, &fe):
		writeJSON(w, http.StatusBadRequest, apiError{Error: fe.Message, Field: fe.Field})
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not found")
	case errors.Is(err, store.ErrConflict):
		writeJSON(w, http.StatusConflict, apiError{Error: "a route for this domain already exists", Field: "hostname"})
	default:
		s.Log.Error("internal error", "err", err)
		writeError(w, http.StatusInternalServerError, "something went wrong; check the RyProx logs")
	}
}

func (s *Server) audit(r *http.Request, actor, action, detail string) {
	if err := s.Store.AddAudit(r.Context(), store.AuditEntry{Actor: actor, Action: action, Detail: detail, IP: clientIP(r)}); err != nil {
		s.Log.Error("audit log write failed", "err", err)
	}
	s.Log.Info("admin action", "actor", actor, "action", action, "detail", detail, "ip", clientIP(r))
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	setup := s.setupHash != nil
	s.mu.Unlock()
	out := map[string]any{
		"setupRequired": setup,
		"version":       version.Version,
		// Warn when the dashboard is used over plain HTTP from another machine.
		"insecure": r.TLS == nil && !isLoopback(r) && !openedAsLocalhost(r),
	}
	if u, _ := s.currentSession(r); u != nil {
		out["user"] = map[string]any{"username": u.Username}
	}
	writeJSON(w, http.StatusOK, out)
}
