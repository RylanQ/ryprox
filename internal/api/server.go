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
	"github.com/rylanq/ryprox/internal/crowdsec"
	"github.com/rylanq/ryprox/internal/proxy"
	"github.com/rylanq/ryprox/internal/secrets"
	"github.com/rylanq/ryprox/internal/store"
	"github.com/rylanq/ryprox/internal/version"
)

// Session lifetimes.
const (
	sessionIdle      = 12 * time.Hour
	localSessionIdle = time.Hour // dashboard over plain HTTP: cookies on localhost are shared with every port
	sessionAbsolute  = 7 * 24 * time.Hour
	pendingLoginTTL  = 5 * time.Minute
	maxBodyBytes     = 1 << 20
)

// Server is the admin API and UI.
type Server struct {
	Store  *store.Store
	Engine *proxy.Engine
	Certs  *certs.Manager
	Box    *secrets.Box
	Log    *slog.Logger
	UI     fs.FS // the web/static directory

	// CrowdSec blocks visitors banned by a CrowdSec Local API (optional).
	CrowdSec *crowdsec.Bouncer

	// HTTPClient talks to single sign-on providers (nil: a default client).
	HTTPClient *http.Client

	// HTTPSPort is the public HTTPS port, used to build links to sites.
	HTTPSPort string

	settings atomic.Pointer[store.Settings]

	limiter *auth.Limiter // per account (and per account + address)
	ipLimit *auth.Limiter // per client address

	mu         sync.Mutex
	setupHash  []byte // hash of the one-time setup code; nil once set up
	pending    map[string]pendingLogin
	handoffs   map[string]handoff  // one-time codes that sign a visitor in to a site
	ceremonies map[string]ceremony // passkey challenges in progress
	ssoStates  map[string]ssoState // single sign-on logins in progress
	ssoCache   sync.Map            // discovered providers

	portalOnce sync.Once
	portal     http.Handler
}

type pendingLogin struct {
	userID  int64
	ip      string
	realm   realm
	expires time.Time
}

// New prepares the server: loads settings and, on a fresh install,
// creates a one-time setup code which it returns (empty if already set up).
func New(ctx context.Context, s *Server) (setupCode string, err error) {
	s.limiter = auth.NewLimiter()
	s.ipLimit = auth.NewLimiter()
	s.pending = map[string]pendingLogin{}
	s.handoffs = map[string]handoff{}
	st, err := s.Store.GetSettings(ctx)
	if err != nil {
		return "", err
	}
	s.settings.Store(&st)
	s.startCrowdSec(ctx)
	n, err := s.Store.CountAdmins(ctx)
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
	mux.HandleFunc("POST /api/login/passkey/begin", func(w http.ResponseWriter, r *http.Request) { s.passkeyLoginBegin(w, r, dashboard) })
	mux.HandleFunc("POST /api/login/passkey/finish", func(w http.ResponseWriter, r *http.Request) {
		s.passkeyLoginFinish(w, r, dashboard, adminsOnly)
	})

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
	priv("GET /api/people", s.handleListPeople)
	priv("POST /api/invites", s.handleCreateInvite)
	priv("DELETE /api/invites/{id}", s.handleDeleteInvite)
	priv("PUT /api/people/{id}", s.handleUpdatePerson)
	priv("PUT /api/people/{id}/email", s.handleSetEmail)
	priv("GET /api/account/passkeys", func(w http.ResponseWriter, r *http.Request, u *store.User, _ *store.Session) { s.listPasskeys(w, r, u) })
	priv("POST /api/account/passkeys/begin", func(w http.ResponseWriter, r *http.Request, u *store.User, _ *store.Session) {
		s.passkeyRegisterBegin(w, r, u, dashboard)
	})
	priv("POST /api/account/passkeys/finish", func(w http.ResponseWriter, r *http.Request, u *store.User, _ *store.Session) {
		s.passkeyRegisterFinish(w, r, u, dashboard)
	})
	priv("DELETE /api/account/passkeys/{id}", func(w http.ResponseWriter, r *http.Request, u *store.User, _ *store.Session) {
		s.deletePasskey(w, r, u)
	})
	priv("POST /api/import/npm", s.handleImportNPM)
	priv("GET /api/crowdsec", s.handleGetCrowdSec)
	priv("PUT /api/crowdsec", s.handlePutCrowdSec)
	priv("GET /api/sso", s.handleGetSSO)
	priv("PUT /api/sso", s.handlePutSSO)
	priv("GET /api/activity/export", s.handleActivityExport)
	priv("GET /api/account/tokens", func(w http.ResponseWriter, r *http.Request, u *store.User, _ *store.Session) { s.listTokens(w, r, u) })
	priv("POST /api/account/tokens", func(w http.ResponseWriter, r *http.Request, u *store.User, sess *store.Session) {
		if sess.ID == 0 {
			writeError(w, http.StatusForbidden, "tokens can't create other tokens")
			return
		}
		s.createToken(w, r, u, true)
	})
	priv("DELETE /api/account/tokens/{id}", func(w http.ResponseWriter, r *http.Request, u *store.User, _ *store.Session) { s.deleteToken(w, r, u) })
	priv("DELETE /api/people/{id}", s.handleDeletePerson)

	// The sign-in portal also works here, so invites can be accepted on the
	// dashboard's own address.
	mux.Handle(proxy.PortalPrefix, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.Portal(w, r, nil)
	}))

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

	return s.securityHeaders(s.restrictHosts(s.csrfProtect(s.requireSecurePost(mux))))
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
		// Scripts using an access token aren't browsers: a cross-site page can't
		// send an Authorization header here without a CORS preflight, which is
		// never granted, so the CSRF checks below don't apply to them.
		if bearerToken(r) != "" && r.Header.Get("Cookie") == "" {
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

// A realm is where a session is valid: the dashboard (host "") or one
// private site. A session from one realm is never accepted in another, so
// signing in to one site doesn't open the others, or the dashboard.
type realm struct{ host string }

var dashboard = realm{}

func (rl realm) cookieName(r *http.Request) string {
	name := "ryprox"
	if rl.host != "" {
		name = "ryprox-access"
	}
	if r.TLS != nil {
		return "__Host-" + name // __Host- cookies must be Secure and host-only
	}
	return name
}

// The dashboard uses Strict cookies. Sites use Lax, so following a link to a
// site (e.g. from a chat message) arrives signed in.
func (rl realm) sameSite() http.SameSite {
	if rl.host == "" {
		return http.SameSiteStrictMode
	}
	return http.SameSiteLaxMode
}

func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, rl realm, token string, expires time.Time) {
	// Secure is only false on plain HTTP, which RyProx only allows from the
	// server itself (the local dashboard, or an SSH tunnel).
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // see above
		Name:     rl.cookieName(r),
		Value:    token,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: rl.sameSite(),
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter, r *http.Request, rl realm) {
	http.SetCookie(w, &http.Cookie{Name: rl.cookieName(r), Value: "", Path: "/", MaxAge: -1, //nolint:gosec // as above
		HttpOnly: true, Secure: r.TLS != nil, SameSite: rl.sameSite()})
}

// sessionFor returns the signed-in user for this realm, or nil. Everything is
// re-checked on every request: expiry, idle time, the realm, whether the
// account is disabled, and (for the dashboard) the admin role.
func (s *Server) sessionFor(r *http.Request, rl realm) (*store.User, *store.Session) {
	c, err := r.Cookie(rl.cookieName(r))
	if err != nil || c.Value == "" || len(c.Value) > 100 {
		return nil, nil
	}
	ctx := r.Context()
	sess, err := s.Store.GetSessionByHash(ctx, auth.HashToken(c.Value))
	if err != nil || sess.Host != rl.host {
		return nil, nil
	}
	now := time.Now()
	idle := sessionIdle
	if rl == dashboard && r.TLS == nil {
		idle = localSessionIdle
	}
	if now.After(sess.ExpiresAt) || now.Sub(sess.LastSeenAt) > idle {
		_ = s.Store.DeleteSession(ctx, sess.UserID, sess.ID)
		return nil, nil
	}
	u, err := s.Store.GetUser(ctx, sess.UserID)
	if err != nil || u.Disabled {
		return nil, nil
	}
	if rl == dashboard && u.Role != store.RoleAdmin {
		return nil, nil
	}
	if now.Sub(sess.LastSeenAt) > time.Minute {
		_ = s.Store.TouchSession(ctx, sess.ID, now)
	}
	return u, sess
}

// currentSession returns the signed-in dashboard admin, or nil.
func (s *Server) currentSession(r *http.Request) (*store.User, *store.Session) {
	return s.sessionFor(r, dashboard)
}

func (s *Server) requireSession(h func(http.ResponseWriter, *http.Request, *store.User, *store.Session)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if raw := bearerToken(r); raw != "" {
			// API clients: an admin token, never mixed with a cookie session.
			// Tokens can't change account security (password, passkeys,
			// sessions, other tokens): that needs a person signed in.
			if strings.HasPrefix(r.URL.Path, "/api/account/") || r.URL.Path == "/api/logout" {
				writeError(w, http.StatusForbidden, "access tokens can't change account settings")
				return
			}
			u, t := s.tokenUser(r.Context(), r, raw, store.ScopeAdmin)
			if u == nil {
				writeError(w, http.StatusUnauthorized, "access token not valid")
				return
			}
			h(w, r, u, &store.Session{UserID: u.ID, IP: clientIP(r), UserAgent: "token: " + t.Name})
			return
		}
		u, sess := s.currentSession(r)
		if u == nil {
			writeError(w, http.StatusUnauthorized, "please log in")
			return
		}
		h(w, r, u, sess)
	})
}

func (s *Server) startSession(w http.ResponseWriter, r *http.Request, userID int64, rl realm) error {
	token, err := auth.NewToken()
	if err != nil {
		return err
	}
	now := time.Now()
	ua := r.UserAgent()
	if len(ua) > 300 {
		ua = ua[:300]
	}
	sess := &store.Session{TokenHash: auth.HashToken(token), UserID: userID, Host: rl.host, CreatedAt: now, LastSeenAt: now,
		ExpiresAt: now.Add(sessionAbsolute), IP: clientIP(r), UserAgent: ua}
	if err := s.Store.CreateSession(r.Context(), sess); err != nil {
		return err
	}
	_ = s.Store.RecordLogin(r.Context(), userID)
	s.setSessionCookie(w, r, rl, token, sess.ExpiresAt)
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
	for k, h := range s.handoffs {
		if time.Now().After(h.expires) {
			delete(s.handoffs, k)
		}
	}
}

// restrictHosts only answers requests addressed to RyProx itself: localhost
// (directly or through an SSH tunnel), or RyProx's own domains. This blocks
// DNS-rebinding attacks from web pages the admin visits.
func (s *Server) restrictHosts(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := proxy.NormalizeHost(r.Host)
		st := s.Settings()
		switch {
		case openedAsLocalhost(r):
		case r.TLS != nil && host != "" && (host == st.AdminHostname || host == st.SignInHostname()):
		default:
			http.Error(w, "unknown host", http.StatusMisdirectedRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireSecurePost refuses passwords and other changes over plain HTTP,
// except from this machine (locally or through an SSH tunnel).
func (s *Server) requireSecurePost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.TLS == nil && !s.isLocal(r) {
			writeError(w, http.StatusForbidden, "this needs HTTPS; open RyProx through an SSH tunnel or its HTTPS domain")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// isLocal reports whether a plain-HTTP request comes from this machine: the
// browser addressed localhost, and the connection comes from loopback or,
// inside a container, from the host (the default gateway).
func (s *Server) isLocal(r *http.Request) bool {
	if !openedAsLocalhost(r) {
		return false
	}
	if isLoopback(r) {
		return true
	}
	gw := defaultGateway()
	return gw != nil && gw.Equal(net.ParseIP(clientIP(r)))
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

// clientKey identifies a client for rate limiting: its IPv4 address, or its
// IPv6 /64 network (one user usually controls a whole /64).
func clientKey(r *http.Request) string {
	ip := net.ParseIP(clientIP(r))
	if ip == nil {
		return clientIP(r)
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
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
		"insecure": r.TLS == nil && !s.isLocal(r),
	}
	if u, _ := s.currentSession(r); u != nil {
		out["user"] = map[string]any{"username": u.Username}
	}
	writeJSON(w, http.StatusOK, out)
}
