// SPDX-License-Identifier: AGPL-3.0-only

// Package console opens terminals (SSH) and remote desktops (RDP, VNC) in
// the browser, on routes whose kind is ssh, rdp or vnc.
//
// The visitor has already been signed in and checked against the route's
// access list by the proxy engine. Which machine to connect to always comes
// from the route's saved configuration, never from the browser.
//
// SSH is handled by RyProx itself. RDP and VNC go through guacd, the
// connection daemon from Apache Guacamole, which must run next to RyProx.
package console

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/rylanq/ryprox/internal/auth"
	"github.com/rylanq/ryprox/internal/secrets"
	"github.com/rylanq/ryprox/internal/store"
)

// PasswordPurpose is the sealing purpose of saved console passwords.
const PasswordPurpose = "console-password"

const ticketTTL = time.Minute

// Service serves console routes.
type Service struct {
	Store *store.Store
	Box   *secrets.Box
	Log   *slog.Logger
	UI    fs.FS // the web/static directory
	// DefaultGuacd is used when no guacd address is saved (e.g. guacd:4822 in Docker).
	DefaultGuacd string
	// Dial reaches a machine, through a site's tunnel when site != 0.
	Dial func(ctx context.Context, site int64, addr string) (net.Conn, error)
	// Audit records who connected where.
	Audit func(r *http.Request, actor, action, detail string)

	mu      sync.Mutex
	tickets map[string]ticket
	keyMu   sync.Mutex
}

// ticket carries what a person typed (username, password) from the
// connect form to the WebSocket, so secrets never appear in a URL.
type ticket struct {
	routeID  int64
	host     string
	user     string
	ip       string
	username string
	password string
	width    int
	height   int
	dpi      int
	expires  time.Time
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

var assets = map[string]string{
	"console.js":   "text/javascript; charset=utf-8",
	"console.css":  "text/css; charset=utf-8",
	"xterm.mjs":    "text/javascript; charset=utf-8",
	"xterm.css":    "text/css; charset=utf-8",
	"guacamole.js": "text/javascript; charset=utf-8",
}

// ServeConsole implements proxy.Console.
func (s *Service) ServeConsole(w http.ResponseWriter, r *http.Request, route *store.Route, user string) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "+
		"img-src 'self' data: blob:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	if r.TLS != nil {
		h.Set("Strict-Transport-Security", "max-age=31536000")
	}

	switch p := r.URL.Path; {
	case p == "/" && r.Method == http.MethodGet:
		s.file(w, r, "console/index.html", "text/html; charset=utf-8")
	case strings.HasPrefix(p, "/assets/") && r.Method == http.MethodGet:
		name := strings.TrimPrefix(p, "/assets/")
		ct, ok := assets[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		s.file(w, r, "console/"+name, ct)
	case p == "/info" && r.Method == http.MethodGet:
		s.info(w, route, user)
	case p == "/session" && r.Method == http.MethodPost:
		s.newSession(w, r, route, user)
	case p == "/ws" && r.Method == http.MethodGet:
		s.connect(w, r, route, user)
	default:
		http.NotFound(w, r)
	}
}

func (s *Service) file(w http.ResponseWriter, r *http.Request, name, ct string) {
	b, err := fs.ReadFile(s.UI, name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", ct)
	// The name is checked against a fixed list and the bytes come from files
	// built into the binary.
	_, _ = w.Write(b) //nolint:gosec // see above
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Service) info(w http.ResponseWriter, route *store.Route, user string) {
	k := route.Config.Console
	writeJSON(w, http.StatusOK, map[string]any{
		"kind":          route.Config.Kind,
		"name":          route.Hostname,
		"user":          user,
		"username":      k.Username,
		"askUsername":   k.Username == "",
		"askPassword":   k.Auth == store.ConsoleAuthAsk,
		"usernameUsed":  route.Config.Kind != store.KindVNC,
		"guacdRequired": route.Config.Kind != store.KindSSH,
	})
}

func (s *Service) newSession(w http.ResponseWriter, r *http.Request, route *store.Route, user string) {
	// Same-origin check: browsers won't send this header cross-site
	// without a preflight, which is never allowed.
	if r.Header.Get("X-RyProx") != "1" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "missing request header"})
		return
	}
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Width    int    `json:"width"`
		Height   int    `json:"height"`
		DPI      int    `json:"dpi"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8<<10)).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	k := route.Config.Console
	username := k.Username
	if username == "" {
		username = strings.TrimSpace(in.Username)
		if route.Config.Kind != store.KindVNC && (username == "" || len(username) > 100 || strings.ContainsAny(username, "\r\n\x00")) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "enter a username", "field": "username"})
			return
		}
	}
	if len(in.Password) > 500 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password is too long", "field": "password"})
		return
	}
	tok, err := auth.NewToken()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "something went wrong"})
		return
	}
	clamp := func(v, lo, hi, def int) int {
		if v < lo || v > hi {
			return def
		}
		return v
	}
	t := ticket{routeID: route.ID, host: route.Hostname, user: user, ip: clientIP(r), username: username,
		width: clamp(in.Width, 200, 8192, 1280), height: clamp(in.Height, 200, 8192, 800), dpi: clamp(in.DPI, 48, 384, 96),
		expires: time.Now().Add(ticketTTL)}
	if k.Auth == store.ConsoleAuthAsk {
		t.password = in.Password
	}
	s.mu.Lock()
	if s.tickets == nil {
		s.tickets = map[string]ticket{}
	}
	for key, v := range s.tickets {
		if time.Now().After(v.expires) {
			delete(s.tickets, key)
		}
	}
	s.tickets[string(auth.HashToken(tok))] = t
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"ticket": tok})
}

func (s *Service) takeTicket(raw string, route *store.Route, user, ip string) (ticket, bool) {
	key := string(auth.HashToken(raw))
	s.mu.Lock()
	t, ok := s.tickets[key]
	delete(s.tickets, key)
	s.mu.Unlock()
	if !ok || time.Now().After(t.expires) || t.routeID != route.ID || t.host != route.Hostname || t.ip != ip ||
		subtle.ConstantTimeCompare([]byte(t.user), []byte(user)) != 1 {
		return ticket{}, false
	}
	return t, true
}

func (s *Service) connect(w http.ResponseWriter, r *http.Request, route *store.Route, user string) {
	t, ok := s.takeTicket(r.URL.Query().Get("ticket"), route, user, clientIP(r))
	if !ok {
		http.Error(w, "this connection link has expired; reload the page", http.StatusUnauthorized)
		return
	}
	opts := &websocket.AcceptOptions{} // checks that Origin is this site
	if route.Config.Kind != store.KindSSH {
		opts.Subprotocols = []string{"guacamole"}
	}
	c, err := websocket.Accept(w, r, opts)
	if err != nil {
		return
	}
	c.SetReadLimit(1 << 20)
	// r.Context() is cancelled by the proxy engine as soon as the person
	// loses access, which ends the session.
	ctx := r.Context()
	target := route.Config.Console.Address
	s.Audit(r, user, "console.open", route.Config.Kind+" "+target+" as "+t.username)
	start := time.Now()
	var runErr error
	if route.Config.Kind == store.KindSSH {
		runErr = s.runSSH(ctx, c, route, t)
	} else {
		runErr = s.runGuac(ctx, c, route, t)
	}
	detail := route.Config.Kind + " " + target + " after " + time.Since(start).Round(time.Second).String()
	if runErr != nil && !errors.Is(runErr, context.Canceled) {
		s.Log.Info("console session ended", "route", route.Hostname, "user", user, "err", runErr)
		detail += ": " + runErr.Error()
	}
	s.Audit(r, user, "console.close", detail)
}

// password returns the password for a session: typed, or saved by an admin.
func (s *Service) password(route *store.Route, t ticket) (string, error) {
	k := route.Config.Console
	if k.Auth == store.ConsoleAuthStored {
		return s.Box.Open(k.Password, PasswordPurpose)
	}
	return t.password, nil
}

// closeWith closes a WebSocket with a message the page can show.
func closeWith(c *websocket.Conn, msg string) {
	if len(msg) > 120 {
		msg = msg[:120]
	}
	_ = c.Close(websocket.StatusPolicyViolation, msg)
}
