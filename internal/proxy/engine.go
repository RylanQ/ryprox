// SPDX-License-Identifier: AGPL-3.0-only

// Package proxy is RyProx's data plane: it forwards visitors' requests to
// backend services according to the current set of routes.
//
// The live configuration is an immutable snapshot swapped atomically, so a
// change made in the UI applies instantly without dropping a single request.
package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/rylanq/ryprox/internal/store"
)

// Engine routes requests by hostname to backends.
type Engine struct {
	snap   atomic.Pointer[snapshot]
	health *HealthChecker
	log    *slog.Logger
	gate   atomic.Pointer[gateBox]
}

// PortalPrefix is the path RyProx reserves on private sites for its own
// sign-in pages. Requests under it never reach the backend.
const PortalPrefix = "/.ryprox/"

// Gate decides who may open a private route.
type Gate interface {
	// Authorize checks the request's session against the route's access
	// list. If access is refused it writes the response (a sign-in redirect
	// or an error) and returns ok=false.
	Authorize(w http.ResponseWriter, r *http.Request, route *store.Route) (username string, ok bool)
	// Portal serves RyProx's sign-in pages under PortalPrefix.
	Portal(w http.ResponseWriter, r *http.Request, route *store.Route)
}

type gateBox struct{ g Gate }

// SetGate installs the access gate. Until one is set, private routes refuse
// every request (fail closed).
func (e *Engine) SetGate(g Gate) { e.gate.Store(&gateBox{g}) }

// Cookies RyProx uses for sign-in. They are removed before a request is
// forwarded, so a backend can never see (or steal) a RyProx session.
var ryproxCookies = map[string]bool{
	"__Host-ryprox": true, "ryprox": true, "__Host-ryprox-access": true, "ryprox-access": true,
}

// UserHeader carries the signed-in username to the backend. Any copy sent
// by a visitor is removed first, so backends can trust it.
const UserHeader = "X-Ryprox-User"

func stripRyproxCookies(h http.Header) {
	vals := h.Values("Cookie")
	if len(vals) == 0 {
		return
	}
	var kept []string
	for _, line := range vals {
		for _, part := range strings.Split(line, ";") {
			name, _, _ := strings.Cut(strings.TrimSpace(part), "=")
			if name == "" || ryproxCookies[name] {
				continue
			}
			kept = append(kept, strings.TrimSpace(part))
		}
	}
	h.Del("Cookie")
	if len(kept) > 0 {
		h.Set("Cookie", strings.Join(kept, "; "))
	}
}

func stripRyproxHeaders(h http.Header) {
	for name := range h {
		if strings.HasPrefix(http.CanonicalHeaderKey(name), "X-Ryprox-") {
			h.Del(name)
		}
	}
}

type snapshot struct {
	routes map[string]*liveRoute // keyed by hostname
}

type liveRoute struct {
	route     store.Route
	targets   []*liveTarget
	next      atomic.Uint64
	transport *http.Transport
	proxy     *httputil.ReverseProxy
}

type liveTarget struct {
	url    *url.URL
	health *TargetHealth
}

type ctxKey struct{}

// NewEngine returns an engine with no routes.
func NewEngine(log *slog.Logger) *Engine {
	e := &Engine{log: log, health: NewHealthChecker(log)}
	e.snap.Store(&snapshot{routes: map[string]*liveRoute{}})
	return e
}

// Close stops background health checks.
func (e *Engine) Close() { e.health.Close() }

// Check verifies that routes can be turned into a live configuration,
// without applying them. Used before committing a change to the database.
func (e *Engine) Check(routes []store.Route) error {
	_, err := e.build(routes)
	return err
}

// Apply replaces the live configuration. In-flight requests finish on the
// old configuration; new requests use the new one.
func (e *Engine) Apply(routes []store.Route) error {
	s, err := e.build(routes)
	if err != nil {
		return err
	}
	old := e.snap.Swap(s)
	e.health.Sync(routes)
	// Let the old transports' idle connections go.
	for _, lr := range old.routes {
		lr.transport.CloseIdleConnections()
	}
	return nil
}

// Hostnames returns the hostnames of all enabled routes.
func (e *Engine) Hostnames() []string {
	s := e.snap.Load()
	out := make([]string, 0, len(s.routes))
	for h := range s.routes {
		out = append(out, h)
	}
	return out
}

// HasHost reports whether an enabled route exists for host.
func (e *Engine) HasHost(host string) bool {
	_, ok := e.snap.Load().routes[host]
	return ok
}

// Health returns the health of each target, keyed by route ID.
func (e *Engine) Health() map[int64][]TargetStatus { return e.health.Status() }

func (e *Engine) build(routes []store.Route) (*snapshot, error) {
	s := &snapshot{routes: make(map[string]*liveRoute, len(routes))}
	for _, r := range routes {
		if !r.Enabled {
			continue
		}
		if _, dup := s.routes[r.Hostname]; dup {
			return nil, fmt.Errorf("hostname %s is used by two routes", r.Hostname)
		}
		lr, err := e.buildRoute(r)
		if err != nil {
			return nil, fmt.Errorf("route %s: %w", r.Hostname, err)
		}
		s.routes[r.Hostname] = lr
	}
	return s, nil
}

func (e *Engine) buildRoute(r store.Route) (*liveRoute, error) {
	if len(r.Config.Targets) == 0 {
		return nil, errors.New("no targets")
	}
	lr := &liveRoute{route: r}
	for _, t := range r.Config.Targets {
		u, err := url.Parse(t.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, fmt.Errorf("invalid target %q", t.URL)
		}
		lr.targets = append(lr.targets, &liveTarget{url: u, health: e.health.Get(r.ID, t.URL)})
	}
	lr.transport = newTransport(r.Config.TLSSkipVerify)
	lr.proxy = &httputil.ReverseProxy{
		Rewrite:        lr.rewrite,
		Transport:      lr.transport,
		ModifyResponse: lr.modifyResponse,
		ErrorHandler:   e.errorHandler(lr),
		ErrorLog:       slog.NewLogLogger(e.log.Handler(), slog.LevelWarn),
	}
	return lr, nil
}

func newTransport(skipVerify bool) *http.Transport {
	return &http.Transport{
		Proxy: nil, // never route backend traffic through an environment proxy
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   50,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: skipVerify, //nolint:gosec // admin opt-in for self-signed backends, shown with a warning in the UI
		},
	}
}

// pick chooses a target, skipping ones known to be down. If every target is
// down it still tries one, in case the health check is wrong.
func (lr *liveRoute) pick() *liveTarget {
	n := len(lr.targets)
	if n == 1 {
		return lr.targets[0]
	}
	if lr.route.Config.LoadBalancing == "failover" {
		for _, t := range lr.targets {
			if t.health.Usable() {
				return t
			}
		}
		return lr.targets[0]
	}
	start := lr.next.Add(1) - 1
	for i := range n {
		t := lr.targets[(start+uint64(i))%uint64(n)]
		if t.health.Usable() {
			return t
		}
	}
	return lr.targets[start%uint64(n)]
}

func (lr *liveRoute) rewrite(pr *httputil.ProxyRequest) {
	t := lr.pick()
	pr.Out = pr.Out.WithContext(context.WithValue(pr.Out.Context(), ctxKey{}, t))
	pr.SetURL(t.url)

	// Rewrite has already removed any X-Forwarded-* headers sent by the
	// visitor, so they can't be spoofed. Set fresh, trustworthy ones.
	pr.SetXForwarded()
	pr.Out.Header.Del("Forwarded")
	pr.Out.Header.Del("X-Real-Ip")
	if ip, _, err := net.SplitHostPort(pr.In.RemoteAddr); err == nil {
		pr.Out.Header.Set("X-Real-Ip", ip)
	}
	if lr.route.Config.PreserveHost {
		pr.Out.Host = pr.In.Host
	}
	applyHeaderRules(pr.Out.Header, lr.route.Config.RequestHeaders)
}

func (lr *liveRoute) modifyResponse(resp *http.Response) error {
	applyHeaderRules(resp.Header, lr.route.Config.ResponseHeaders)
	return nil
}

func applyHeaderRules(h http.Header, rules []store.HeaderRule) {
	for _, r := range rules {
		switch r.Action {
		case "set":
			h.Set(r.Name, r.Value)
		case "remove":
			h.Del(r.Name)
		}
	}
}

func (e *Engine) errorHandler(lr *liveRoute) func(http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, r *http.Request, err error) {
		if errors.Is(err, context.Canceled) {
			// The visitor went away; nothing to report.
			w.WriteHeader(499)
			return
		}
		target := ""
		if t, ok := r.Context().Value(ctxKey{}).(*liveTarget); ok {
			target = t.url.String()
			// Passive check: avoid this target briefly if we couldn't connect.
			var opErr *net.OpError
			if errors.As(err, &opErr) && opErr.Op == "dial" {
				t.health.MarkFailed(10 * time.Second)
			}
		}
		e.log.Warn("backend error", "host", lr.route.Hostname, "target", target, "err", err)
		WritePage(w, http.StatusBadGateway, "Service unavailable",
			"The service behind this address isn't responding right now. Please try again in a moment.")
	}
}

// IsHTTPSRedirect reports whether the route for host wants HTTP visitors
// redirected to HTTPS.
func (e *Engine) IsHTTPSRedirect(host string) bool {
	lr, ok := e.snap.Load().routes[host]
	return ok && lr.route.Config.HTTPSRedirect
}

// ServeHTTP forwards the request to the route for its Host header.
func (e *Engine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := NormalizeHost(r.Host)
	lr, ok := e.snap.Load().routes[host]
	if !ok {
		WritePage(w, http.StatusNotFound, "Not found", "No site is configured at this address.")
		return
	}
	stripRyproxHeaders(r.Header)
	if !lr.route.Config.Access.IsPublic() {
		gb := e.gate.Load()
		if gb == nil || gb.g == nil {
			WritePage(w, http.StatusServiceUnavailable, "Not available", "This site is private and sign-in isn't available right now.")
			return
		}
		if strings.HasPrefix(r.URL.Path, PortalPrefix) {
			gb.g.Portal(w, r, &lr.route)
			return
		}
		user, ok := gb.g.Authorize(w, r, &lr.route)
		if !ok {
			return
		}
		r.Header.Set(UserHeader, user)
	}
	stripRyproxCookies(r.Header)
	if isUpgrade(r) && !lr.route.Config.Websockets {
		WritePage(w, http.StatusForbidden, "Not allowed", "WebSocket connections are turned off for this site.")
		return
	}
	lr.proxy.ServeHTTP(w, r)
}

// NormalizeHost lower-cases a Host header and removes any port.
func NormalizeHost(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.TrimSuffix(strings.ToLower(h), ".")
}

func isUpgrade(r *http.Request) bool {
	for _, v := range r.Header.Values("Connection") {
		for _, tok := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), "upgrade") {
				return true
			}
		}
	}
	return false
}

// WritePage writes a small, self-contained error page.
func WritePage(w http.ResponseWriter, code int, title, msg string) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	w.WriteHeader(code)
	_, _ = fmt.Fprintf(w, `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>%d %s</title>
<style>body{font:16px/1.5 system-ui,sans-serif;display:grid;place-items:center;min-height:100vh;margin:0;background:#f6f7f9;color:#1d2433}
main{max-width:28rem;padding:2rem;text-align:center}h1{font-size:1.25rem;margin:.5rem 0}p{color:#5b6475}.c{font-size:3rem;font-weight:700;color:#c3c8d2}
@media(prefers-color-scheme:dark){body{background:#12151b;color:#e7e9ee}p{color:#9aa3b2}.c{color:#3a4150}}</style></head>
<body><main><div class="c">%d</div><h1>%s</h1><p>%s</p></main></body></html>`,
		code, html.EscapeString(title), code, html.EscapeString(title), html.EscapeString(msg))
}
