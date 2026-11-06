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
	"sort"
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
	// or an error) and returns ok=false. On success, stillAllowed re-checks
	// the same session and is called periodically for long-lived requests
	// (WebSockets, streams), which are cut off as soon as it returns false.
	Authorize(w http.ResponseWriter, r *http.Request, route *store.Route) (username string, stillAllowed func() bool, ok bool)
	// Portal handles requests under PortalPrefix on a private route.
	Portal(w http.ResponseWriter, r *http.Request, route *store.Route)
}

// recheckInterval is how often long-lived requests on private routes are
// re-authorized (nanoseconds; atomic so tests can shorten it).
var recheckInterval atomic.Int64

func init() { recheckInterval.Store(int64(15 * time.Second)) }

type userKey struct{}

type gateBox struct{ g Gate }

// SetGate installs the access gate. Until one is set, private routes refuse
// every request (fail closed).
func (e *Engine) SetGate(g Gate) { e.gate.Store(&gateBox{g}) }

// IsRyproxCookie reports whether a cookie name belongs to RyProx. These
// cookies are removed from requests before forwarding, so a backend never
// sees a RyProx session, and removed from backend responses, so a backend
// can't set or clear one.
func IsRyproxCookie(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	n = strings.TrimPrefix(n, "__host-")
	n = strings.TrimPrefix(n, "__secure-")
	return n == "ryprox" || strings.HasPrefix(n, "ryprox-")
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
			if name == "" || IsRyproxCookie(name) {
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

// stripUnsafeHeaders removes headers a visitor must not be able to set:
// RyProx's own X-Ryprox-* headers, and any header containing an underscore.
// Many backends (CGI, PHP, WSGI, Rack) treat "_" and "-" as the same, so
// "X_Ryprox_User" would otherwise reach them as X-Ryprox-User.
func stripUnsafeHeaders(h http.Header) {
	for name := range h {
		if strings.Contains(name, "_") || strings.HasPrefix(http.CanonicalHeaderKey(name), "X-Ryprox-") {
			delete(h, name)
		}
	}
}

type snapshot struct {
	routes map[string]*liveRoute // keyed by hostname
}

type liveRoute struct {
	route     store.Route
	pools     []*pool // path rules, longest prefix first, then the default ("")
	transport *http.Transport
	proxy     *httputil.ReverseProxy
	limiter   *rateLimiter
}

// pool is a set of targets serving one path prefix ("" = everything else).
type pool struct {
	prefix  string
	strip   bool
	targets []*liveTarget
	next    atomic.Uint64
}

type poolKey struct{}

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

func (e *Engine) buildPool(routeID int64, prefix string, strip bool, targets []store.Target) (*pool, error) {
	if len(targets) == 0 {
		return nil, errors.New("no targets")
	}
	p := &pool{prefix: prefix, strip: strip}
	for _, t := range targets {
		u, err := url.Parse(t.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, fmt.Errorf("invalid target %q", t.URL)
		}
		p.targets = append(p.targets, &liveTarget{url: u, health: e.health.Get(routeID, t.URL)})
	}
	return p, nil
}

func (e *Engine) buildRoute(r store.Route) (*liveRoute, error) {
	lr := &liveRoute{route: r}
	if n := r.Config.RateLimit.RequestsPerMinute; n > 0 {
		lr.limiter = newRateLimiter(n)
	}
	if r.Config.IsRedirect() {
		if _, err := url.Parse(r.Config.Redirect.To); err != nil || r.Config.Redirect.To == "" {
			return nil, errors.New("invalid redirect address")
		}
		lr.transport = newTransport(false)
		return lr, nil
	}
	rules := append([]store.PathRule(nil), r.Config.Paths...)
	sort.SliceStable(rules, func(i, j int) bool { return len(rules[i].Prefix) > len(rules[j].Prefix) })
	for _, pr := range rules {
		if pr.Prefix == "" || !strings.HasPrefix(pr.Prefix, "/") {
			return nil, fmt.Errorf("invalid path %q", pr.Prefix)
		}
		p, err := e.buildPool(r.ID, pr.Prefix, pr.StripPrefix, pr.Targets)
		if err != nil {
			return nil, fmt.Errorf("path %s: %w", pr.Prefix, err)
		}
		lr.pools = append(lr.pools, p)
	}
	def, err := e.buildPool(r.ID, "", false, r.Config.Targets)
	if err != nil {
		return nil, err
	}
	lr.pools = append(lr.pools, def)
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
func (p *pool) pick(failover bool) *liveTarget {
	n := len(p.targets)
	if n == 1 {
		return p.targets[0]
	}
	if failover {
		for _, t := range p.targets {
			if t.health.Usable() {
				return t
			}
		}
		return p.targets[0]
	}
	start := p.next.Add(1) - 1
	for i := range n {
		t := p.targets[(start+uint64(i))%uint64(n)]
		if t.health.Usable() {
			return t
		}
	}
	return p.targets[start%uint64(n)]
}

// matches reports whether path falls under the pool's prefix: /api matches
// /api and /api/x, but not /apix.
func (p *pool) matches(path string) bool {
	return p.prefix == "" || path == p.prefix || strings.HasPrefix(path, p.prefix+"/")
}

// poolFor returns the pool for a request path.
func (lr *liveRoute) poolFor(path string) *pool {
	for _, p := range lr.pools {
		if p.matches(path) {
			return p
		}
	}
	return lr.pools[len(lr.pools)-1]
}

func (lr *liveRoute) rewrite(pr *httputil.ProxyRequest) {
	p, _ := pr.In.Context().Value(poolKey{}).(*pool)
	if p == nil {
		p = lr.poolFor(pr.In.URL.Path)
	}
	t := p.pick(lr.route.Config.LoadBalancing == "failover")
	pr.Out = pr.Out.WithContext(context.WithValue(pr.Out.Context(), ctxKey{}, t))
	if p.strip && p.prefix != "" {
		rest := strings.TrimPrefix(pr.Out.URL.Path, p.prefix)
		if !strings.HasPrefix(rest, "/") {
			rest = "/" + rest
		}
		pr.Out.URL.Path, pr.Out.URL.RawPath = rest, ""
	}
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
	// Set the identity header last, on the outgoing request: after hop-by-hop
	// headers are removed (so "Connection: X-Ryprox-User" can't drop it) and
	// after header rules (so a rule can't overwrite it).
	pr.Out.Header.Del(UserHeader)
	if user, ok := pr.In.Context().Value(userKey{}).(string); ok {
		pr.Out.Header.Set(UserHeader, user)
	}
}

func (lr *liveRoute) modifyResponse(resp *http.Response) error {
	applyHeaderRules(resp.Header, lr.route.Config.ResponseHeaders)
	// A backend must not set, replace or clear RyProx's session cookies.
	if cookies := resp.Header.Values("Set-Cookie"); len(cookies) > 0 {
		kept := cookies[:0:0]
		for _, c := range cookies {
			name, _, _ := strings.Cut(c, "=")
			if !IsRyproxCookie(name) {
				kept = append(kept, c)
			}
		}
		resp.Header.Del("Set-Cookie")
		for _, c := range kept {
			resp.Header.Add("Set-Cookie", c)
		}
	}
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
	cfg := &lr.route.Config
	if cfg.Expired(time.Now()) {
		WritePage(w, http.StatusGone, "Link expired", "This address was only available for a limited time.")
		return
	}
	if lr.limiter != nil && !lr.limiter.allow(clientKey(r.RemoteAddr)) {
		w.Header().Set("Retry-After", "60")
		WritePage(w, http.StatusTooManyRequests, "Slow down", "Too many requests from your address. Please wait a minute and try again.")
		return
	}
	stripUnsafeHeaders(r.Header)
	if !cfg.Access.IsPublic() {
		gb := e.gate.Load()
		if gb == nil || gb.g == nil {
			WritePage(w, http.StatusServiceUnavailable, "Not available", "This site is private and sign-in isn't available right now.")
			return
		}
		if strings.HasPrefix(r.URL.Path, PortalPrefix) {
			gb.g.Portal(w, r, &lr.route)
			return
		}
		user, stillAllowed, ok := gb.g.Authorize(w, r, &lr.route)
		if !ok {
			return
		}
		ctx, cancel := context.WithCancel(context.WithValue(r.Context(), userKey{}, user))
		defer cancel()
		if stillAllowed != nil {
			go watchAccess(ctx, cancel, stillAllowed)
		}
		r = r.WithContext(ctx)
	}
	if cfg.IsRedirect() {
		redirect(w, r, cfg.Redirect)
		return
	}
	if cfg.LandingPath != "" && r.URL.Path == "/" && r.URL.RawQuery == "" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		http.Redirect(w, r, cfg.LandingPath, http.StatusFound)
		return
	}
	stripRyproxCookies(r.Header)
	r = r.WithContext(context.WithValue(r.Context(), poolKey{}, lr.poolFor(r.URL.Path)))
	if isUpgrade(r) && !lr.route.Config.Websockets {
		WritePage(w, http.StatusForbidden, "Not allowed", "WebSocket connections are turned off for this site.")
		return
	}
	lr.proxy.ServeHTTP(w, r)
}

// redirect sends the visitor to a redirect route's destination.
func redirect(w http.ResponseWriter, r *http.Request, rd store.Redirect) {
	to := rd.To
	if rd.KeepPath {
		to += r.URL.EscapedPath()
		if r.URL.RawQuery != "" {
			to += "?" + r.URL.RawQuery
		}
	}
	code := rd.Code
	if code == 0 {
		code = http.StatusMovedPermanently
	}
	http.Redirect(w, r, to, code) //nolint:gosec // destination is admin configuration, not visitor input
}

// watchAccess cancels a long-lived request once its session stops being
// valid. Cancelling the request context closes upgraded (WebSocket)
// connections and aborts streaming responses.
func watchAccess(ctx context.Context, cancel context.CancelFunc, stillAllowed func() bool) {
	t := time.NewTicker(time.Duration(recheckInterval.Load()))
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if !stillAllowed() {
				cancel()
				return
			}
		}
	}
}

// Route returns the live configuration of the enabled route for host.
func (e *Engine) Route(host string) (*store.Route, bool) {
	lr, ok := e.snap.Load().routes[host]
	if !ok {
		return nil, false
	}
	r := lr.route
	return &r, true
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
