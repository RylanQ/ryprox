// SPDX-License-Identifier: AGPL-3.0-only

package proxy

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rylanq/ryprox/internal/store"
)

// echo is a backend that reports what it received.
func echo(t *testing.T, name string) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend", name)
		w.Header().Set("Server", "secret-backend/1.0")
		_, _ = fmt.Fprintf(w, "name=%s\nhost=%s\npath=%s\nxff=%s\nxfh=%s\nxfp=%s\nfwd=%s\nreal=%s\nadded=%s\nremoved=%s\n",
			name, r.Host, r.URL.RequestURI(), r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Forwarded-Host"),
			r.Header.Get("X-Forwarded-Proto"), r.Header.Get("Forwarded"), r.Header.Get("X-Real-Ip"),
			r.Header.Get("X-Added"), r.Header.Get("X-Secret"))
	}))
	t.Cleanup(s.Close)
	return s
}

func newEngine(t *testing.T, routes ...store.Route) *Engine {
	t.Helper()
	e := NewEngine(slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(e.Close)
	if err := e.Apply(routes); err != nil {
		t.Fatal(err)
	}
	return e
}

func route(id int64, host string, targets ...string) store.Route {
	r := store.Route{ID: id, Hostname: host, Enabled: true, Config: store.RouteConfig{LoadBalancing: "round_robin", Websockets: true,
		Access: store.Access{Mode: store.AccessPublic}}}
	for _, u := range targets {
		r.Config.Targets = append(r.Config.Targets, store.Target{URL: u})
	}
	return r
}

func do(t *testing.T, h http.Handler, host, path string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+host+path, nil)
	req.RemoteAddr = "203.0.113.7:51234"
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func field(body, key string) string {
	for _, line := range strings.Split(body, "\n") {
		if v, ok := strings.CutPrefix(line, key+"="); ok {
			return v
		}
	}
	return "<missing>"
}

func TestRoutesByHost(t *testing.T) {
	a, b := echo(t, "a"), echo(t, "b")
	e := newEngine(t, route(1, "a.example.com", a.URL), route(2, "b.example.com", b.URL))

	if got := field(do(t, e, "a.example.com", "/x?y=1", nil).Body.String(), "name"); got != "a" {
		t.Fatalf("a → %s", got)
	}
	// Host matching ignores case, port and a trailing dot.
	if got := field(do(t, e, "B.Example.COM.:443", "/", nil).Body.String(), "name"); got != "b" {
		t.Fatalf("b → %s", got)
	}
	if rec := do(t, e, "c.example.com", "/", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown host: %d", rec.Code)
	}
	if rec := do(t, e, "a.example.com.evil.com", "/", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("suffix trick: %d", rec.Code)
	}
}

func TestPathAndQueryPassThrough(t *testing.T) {
	a := echo(t, "a")
	e := newEngine(t, route(1, "a.example.com", a.URL))
	body := do(t, e, "a.example.com", "/deep/path?q=1&r=two", nil).Body.String()
	if got := field(body, "path"); got != "/deep/path?q=1&r=two" {
		t.Fatalf("path = %q", got)
	}
}

func TestForwardedHeadersCannotBeSpoofed(t *testing.T) {
	a := echo(t, "a")
	e := newEngine(t, route(1, "a.example.com", a.URL))
	body := do(t, e, "a.example.com", "/", map[string]string{
		"X-Forwarded-For":   "1.2.3.4",
		"X-Forwarded-Host":  "evil.com",
		"X-Forwarded-Proto": "https",
		"Forwarded":         "for=1.2.3.4",
		"X-Real-IP":         "1.2.3.4",
	}).Body.String()

	checks := map[string]string{"xff": "203.0.113.7", "xfh": "a.example.com", "xfp": "http", "fwd": "", "real": "203.0.113.7"}
	for k, want := range checks {
		if got := field(body, k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
}

func TestPreserveHost(t *testing.T) {
	a := echo(t, "a")
	r := route(1, "a.example.com", a.URL)
	e := newEngine(t, r)
	if got := field(do(t, e, "a.example.com", "/", nil).Body.String(), "host"); got == "a.example.com" {
		t.Fatal("host preserved by default")
	}
	r.Config.PreserveHost = true
	if err := e.Apply([]store.Route{r}); err != nil {
		t.Fatal(err)
	}
	if got := field(do(t, e, "a.example.com", "/", nil).Body.String(), "host"); got != "a.example.com" {
		t.Fatalf("host = %q", got)
	}
}

func TestHeaderRules(t *testing.T) {
	a := echo(t, "a")
	r := route(1, "a.example.com", a.URL)
	r.Config.RequestHeaders = []store.HeaderRule{{Action: "set", Name: "X-Added", Value: "yes"}, {Action: "remove", Name: "X-Secret"}}
	r.Config.ResponseHeaders = []store.HeaderRule{{Action: "remove", Name: "Server"}, {Action: "set", Name: "X-Frame-Options", Value: "DENY"}}
	e := newEngine(t, r)
	rec := do(t, e, "a.example.com", "/", map[string]string{"X-Secret": "s3cret"})
	body := rec.Body.String()
	if field(body, "added") != "yes" || field(body, "removed") != "" {
		t.Fatalf("request rules not applied:\n%s", body)
	}
	if rec.Header().Get("Server") != "" || rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("response rules not applied: %v", rec.Header())
	}
}

func TestRoundRobinAndFailover(t *testing.T) {
	a, b := echo(t, "a"), echo(t, "b")
	r := route(1, "lb.example.com", a.URL, b.URL)
	e := newEngine(t, r)
	seen := map[string]int{}
	for range 10 {
		seen[field(do(t, e, "lb.example.com", "/", nil).Body.String(), "name")]++
	}
	if seen["a"] != 5 || seen["b"] != 5 {
		t.Fatalf("round robin uneven: %v", seen)
	}

	r.Config.LoadBalancing = "failover"
	_ = e.Apply([]store.Route{r})
	for range 5 {
		if got := field(do(t, e, "lb.example.com", "/", nil).Body.String(), "name"); got != "a" {
			t.Fatalf("failover should use first target, got %s", got)
		}
	}
}

func TestDeadTargetIsAvoided(t *testing.T) {
	a := echo(t, "a")
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close() // nothing listening now

	e := newEngine(t, route(1, "lb.example.com", deadURL, a.URL))
	// The first request to the dead target fails with 502 and marks it bad...
	codes := []int{}
	for range 6 {
		codes = append(codes, do(t, e, "lb.example.com", "/", nil).Code)
	}
	bad := 0
	for _, c := range codes {
		if c == http.StatusBadGateway {
			bad++
		}
	}
	// ...after which traffic goes to the healthy target.
	if bad != 1 {
		t.Fatalf("codes = %v, want exactly one 502", codes)
	}
}

func TestBackendDownShowsErrorPage(t *testing.T) {
	dead := httptest.NewServer(http.NotFoundHandler())
	u := dead.URL
	dead.Close()
	e := newEngine(t, route(1, "x.example.com", u))
	rec := do(t, e, "x.example.com", "/", nil)
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "Service unavailable") {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "127.0.0.1") {
		t.Fatal("error page leaks the backend address")
	}
}

func TestDisabledRouteIsNotServed(t *testing.T) {
	a := echo(t, "a")
	r := route(1, "a.example.com", a.URL)
	r.Enabled = false
	e := newEngine(t, r)
	if rec := do(t, e, "a.example.com", "/", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("disabled route served: %d", rec.Code)
	}
}

func TestLiveApply(t *testing.T) {
	a, b := echo(t, "a"), echo(t, "b")
	e := newEngine(t, route(1, "x.example.com", a.URL))
	if got := field(do(t, e, "x.example.com", "/", nil).Body.String(), "name"); got != "a" {
		t.Fatal(got)
	}
	if err := e.Apply([]store.Route{route(1, "x.example.com", b.URL)}); err != nil {
		t.Fatal(err)
	}
	if got := field(do(t, e, "x.example.com", "/", nil).Body.String(), "name"); got != "b" {
		t.Fatalf("after apply: %s", got)
	}
	// An invalid config is rejected and the old one keeps running.
	if err := e.Apply([]store.Route{route(1, "x.example.com", "not a url")}); err == nil {
		t.Fatal("invalid config applied")
	}
	if got := field(do(t, e, "x.example.com", "/", nil).Body.String(), "name"); got != "b" {
		t.Fatalf("old config lost: %s", got)
	}
	if err := e.Check([]store.Route{route(1, "d.example.com", a.URL), route(2, "d.example.com", b.URL)}); err == nil {
		t.Fatal("duplicate hostnames accepted")
	}
}

// websocketBackend accepts an upgrade and echoes one line.
func websocketBackend(t *testing.T) *httptest.Server {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			http.Error(w, "no", 400)
			return
		}
		conn, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_ = rw.Flush()
		line, _ := rw.ReadString('\n')
		_, _ = rw.WriteString("echo:" + line)
		_ = rw.Flush()
	}))
	t.Cleanup(s.Close)
	return s
}

func TestWebsockets(t *testing.T) {
	ws := websocketBackend(t)
	r := route(1, "ws.example.com", ws.URL)
	e := newEngine(t, r)
	front := httptest.NewServer(e)
	t.Cleanup(front.Close)

	try := func() (int, string) {
		conn, err := net.Dial("tcp", strings.TrimPrefix(front.URL, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = fmt.Fprint(conn, "GET /sock HTTP/1.1\r\nHost: ws.example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusSwitchingProtocols {
			return resp.StatusCode, ""
		}
		_, _ = fmt.Fprint(conn, "hello\n")
		line, _ := br.ReadString('\n')
		return resp.StatusCode, line
	}

	if code, line := try(); code != 101 || line != "echo:hello\n" {
		t.Fatalf("websocket: %d %q", code, line)
	}
	r.Config.Websockets = false
	_ = e.Apply([]store.Route{r})
	if code, _ := try(); code != http.StatusForbidden {
		t.Fatalf("websocket allowed when disabled: %d", code)
	}
}

func TestHealthChecks(t *testing.T) {
	var healthy atomic.Bool
	healthy.Store(true)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			w.WriteHeader(404)
			return
		}
		if healthy.Load() {
			w.WriteHeader(200)
		} else {
			w.WriteHeader(503)
		}
	}))
	t.Cleanup(backend.Close)
	r := route(7, "h.example.com", backend.URL)
	r.Config.HealthCheck = store.HealthCheck{Enabled: true, Path: "/health", IntervalSeconds: 5}
	e := newEngine(t, r)

	waitFor := func(state string) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if st := e.Health()[7]; len(st) == 1 && st[0].State == state {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("state never became %s: %+v", state, e.Health()[7])
	}
	waitFor(StateUp)

	healthy.Store(false)
	// Re-apply with a new interval to force an immediate re-check.
	r.Config.HealthCheck.IntervalSeconds = 6
	_ = e.Apply([]store.Route{r})
	waitFor(StateDown)

	st := e.TestTarget(t.Context(), backend.URL+"/health", false, 0)
	if st.State != StateDown || st.LastError != "HTTP 503" {
		t.Fatalf("TestTarget = %+v", st)
	}
}

// fakeGate lets "alice" in when she presents the right cookie.
type fakeGate struct{}

func (fakeGate) Authorize(w http.ResponseWriter, r *http.Request, _ *store.Route) (string, func() bool, bool) {
	if c, err := r.Cookie("ryprox-access"); err == nil && c.Value == "alice-session" {
		return "alice", func() bool { return true }, true
	}
	http.Redirect(w, r, PortalPrefix+"login", http.StatusFound)
	return "", nil, false
}

func (fakeGate) Portal(w http.ResponseWriter, _ *http.Request, _ *store.Route) {
	_, _ = fmt.Fprint(w, "portal")
}

func cookieEcho(t *testing.T) *httptest.Server {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "cookie=%s\nuser=%s\nspoof=%s\n", r.Header.Get("Cookie"), r.Header.Get(UserHeader), r.Header.Get("X-Ryprox-Role"))
	}))
	t.Cleanup(s.Close)
	return s
}

func TestPrivateRouteFailsClosedWithoutGate(t *testing.T) {
	b := cookieEcho(t)
	r := route(1, "p.example.com", b.URL)
	r.Config.Access = store.Access{} // missing mode = private
	e := newEngine(t, r)
	if rec := do(t, e, "p.example.com", "/", nil); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("private route without a gate: %d", rec.Code)
	}
}

func TestPrivateRouteUsesGate(t *testing.T) {
	b := cookieEcho(t)
	r := route(1, "p.example.com", b.URL)
	r.Config.Access = store.Access{Mode: store.AccessPrivate}
	e := newEngine(t, r)
	e.SetGate(fakeGate{})

	// No session: redirected to sign in; the backend is never reached.
	if rec := do(t, e, "p.example.com", "/secret", nil); rec.Code != http.StatusFound {
		t.Fatalf("anonymous request: %d", rec.Code)
	}
	// Portal paths are handled by RyProx, not the backend.
	if body := do(t, e, "p.example.com", "/.ryprox/login", nil).Body.String(); body != "portal" {
		t.Fatalf("portal: %q", body)
	}
	// Signed in: the backend gets the user, but never RyProx's cookie, and
	// a forged identity header is removed.
	rec := do(t, e, "p.example.com", "/", map[string]string{
		"Cookie":        "theme=dark; ryprox-access=alice-session; __Host-ryprox=x; other=1",
		UserHeader:      "mallory",
		"X-Ryprox-Role": "admin",
	})
	body := rec.Body.String()
	if field(body, "user") != "alice" {
		t.Fatalf("user header: %q", body)
	}
	if c := field(body, "cookie"); c != "theme=dark; other=1" {
		t.Fatalf("cookies reaching backend: %q", c)
	}
	if field(body, "spoof") != "" {
		t.Fatal("forged X-Ryprox-* header reached the backend")
	}
}

func TestPublicRouteStripsForgedIdentity(t *testing.T) {
	b := cookieEcho(t)
	e := newEngine(t, route(1, "pub.example.com", b.URL))
	body := do(t, e, "pub.example.com", "/.ryprox/login", map[string]string{UserHeader: "admin"}).Body.String()
	if field(body, "user") != "" {
		t.Fatal("public route forwarded a forged user header")
	}
	// On public routes, /.ryprox/ belongs to the app.
	if !strings.Contains(body, "cookie=") {
		t.Fatal("public route didn't forward /.ryprox/ to the backend")
	}
}

// --- regression tests for the security review --------------------------

func privateEngine(t *testing.T, backend string) *Engine {
	t.Helper()
	r := route(1, "p.example.com", backend)
	r.Config.Access = store.Access{Mode: store.AccessPrivate}
	e := newEngine(t, r)
	e.SetGate(fakeGate{})
	return e
}

func TestUnderscoreHeadersDropped(t *testing.T) {
	var got http.Header
	b := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got = r.Header.Clone() }))
	t.Cleanup(b.Close)
	e := newEngine(t, route(1, "pub.example.com", b.URL))
	req := httptest.NewRequestWithContext(t.Context(), "GET", "http://pub.example.com/", nil)
	req.Header["X_Ryprox_User"] = []string{"admin"}
	req.Header["X_forwarded_for"] = []string{"1.2.3.4"}
	e.ServeHTTP(httptest.NewRecorder(), req)
	for name := range got {
		if strings.Contains(name, "_") {
			t.Fatalf("underscore header reached the backend: %s", name)
		}
	}
}

func TestConnectionHeaderCantDropIdentity(t *testing.T) {
	var user string
	b := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { user = r.Header.Get(UserHeader) }))
	t.Cleanup(b.Close)
	e := privateEngine(t, b.URL)
	req := httptest.NewRequestWithContext(t.Context(), "GET", "http://p.example.com/", nil)
	req.Header.Set("Cookie", "ryprox-access=alice-session")
	req.Header.Set("Connection", "X-Ryprox-User")
	e.ServeHTTP(httptest.NewRecorder(), req)
	if user != "alice" {
		t.Fatalf("identity header = %q, want alice", user)
	}
}

func TestHeaderRuleCantOverwriteIdentity(t *testing.T) {
	var user string
	b := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { user = r.Header.Get(UserHeader) }))
	t.Cleanup(b.Close)
	r := route(1, "p.example.com", b.URL)
	r.Config.Access = store.Access{Mode: store.AccessPrivate}
	r.Config.RequestHeaders = []store.HeaderRule{{Action: "set", Name: UserHeader, Value: "admin"}}
	e := newEngine(t, r)
	e.SetGate(fakeGate{})
	req := httptest.NewRequestWithContext(t.Context(), "GET", "http://p.example.com/", nil)
	req.Header.Set("Cookie", "ryprox-access=alice-session")
	e.ServeHTTP(httptest.NewRecorder(), req)
	if user != "alice" {
		t.Fatalf("identity header = %q, want alice", user)
	}
}

func TestBackendCantSetRyproxCookies(t *testing.T) {
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Add("Set-Cookie", "__Host-ryprox-access=attacker; Path=/; Secure")
		w.Header().Add("Set-Cookie", "RYPROX=x")
		w.Header().Add("Set-Cookie", "ryprox-access=; Max-Age=0")
		w.Header().Add("Set-Cookie", "theme=dark")
	}))
	t.Cleanup(b.Close)
	e := newEngine(t, route(1, "pub.example.com", b.URL))
	rec := do(t, e, "pub.example.com", "/", nil)
	got := rec.Header().Values("Set-Cookie")
	if len(got) != 1 || got[0] != "theme=dark" {
		t.Fatalf("Set-Cookie reaching the visitor: %q", got)
	}
}

func TestIsRyproxCookie(t *testing.T) {
	for _, n := range []string{"ryprox", "RyProx", "__Host-ryprox", "__host-ryprox-access", "ryprox-access", "__Secure-ryprox-x"} {
		if !IsRyproxCookie(n) {
			t.Errorf("%q not recognised", n)
		}
	}
	for _, n := range []string{"ryproxy", "session", "theme", "my-ryprox"} {
		if IsRyproxCookie(n) {
			t.Errorf("%q wrongly recognised", n)
		}
	}
}

// revokingGate allows alice until revoked is set.
type revokingGate struct{ revoked *atomic.Bool }

func (g revokingGate) Authorize(_ http.ResponseWriter, _ *http.Request, _ *store.Route) (string, func() bool, bool) {
	return "alice", func() bool { return !g.revoked.Load() }, true
}
func (revokingGate) Portal(http.ResponseWriter, *http.Request, *store.Route) {}

func TestRevokedAccessClosesWebSocket(t *testing.T) {
	old := recheckInterval.Load()
	recheckInterval.Store(int64(50 * time.Millisecond))
	t.Cleanup(func() { recheckInterval.Store(old) })

	ws := websocketBackend(t)
	r := route(1, "ws.example.com", ws.URL)
	r.Config.Access = store.Access{Mode: store.AccessPrivate}
	e := newEngine(t, r)
	var revoked atomic.Bool
	e.SetGate(revokingGate{&revoked})
	front := httptest.NewServer(e)
	t.Cleanup(front.Close)

	conn, err := net.Dial("tcp", strings.TrimPrefix(front.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: ws.example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 101 {
		t.Fatalf("upgrade: %v %v", resp, err)
	}
	defer func() { _ = resp.Body.Close() }()
	revoked.Store(true)
	// The backend only answers after a line is sent; the connection must be
	// closed by RyProx before that, without the client sending anything.
	start := time.Now()
	if _, err := br.ReadByte(); err == nil {
		t.Fatal("connection still open after access was revoked")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("connection took too long to close")
	}
}

func TestPathRules(t *testing.T) {
	web, api := echo(t, "web"), echo(t, "api")
	r := route(1, "a.example.com", web.URL)
	r.Config.Paths = []store.PathRule{
		{Prefix: "/api", Targets: []store.Target{{URL: api.URL}}, StripPrefix: true},
		{Prefix: "/api/v2", Targets: []store.Target{{URL: api.URL + "/two"}}},
	}
	e := newEngine(t, r)
	cases := []struct{ path, name, got string }{
		{"/", "web", "/"},
		{"/apix", "web", "/apix"},
		{"/api", "api", "/"},
		{"/api/users?x=1", "api", "/users?x=1"},
		{"/api/v2/z", "api", "/two/api/v2/z"},
	}
	for _, c := range cases {
		body := do(t, e, "a.example.com", c.path, nil).Body.String()
		if field(body, "name") != c.name || field(body, "path") != c.got {
			t.Errorf("%s → %s %s, want %s %s", c.path, field(body, "name"), field(body, "path"), c.name, c.got)
		}
	}
}

func TestBackendBasePath(t *testing.T) {
	a := echo(t, "a")
	e := newEngine(t, route(1, "a.example.com", a.URL+"/app"))
	if got := field(do(t, e, "a.example.com", "/x?y=1", nil).Body.String(), "path"); got != "/app/x?y=1" {
		t.Fatalf("path = %q", got)
	}
}

func TestLandingPath(t *testing.T) {
	a := echo(t, "a")
	r := route(1, "a.example.com", a.URL)
	r.Config.LandingPath = "/page1"
	e := newEngine(t, r)
	rec := do(t, e, "a.example.com", "/", nil)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/page1" {
		t.Fatalf("/ → %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if got := field(do(t, e, "a.example.com", "/other", nil).Body.String(), "path"); got != "/other" {
		t.Fatalf("other path = %q", got)
	}
}

func TestRedirectRoute(t *testing.T) {
	r := store.Route{ID: 1, Hostname: "www.example.com", Enabled: true, Config: store.RouteConfig{Kind: store.KindRedirect,
		Access: store.Access{Mode: store.AccessPublic}, Redirect: store.Redirect{To: "https://example.com", Code: 301, KeepPath: true}}}
	e := newEngine(t, r)
	rec := do(t, e, "www.example.com", "/a/b?c=d", nil)
	if rec.Code != 301 || rec.Header().Get("Location") != "https://example.com/a/b?c=d" {
		t.Fatalf("got %d %q", rec.Code, rec.Header().Get("Location"))
	}
	// A private redirect still asks who you are first.
	r.Config.Access.Mode = store.AccessPrivate
	e = newEngine(t, r)
	if rec := do(t, e, "www.example.com", "/", nil); rec.Code == 301 {
		t.Fatal("private redirect served without a gate")
	}
}

func TestRateLimit(t *testing.T) {
	a := echo(t, "a")
	r := route(1, "a.example.com", a.URL)
	r.Config.RateLimit.RequestsPerMinute = 3
	e := newEngine(t, r)
	for i := range 3 {
		if rec := do(t, e, "a.example.com", "/", nil); rec.Code != 200 {
			t.Fatalf("request %d: %d", i, rec.Code)
		}
	}
	if rec := do(t, e, "a.example.com", "/", nil); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("4th request: %d", rec.Code)
	}
}

func TestRateLimiterWindows(t *testing.T) {
	now := time.Unix(1_000_000_020, 0)
	l := newRateLimiter(2)
	l.now = func() time.Time { return now }
	first, second, third := l.allow("a"), l.allow("a"), l.allow("a")
	if !first || !second || third {
		t.Fatal("first minute")
	}
	if !l.allow("b") {
		t.Fatal("other address limited")
	}
	now = now.Add(2 * time.Minute)
	if !l.allow("a") {
		t.Fatal("not reset after two minutes")
	}
	if clientKey("[2001:db8:1:2:3::1]:5") != clientKey("[2001:db8:1:2:ffff::9]:6") {
		t.Fatal("IPv6 /64 not grouped")
	}
}

func TestExpiredRoute(t *testing.T) {
	a := echo(t, "a")
	r := route(1, "a.example.com", a.URL)
	past := time.Now().Add(-time.Minute)
	r.Config.ExpiresAt = &past
	e := newEngine(t, r)
	if rec := do(t, e, "a.example.com", "/", nil); rec.Code != http.StatusGone {
		t.Fatalf("expired route: %d", rec.Code)
	}
}

func TestUptimeHistory(t *testing.T) {
	h := &TargetHealth{state: StateUnknown}
	now := time.Unix(1_000_000_000, 0)
	h.record(StateUp, now)
	h.record(StateUp, now)
	h.record(StateDown, now)
	h.record(StateUp, now.Add(-time.Hour))
	hist, up := h.history(now)
	if len(hist) != historyHours || hist[historyHours-1] < 0.66 || hist[historyHours-1] > 0.67 || hist[historyHours-2] != 1 || hist[0] != -1 {
		t.Fatalf("history %v", hist)
	}
	if up != 0.75 {
		t.Fatalf("uptime %v", up)
	}
}
