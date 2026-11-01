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
	r := store.Route{ID: id, Hostname: host, Enabled: true, Config: store.RouteConfig{LoadBalancing: "round_robin", Websockets: true}}
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

	st := TestTarget(t.Context(), backend.URL+"/health", false)
	if st.State != StateDown || st.LastError != "HTTP 503" {
		t.Fatalf("TestTarget = %+v", st)
	}
}
