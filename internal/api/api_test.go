// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/rylanq/ryprox/internal/auth"
	"github.com/rylanq/ryprox/internal/certs"
	"github.com/rylanq/ryprox/internal/proxy"
	"github.com/rylanq/ryprox/internal/secrets"
	"github.com/rylanq/ryprox/internal/store"
)

type env struct {
	t      *testing.T
	srv    *Server
	ts     *httptest.Server
	code   string
	engine *proxy.Engine

	setupSecret string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(t.Context(), filepath.Join(dir, "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	box, _ := secrets.LoadOrCreate(filepath.Join(dir, "secret.key"))
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	eng := proxy.NewEngine(log)
	t.Cleanup(eng.Close)
	s := &Server{Store: st, Engine: eng, Box: box, Log: log, DataDir: dir,
		UI: fstest.MapFS{"index.html": {Data: []byte("<!doctype html><title>RyProx</title>")}}}
	s.Certs = certs.New(filepath.Join(dir, "certs"), func(string) bool { return false }, log)
	code, err := New(t.Context(), s)
	if err != nil {
		t.Fatal(err)
	}
	eng.SetGate(s)
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return &env{t: t, srv: s, ts: ts, code: code, engine: eng}
}

// client is a browser with its own cookie jar.
type client struct {
	e    *env
	c    *http.Client
	host string // Host header to send, if not the test server's address
}

func (e *env) client() *client {
	jar, _ := cookiejar.New(nil)
	return &client{e: e, c: &http.Client{Jar: jar}}
}

func (c *client) req(method, path string, body any, hdr map[string]string) (int, map[string]any) {
	c.e.t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequestWithContext(c.e.t.Context(), method, c.e.ts.URL+path, r)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-RyProx", "1")
	if c.host != "" {
		req.Host = c.host
	}
	for k, v := range hdr {
		if k == "Host" {
			req.Host = v
			continue
		}
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	resp, err := c.c.Do(req)
	if err != nil {
		c.e.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if len(raw) > 0 && raw[0] == '{' {
		_ = json.Unmarshal(raw, &out)
	} else if len(raw) > 0 && raw[0] == '[' {
		var list []any
		_ = json.Unmarshal(raw, &list)
		out = map[string]any{"list": list}
	}
	return resp.StatusCode, out
}

func (c *client) post(path string, body any) (int, map[string]any) {
	return c.req(http.MethodPost, path, body, nil)
}

const pw = "a very good password"

// setup completes first-run setup and returns the TOTP secret.
func (e *env) setup(c *client) string {
	e.t.Helper()
	code, out := c.post("/api/setup/begin", map[string]string{"setupCode": e.code, "username": "admin"})
	if code != 200 {
		e.t.Fatalf("begin: %d %v", code, out)
	}
	secret := out["totpSecret"].(string)
	if !strings.HasPrefix(out["qr"].(string), "data:image/png;base64,") {
		e.t.Fatal("no QR code")
	}
	totp, _ := auth.TOTPCodeAt(secret, time.Now())
	code, out = c.post("/api/setup/finish", map[string]string{
		"setupCode": e.code, "username": "admin", "password": pw, "totpSecret": secret, "totpCode": totp})
	if code != 200 {
		e.t.Fatalf("finish: %d %v", code, out)
	}
	if n := len(out["recoveryCodes"].([]any)); n != 10 {
		e.t.Fatalf("%d recovery codes", n)
	}
	e.setupSecret = secret
	return secret
}

func TestSetupFlow(t *testing.T) {
	e := newEnv(t)
	c := e.client()
	if e.code == "" {
		t.Fatal("no setup code on a fresh install")
	}
	_, st := c.req("GET", "/api/state", nil, nil)
	if st["setupRequired"] != true {
		t.Fatal("setup not required on fresh install")
	}
	// Routes need a login.
	if code, _ := c.req("GET", "/api/routes", nil, nil); code != 401 {
		t.Fatalf("routes without login: %d", code)
	}
	// Wrong setup code.
	if code, _ := c.post("/api/setup/begin", map[string]string{"setupCode": "AAAA-BBBB-CCCC"}); code != 403 {
		t.Fatalf("wrong setup code: %d", code)
	}
	// Weak password and wrong 2FA code are refused.
	_, begin := c.post("/api/setup/begin", map[string]string{"setupCode": e.code})
	secret := begin["totpSecret"].(string)
	totp, _ := auth.TOTPCodeAt(secret, time.Now())
	if code, out := c.post("/api/setup/finish", map[string]string{"setupCode": e.code, "username": "admin",
		"password": "short", "totpSecret": secret, "totpCode": totp}); code != 400 || out["field"] != "password" {
		t.Fatalf("weak password: %d %v", code, out)
	}
	if code, out := c.post("/api/setup/finish", map[string]string{"setupCode": e.code, "username": "admin",
		"password": pw, "totpSecret": secret, "totpCode": "000000"}); code != 400 || out["field"] != "totpCode" {
		t.Fatalf("bad totp: %d %v", code, out)
	}

	e.setup(c)
	_, st = c.req("GET", "/api/state", nil, nil)
	if st["setupRequired"] != false || st["user"] == nil {
		t.Fatalf("after setup: %v", st)
	}
	if code, _ := c.req("GET", "/api/routes", nil, nil); code != 200 {
		t.Fatalf("logged in after setup: %d", code)
	}
	// Setup can't run twice, even with the right code.
	if code, _ := e.client().post("/api/setup/begin", map[string]string{"setupCode": e.code}); code != 409 {
		t.Fatalf("second setup: %d", code)
	}
	// The TOTP secret is encrypted at rest.
	u, _ := e.srv.Store.GetUserByUsername(t.Context(), "admin")
	if strings.Contains(u.TOTPSecret, secret) {
		t.Fatal("TOTP secret stored in plain text")
	}
}

func TestSetupCodeGuessingIsLimited(t *testing.T) {
	e := newEnv(t)
	c := e.client()
	last := 0
	for range 8 {
		last, _ = c.post("/api/setup/begin", map[string]string{"setupCode": "WRONG-WRONG-WRONG"})
	}
	if last != 429 {
		t.Fatalf("after 8 wrong codes: %d, want 429", last)
	}
}

func login(t *testing.T, c *client, password, code string) (int, map[string]any) {
	t.Helper()
	status, out := c.post("/api/login", map[string]string{"username": "Admin", "password": password})
	if status != 200 {
		return status, out
	}
	return c.post("/api/login/verify", map[string]string{"loginToken": out["loginToken"].(string), "code": code})
}

func TestLoginFlow(t *testing.T) {
	e := newEnv(t)
	secret := e.setup(e.client())

	// Wrong password and unknown user give the same message.
	c := e.client()
	s1, o1 := c.post("/api/login", map[string]string{"username": "admin", "password": "wrong password!!"})
	s2, o2 := c.post("/api/login", map[string]string{"username": "nobody", "password": "wrong password!!"})
	if s1 != 401 || s2 != 401 || o1["error"] != o2["error"] {
		t.Fatalf("login errors differ: %d %v / %d %v", s1, o1, s2, o2)
	}

	// The password alone is not enough.
	status, out := c.post("/api/login", map[string]string{"username": "admin", "password": pw})
	if status != 200 || out["needCode"] != true {
		t.Fatalf("password step: %d %v", status, out)
	}
	if code, _ := c.req("GET", "/api/routes", nil, nil); code != 401 {
		t.Fatal("logged in without a second factor")
	}
	token := out["loginToken"].(string)
	if code, _ := c.post("/api/login/verify", map[string]string{"loginToken": token, "code": "123456"}); code != 401 {
		t.Fatalf("wrong code accepted: %d", code)
	}

	// Setup used the current code, so it can't be replayed now. Use the next one.
	next, _ := auth.TOTPCodeAt(secret, time.Now().Add(30*time.Second))
	if code, out := c.post("/api/login/verify", map[string]string{"loginToken": token, "code": next}); code != 200 {
		t.Fatalf("right code rejected: %d %v", code, out)
	}
	if code, _ := c.req("GET", "/api/routes", nil, nil); code != 200 {
		t.Fatal("not logged in after correct code")
	}

	// A second browser can't reuse that same code (replay protection).
	if code, _ := login(t, e.client(), pw, next); code != 401 {
		t.Fatalf("replayed TOTP code accepted: %d", code)
	}

	// Logout ends the session.
	c.post("/api/logout", nil)
	if code, _ := c.req("GET", "/api/routes", nil, nil); code != 401 {
		t.Fatal("still logged in after logout")
	}
}

func TestRecoveryCodeLogin(t *testing.T) {
	e := newEnv(t)
	c := e.client()
	e.setup(c)
	// Make fresh codes we know.
	_, out := c.post("/api/account/recovery-codes", map[string]string{"password": pw})
	rc := out["recoveryCodes"].([]any)[0].(string)

	if code, out := login(t, e.client(), pw, strings.ToUpper(rc)); code != 200 || out["recoveryCodesLeft"].(float64) != 9 {
		t.Fatalf("recovery login: %d %v", code, out)
	}
	if code, _ := login(t, e.client(), pw, rc); code != 401 {
		t.Fatal("recovery code worked twice")
	}
}

func TestLoginRateLimit(t *testing.T) {
	e := newEnv(t)
	e.setup(e.client())
	c := e.client()
	last := 0
	for range 7 {
		last, _ = c.post("/api/login", map[string]string{"username": "admin", "password": "wrong password!!"})
	}
	if last != 429 {
		t.Fatalf("after 7 failures: %d, want 429", last)
	}
	// Even the right password is refused while locked.
	if code, _ := c.post("/api/login", map[string]string{"username": "admin", "password": pw}); code != 429 {
		t.Fatalf("right password during lockout: %d", code)
	}
}

func TestCSRFProtection(t *testing.T) {
	e := newEnv(t)
	c := e.client()
	e.setup(c)
	body := map[string]any{"hostname": "x.example.com", "enabled": true,
		"config": map[string]any{"targets": []map[string]string{{"url": "http://127.0.0.1:1"}}}}

	cases := map[string]map[string]string{
		"no custom header":  {"X-RyProx": ""},
		"cross-site fetch":  {"Sec-Fetch-Site": "cross-site"},
		"same-site fetch":   {"Sec-Fetch-Site": "same-site"},
		"foreign origin":    {"Origin": "https://evil.example"},
		"form content type": {"Content-Type": "application/x-www-form-urlencoded"},
	}
	for name, hdr := range cases {
		if code, _ := c.req("POST", "/api/routes", body, hdr); code != 403 && code != 415 {
			t.Errorf("%s: got %d, want refusal", name, code)
		}
	}
	routes, _ := e.srv.Store.ListRoutes(t.Context())
	if len(routes) != 0 {
		t.Fatal("a forged request created a route")
	}
}

func TestSecurityHeaders(t *testing.T) {
	e := newEnv(t)
	resp, err := http.Get(e.ts.URL + "/") //nolint:noctx // test
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	for _, h := range []string{"Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"} {
		if resp.Header.Get(h) == "" {
			t.Errorf("missing %s", h)
		}
	}
	if !strings.Contains(resp.Header.Get("Content-Security-Policy"), "script-src 'self'") {
		t.Error("CSP allows inline scripts")
	}
}

func TestRoutesCRUDAndLiveProxy(t *testing.T) {
	e := newEnv(t)
	c := e.client()
	e.setup(c)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "hello from backend")
	}))
	t.Cleanup(backend.Close)

	route := map[string]any{"hostname": "App.Example.com", "enabled": true,
		"config": map[string]any{"targets": []map[string]string{{"url": backend.URL}}, "websockets": true,
			"access": map[string]any{"mode": "public"}}}
	code, out := c.post("/api/routes", route)
	if code != 201 || out["hostname"] != "app.example.com" {
		t.Fatalf("create: %d %v", code, out)
	}
	id := int64(out["id"].(float64))

	// It works through the proxy immediately.
	req := httptest.NewRequestWithContext(t.Context(), "GET", "http://app.example.com/", nil)
	rec := httptest.NewRecorder()
	e.engine.ServeHTTP(rec, req)
	if rec.Body.String() != "hello from backend" {
		t.Fatalf("proxy: %d %q", rec.Code, rec.Body.String())
	}

	// Duplicate and invalid routes are refused with the field named.
	if code, out := c.post("/api/routes", route); code != 409 || out["field"] != "hostname" {
		t.Fatalf("duplicate: %d %v", code, out)
	}
	bad := map[string]any{"hostname": "b.example.com", "config": map[string]any{"targets": []map[string]string{{"url": "10.0.0.1:80"}}}}
	if code, out := c.post("/api/routes", bad); code != 400 || out["field"] != "targets.0" {
		t.Fatalf("invalid: %d %v", code, out)
	}
	if code, _ := c.req("POST", "/api/routes", map[string]any{"hostname": "x", "evil": 1}, nil); code != 400 {
		t.Fatal("unknown JSON fields accepted")
	}

	// Disable → no longer served.
	if code, _ := c.post(fmt.Sprintf("/api/routes/%d/enabled", id), map[string]bool{"enabled": false}); code != 200 {
		t.Fatal("disable failed")
	}
	rec = httptest.NewRecorder()
	e.engine.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), "GET", "http://app.example.com/", nil))
	if rec.Code != 404 {
		t.Fatalf("disabled route still served: %d", rec.Code)
	}

	// Listing includes health and certificate status.
	_, list := c.req("GET", "/api/routes", nil, nil)
	if n := len(list["routes"].([]any)); n != 1 {
		t.Fatalf("%d routes listed", n)
	}

	// Test-target button.
	if code, out := c.post("/api/test-target", map[string]any{"url": backend.URL}); code != 200 || out["state"] != "up" {
		t.Fatalf("test target: %d %v", code, out)
	}

	// Delete.
	if code, _ := c.req("DELETE", fmt.Sprintf("/api/routes/%d", id), nil, nil); code != 200 {
		t.Fatal("delete failed")
	}
	_, act := c.req("GET", "/api/activity", nil, nil)
	if len(act["list"].([]any)) < 4 {
		t.Fatalf("activity log too short: %v", act)
	}
}

func TestSettingsValidation(t *testing.T) {
	e := newEnv(t)
	c := e.client()
	e.setup(c)
	// Admin domain without HTTPS is refused.
	if code, out := c.req("PUT", "/api/settings", map[string]any{"tlsMode": "off", "adminHostname": "admin.example.com"}, nil); code != 400 || out["field"] != "adminHostname" {
		t.Fatalf("admin domain without HTTPS: %d %v", code, out)
	}
	ok := map[string]any{"tlsMode": "acme", "acmeEmail": "me@example.com", "acmeStaging": true, "adminHostname": "admin.example.com"}
	if code, out := c.req("PUT", "/api/settings", ok, nil); code != 200 {
		t.Fatalf("valid settings: %d %v", code, out)
	}
	// A route can't take the admin domain.
	route := map[string]any{"hostname": "admin.example.com", "enabled": true,
		"config": map[string]any{"targets": []map[string]string{{"url": "http://127.0.0.1:9"}}}}
	if code, out := c.post("/api/routes", route); code != 400 || out["field"] != "hostname" {
		t.Fatalf("route on admin domain: %d %v", code, out)
	}
}

func TestPasswordChangeSignsOutOthers(t *testing.T) {
	e := newEnv(t)
	a := e.client()
	secret := e.setup(a)
	b := e.client()
	next, _ := auth.TOTPCodeAt(secret, time.Now().Add(30*time.Second))
	if code, _ := login(t, b, pw, next); code != 200 {
		t.Fatal("second login failed")
	}
	if code, out := a.post("/api/account/password", map[string]string{"current": pw, "new": "another great password"}); code != 200 {
		t.Fatalf("change: %d %v", code, out)
	}
	if code, _ := b.req("GET", "/api/routes", nil, nil); code != 401 {
		t.Fatal("other session survived a password change")
	}
	if code, _ := a.req("GET", "/api/routes", nil, nil); code != 200 {
		t.Fatal("current session was signed out")
	}
}

func TestLoginTokenBoundToIP(t *testing.T) {
	e := newEnv(t)
	e.setup(e.client())
	c := e.client()
	_, out := c.post("/api/login", map[string]string{"username": "admin", "password": pw})
	token := out["loginToken"].(string)
	// Simulate the token being used from a different address.
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/login/verify",
		strings.NewReader(fmt.Sprintf(`{"loginToken":%q,"code":"000000"}`, token)))
	req.Host = "127.0.0.1"
	req.RemoteAddr = "127.0.0.2:1234" // this machine, but a different address
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-RyProx", "1")
	rec := httptest.NewRecorder()
	e.srv.Handler().ServeHTTP(rec, req)
	if rec.Code != 401 || !strings.Contains(rec.Body.String(), "expired") {
		t.Fatalf("token used from another IP: %d %s", rec.Code, rec.Body.String())
	}
}
