// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rylanq/ryprox/internal/auth"
	"github.com/rylanq/ryprox/internal/proxy"
	"github.com/rylanq/ryprox/internal/store"
)

const (
	signInHost = "login.example.com"
	visitor    = "198.51.100.7:4000"
	attacker   = "203.0.113.66:4000"
	memberPW   = "member password!!"
)

// enableSignIn turns on HTTPS with a sign-in domain.
func (e *env) enableSignIn() {
	e.t.Helper()
	st := store.Settings{TLSMode: store.TLSModeACME, ACMEEmail: "a@example.com", ACMEStaging: true, AuthHostname: signInHost}
	if err := e.srv.Store.SaveSettings(e.t.Context(), st); err != nil {
		e.t.Fatal(err)
	}
	e.srv.settings.Store(&st)
	e.srv.Certs.Configure(st)
}

type browserReq struct {
	method, url, cookie, from string
	body                      any
	header                    map[string]string
}

func (e *env) send(h http.Handler, br browserReq) *httptest.ResponseRecorder {
	e.t.Helper()
	var rd *bytes.Reader
	if br.body != nil {
		b, _ := json.Marshal(br.body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequestWithContext(e.t.Context(), br.method, br.url, rd)
	req.RemoteAddr = br.from
	if br.body != nil {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-RyProx", "1")
	} else {
		req.Header.Set("Sec-Fetch-Mode", "navigate")
	}
	if br.cookie != "" {
		req.Header.Set("Cookie", br.cookie)
	}
	for k, v := range br.header {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// signInPage sends a request to the sign-in domain.
func (e *env) signInPage(method, path, cookie string, body any, from string) *httptest.ResponseRecorder {
	return e.send(e.srv.SignInHandler(), browserReq{method: method, url: "https://" + signInHost + path, cookie: cookie, body: body, from: from})
}

// site sends a request to a route through the proxy engine.
func (e *env) site(method, host, path, cookie string, from string) *httptest.ResponseRecorder {
	return e.send(e.engine, browserReq{method: method, url: "https://" + host + path, cookie: cookie, from: from})
}

func sessionCookie(rec *httptest.ResponseRecorder) string {
	for _, c := range rec.Result().Cookies() {
		if strings.Contains(c.Name, "ryprox") && c.Value != "" {
			return c.Name + "=" + c.Value
		}
	}
	return ""
}

func decode(rec *httptest.ResponseRecorder) map[string]any {
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out
}

func (e *env) privateRoute(admin *client, host, backend string, users []int64) int64 {
	e.t.Helper()
	code, out := admin.post("/api/routes", map[string]any{"hostname": host, "enabled": true,
		"config": map[string]any{"targets": []map[string]string{{"url": backend}}, "websockets": true,
			"access": map[string]any{"mode": "private", "users": users}}})
	if code != 201 {
		e.t.Fatalf("create route: %d %v", code, out)
	}
	return int64(out["id"].(float64))
}

func (e *env) setAccess(admin *client, id int64, host, backend string, users []int64) {
	e.t.Helper()
	code, out := admin.req("PUT", fmt.Sprintf("/api/routes/%d", id), map[string]any{"hostname": host, "enabled": true,
		"config": map[string]any{"targets": []map[string]string{{"url": backend}},
			"access": map[string]any{"mode": "private", "users": users}}}, nil)
	if code != 200 {
		e.t.Fatalf("set access: %d %v", code, out)
	}
}

// join invites name to routes and accepts the invite on the sign-in domain.
// It returns the user ID, TOTP secret and sign-in domain cookie.
func (e *env) join(admin *client, name string, routes []int64) (int64, string, string) {
	e.t.Helper()
	code, out := admin.post("/api/invites", map[string]any{"username": name, "role": "member", "routes": routes})
	if code != 201 {
		e.t.Fatalf("invite: %d %v", code, out)
	}
	link := out["url"].(string)
	if !strings.HasPrefix(link, "https://"+signInHost+"/.ryprox/invite#") {
		e.t.Fatalf("invite link must be on the sign-in domain, in the fragment: %s", link)
	}
	token := link[strings.Index(link, "#")+1:]
	begin := e.signInPage("POST", "/.ryprox/api/invite/begin", "", map[string]string{"token": token}, visitor)
	secret := decode(begin)["totpSecret"].(string)
	totp, _ := auth.TOTPCodeAt(secret, time.Now())
	fin := e.signInPage("POST", "/.ryprox/api/invite/finish", "", map[string]string{
		"token": token, "password": memberPW, "totpSecret": secret, "totpCode": totp}, visitor)
	if fin.Code != 200 || decode(fin)["signedIn"] != true {
		e.t.Fatalf("finish: %d %s", fin.Code, fin.Body.String())
	}
	if again := e.signInPage("POST", "/.ryprox/api/invite/begin", "", map[string]string{"token": token}, visitor); again.Code != 404 {
		e.t.Fatalf("invite reused: %d", again.Code)
	}
	_, people := admin.req("GET", "/api/people", nil, nil)
	var id int64
	for _, p := range people["people"].([]any) {
		if p.(map[string]any)["username"] == name {
			id = int64(p.(map[string]any)["id"].(float64))
		}
	}
	return id, secret, sessionCookie(fin)
}

// open signs in to host using a sign-in domain session, following the
// one-time-code handover, and returns the site cookie.
func (e *env) open(host, rd, signInCookie, from string) (string, *httptest.ResponseRecorder) {
	e.t.Helper()
	cont := e.signInPage("POST", "/.ryprox/api/continue", signInCookie, map[string]string{"site": host, "rd": rd}, from)
	if cont.Code != 200 {
		return "", cont
	}
	u, _ := url.Parse(decode(cont)["url"].(string))
	if u.Host != host || u.Path != "/.ryprox/callback" {
		e.t.Fatalf("callback URL %s", u)
	}
	cb := e.site("GET", host, u.RequestURI(), "", from)
	return sessionCookie(cb), cb
}

func identityBackend(t *testing.T) *httptest.Server {
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "user=%s cookie=%s", r.Header.Get(proxy.UserHeader), r.Header.Get("Cookie"))
	}))
	t.Cleanup(b.Close)
	return b
}

func TestPrivateIsTheDefault(t *testing.T) {
	e := newEnv(t)
	admin := e.client()
	e.setup(admin)
	b := identityBackend(t)
	code, out := admin.post("/api/routes", map[string]any{"hostname": "d.example.com", "enabled": true,
		"config": map[string]any{"targets": []map[string]string{{"url": b.URL}}}})
	if code != 201 || out["config"].(map[string]any)["access"].(map[string]any)["mode"] != "private" {
		t.Fatalf("new route not private: %v", out)
	}
	// Without a sign-in domain, private sites refuse everyone.
	if rec := e.site("GET", "d.example.com", "/", "", visitor); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("no sign-in domain: %d", rec.Code)
	}
	e.enableSignIn()
	rec := e.site("GET", "d.example.com", "/photos?x=1", "", visitor)
	want := "https://" + signInHost + "/.ryprox/login?" + url.Values{"site": {"d.example.com"}, "rd": {"/photos?x=1"}}.Encode()
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != want {
		t.Fatalf("anonymous visitor: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if strings.Contains(rec.Body.String(), "user=") {
		t.Fatal("backend reached without signing in")
	}
	api := e.send(e.engine, browserReq{method: "GET", url: "https://d.example.com/api", from: visitor,
		header: map[string]string{"Sec-Fetch-Mode": "cors"}})
	if api.Code != http.StatusUnauthorized {
		t.Fatalf("API call: %d", api.Code)
	}
}

func TestSignInHappensOnlyOnTheSignInDomain(t *testing.T) {
	e := newEnv(t)
	admin := e.client()
	e.setup(admin)
	e.enableSignIn()
	b := identityBackend(t)
	e.privateRoute(admin, "photos.example.com", b.URL, nil)
	// No sign-in pages, APIs or invites on a route's own domain, where its
	// backend could interfere with them.
	for _, p := range []string{"/.ryprox/login", "/.ryprox/", "/.ryprox/invite", "/.ryprox/static/portal.js", "/.ryprox/api/state"} {
		if rec := e.site("GET", "photos.example.com", p, "", visitor); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s on a route: %d", p, rec.Code)
		}
	}
	rec := e.send(e.engine, browserReq{method: "POST", url: "https://photos.example.com/.ryprox/api/login", from: visitor,
		body: map[string]string{"username": "admin", "password": pw}})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("POST login on a route: %d", rec.Code)
	}
}

func TestMemberSignInAndHandover(t *testing.T) {
	e := newEnv(t)
	admin := e.client()
	e.setup(admin)
	e.enableSignIn()
	b := identityBackend(t)
	photos := e.privateRoute(admin, "photos.example.com", b.URL, nil)
	nas := e.privateRoute(admin, "nas.example.com", b.URL, nil)
	sam, _, signIn := e.join(admin, "sam", []int64{photos})

	cookie, cb := e.open("photos.example.com", "/album?id=2", signIn, visitor)
	if cookie == "" || cb.Code != http.StatusFound || cb.Header().Get("Location") != "/album?id=2" {
		t.Fatalf("handover: %d %q %q", cb.Code, cookie, cb.Header().Get("Location"))
	}
	// The backend learns who it is and never sees a RyProx cookie, even a forged identity.
	rec := e.send(e.engine, browserReq{method: "GET", url: "https://photos.example.com/", cookie: cookie + "; theme=dark", from: visitor,
		header: map[string]string{proxy.UserHeader: "admin", "X_Ryprox_User": "admin"}})
	if body := rec.Body.String(); body != "user=sam cookie=theme=dark" {
		t.Fatalf("photos as sam: %d %q", rec.Code, body)
	}
	// Sam isn't on nas's list: no code is issued.
	if _, cont := e.open("nas.example.com", "/", signIn, visitor); cont.Code != http.StatusForbidden || decode(cont)["denied"] != true {
		t.Fatalf("continue to a site without access: %d", cont.Code)
	}
	// The photos session doesn't open nas, even once Sam is allowed there.
	e.setAccess(admin, nas, "nas.example.com", b.URL, []int64{sam})
	if rec := e.site("GET", "nas.example.com", "/", cookie, visitor); rec.Code != http.StatusFound ||
		!strings.HasPrefix(rec.Header().Get("Location"), "https://"+signInHost+"/.ryprox/login") {
		t.Fatalf("photos cookie opened nas: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	// Public or unknown sites get no code.
	if _, cont := e.open("unknown.example.com", "/", signIn, visitor); cont.Code != http.StatusNotFound {
		t.Fatalf("continue to unknown site: %d", cont.Code)
	}
}

func TestHandoverCodes(t *testing.T) {
	e := newEnv(t)
	admin := e.client()
	e.setup(admin)
	e.enableSignIn()
	b := identityBackend(t)
	photos := e.privateRoute(admin, "photos.example.com", b.URL, nil)
	nas := e.privateRoute(admin, "nas.example.com", b.URL, nil)
	_, _, signIn := e.join(admin, "sam", []int64{photos, nas})

	issue := func() string {
		cont := e.signInPage("POST", "/.ryprox/api/continue", signIn, map[string]string{"site": "photos.example.com", "rd": "/"}, visitor)
		u, _ := url.Parse(decode(cont)["url"].(string))
		return u.RequestURI()
	}
	redeemed := func(host, uri, from string) bool {
		return sessionCookie(e.site("GET", host, uri, "", from)) != ""
	}
	// Single use.
	uri := issue()
	if !redeemed("photos.example.com", uri, visitor) || redeemed("photos.example.com", uri, visitor) {
		t.Fatal("code is not single-use")
	}
	// Bound to the visitor's address: a code someone else obtained can't be
	// used to sign a victim in (login CSRF), or by the attacker.
	if redeemed("photos.example.com", issue(), attacker) {
		t.Fatal("code redeemed from another address")
	}
	// Bound to one site.
	if redeemed("nas.example.com", issue(), visitor) {
		t.Fatal("photos code redeemed on nas")
	}
	// Made-up codes do nothing.
	if redeemed("photos.example.com", "/.ryprox/callback?code=guess&rd=/", visitor) {
		t.Fatal("invented code accepted")
	}
}

func TestRevocationIsImmediate(t *testing.T) {
	e := newEnv(t)
	admin := e.client()
	e.setup(admin)
	e.enableSignIn()
	b := identityBackend(t)
	photos := e.privateRoute(admin, "photos.example.com", b.URL, nil)
	sam, _, signIn := e.join(admin, "sam", []int64{photos})
	cookie, _ := e.open("photos.example.com", "/", signIn, visitor)

	e.setAccess(admin, photos, "photos.example.com", b.URL, []int64{})
	if rec := e.site("GET", "photos.example.com", "/", cookie, visitor); rec.Code != http.StatusFound ||
		!strings.HasPrefix(rec.Header().Get("Location"), "https://"+signInHost+"/.ryprox/denied") {
		t.Fatalf("after removal: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	e.setAccess(admin, photos, "photos.example.com", b.URL, []int64{sam})
	if code, out := admin.req("PUT", fmt.Sprintf("/api/people/%d", sam), map[string]any{"role": "member", "disabled": true}, nil); code != 200 {
		t.Fatalf("disable: %d %v", code, out)
	}
	if rec := e.site("GET", "photos.example.com", "/", cookie, visitor); rec.Code != http.StatusFound ||
		!strings.HasPrefix(rec.Header().Get("Location"), "https://"+signInHost+"/.ryprox/login") {
		t.Fatalf("disabled user still in: %d", rec.Code)
	}
	if rec := e.signInPage("POST", "/.ryprox/api/continue", signIn, map[string]string{"site": "photos.example.com"}, visitor); rec.Code != http.StatusUnauthorized {
		t.Fatalf("disabled user's sign-in session still works: %d", rec.Code)
	}
}

func TestMembersCantUseTheDashboard(t *testing.T) {
	e := newEnv(t)
	admin := e.client()
	e.setup(admin)
	e.enableSignIn()
	b := identityBackend(t)
	photos := e.privateRoute(admin, "photos.example.com", b.URL, nil)
	_, secret, signIn := e.join(admin, "sam", []int64{photos})

	m := e.client()
	code, out := m.post("/api/login", map[string]string{"username": "sam", "password": memberPW})
	if code != 200 {
		t.Fatalf("password step: %d %v", code, out)
	}
	next, _ := auth.TOTPCodeAt(secret, time.Now().Add(30*time.Second))
	if code, _ := m.post("/api/login/verify", map[string]string{"loginToken": out["loginToken"].(string), "code": next}); code != 403 {
		t.Fatalf("member signed in to dashboard: %d", code)
	}
	if code, _ := m.req("GET", "/api/routes", nil, nil); code != 401 {
		t.Fatal("member reached the admin API")
	}
	for _, stolen := range []string{
		strings.Replace(signIn, "__Host-ryprox-access=", "ryprox=", 1),
		strings.Replace(signIn, "__Host-ryprox-access=", "ryprox-access=", 1),
	} {
		if code, _ := m.req("GET", "/api/routes", nil, map[string]string{"Cookie": stolen}); code != 401 {
			t.Fatal("sign-in session accepted by the dashboard")
		}
	}
}

func TestSafeRedirectPath(t *testing.T) {
	cases := map[string]string{
		"/album?id=2":           "/album?id=2",
		"/a/b/":                 "/a/b/",
		"":                      "/",
		"https://evil.com/":     "/",
		"//evil.com":            "/",
		"/.//evil.com":          "/evil.com",
		"/%2e//evil.com":        "/evil.com",
		"/a/..//evil.com":       "/evil.com",
		"/\\evil.com":           "/",
		"/.ryprox/login":        "/",
		"/.ryprox":              "/",
		"/x\r\nSet-Cookie: a=b": "/",
		"javascript:alert(1)":   "/",
	}
	for in, want := range cases {
		got := safeRedirectPath(in)
		if got != want {
			t.Errorf("safeRedirectPath(%q) = %q, want %q", in, got, want)
		}
		if strings.HasPrefix(got, "//") || !strings.HasPrefix(got, "/") {
			t.Errorf("%q produced an off-site redirect %q", in, got)
		}
	}
}

func TestStrangersCantLockOutTheAdmin(t *testing.T) {
	e := newEnv(t)
	admin := e.client()
	secret := e.setup(admin)
	e.enableSignIn()
	// Failures from many addresses on the public sign-in page...
	for i := range 12 {
		for range 7 {
			e.signInPage("POST", "/.ryprox/api/login", "", map[string]string{"username": "admin", "password": "wrong password!!"},
				fmt.Sprintf("203.0.113.%d:1000", i))
		}
	}
	// ...lock out each guessing address...
	if rec := e.signInPage("POST", "/.ryprox/api/login", "", map[string]string{"username": "admin", "password": pw}, "203.0.113.1:1000"); rec.Code != 429 {
		t.Fatalf("attacker address not limited: %d", rec.Code)
	}
	// ...but not the admin, on the sign-in page or the dashboard.
	if rec := e.signInPage("POST", "/.ryprox/api/login", "", map[string]string{"username": "admin", "password": pw}, visitor); rec.Code != 200 {
		t.Fatalf("admin locked out of sign-in page: %d", rec.Code)
	}
	if code, _ := login(t, e.client(), pw, mustCode(secret, 30*time.Second)); code != 200 {
		t.Fatalf("admin locked out of dashboard: %d", code)
	}
}

func mustCode(secret string, offset time.Duration) string {
	c, _ := auth.TOTPCodeAt(secret, time.Now().Add(offset))
	return c
}

func TestParallelGuessesAreLimited(t *testing.T) {
	e := newEnv(t)
	e.setup(e.client())
	e.enableSignIn()
	var mu sync.Mutex
	evaluated := 0
	var wg sync.WaitGroup
	for range 40 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := e.signInPage("POST", "/.ryprox/api/login", "", map[string]string{"username": "admin", "password": "wrong password!!"}, attacker)
			if rec.Code == http.StatusUnauthorized {
				mu.Lock()
				evaluated++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if evaluated > 6 {
		t.Fatalf("%d parallel guesses were checked; at most 6 should be", evaluated)
	}
}

func TestDashboardListenerChecks(t *testing.T) {
	e := newEnv(t)
	h := e.srv.Handler()
	// DNS rebinding: a page on evil.com resolving to 127.0.0.1.
	rec := e.send(h, browserReq{method: "GET", url: "http://evil.example/api/state", from: "127.0.0.1:1"})
	if rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("foreign Host accepted: %d", rec.Code)
	}
	// Passwords over plain HTTP from another machine are refused, even with a localhost Host.
	rec = e.send(h, browserReq{method: "POST", url: "http://localhost:8081/api/login", from: "198.51.100.9:1",
		body: map[string]string{"username": "admin", "password": pw}})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("plain-HTTP login from another machine: %d", rec.Code)
	}
	// From this machine it's fine.
	rec = e.send(h, browserReq{method: "POST", url: "http://localhost:8081/api/login", from: "127.0.0.1:1",
		body: map[string]string{"username": "admin", "password": pw}})
	if rec.Code == http.StatusForbidden || rec.Code == http.StatusMisdirectedRequest {
		t.Fatalf("local login refused: %d", rec.Code)
	}
}

func TestReadGateway(t *testing.T) {
	p := filepath.Join(t.TempDir(), "route")
	table := "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
		"eth0\t00000000\t010011AC\t0003\t0\t0\t0\t00000000\t0\t0\t0\n" +
		"eth0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n"
	if err := os.WriteFile(p, []byte(table), 0o600); err != nil {
		t.Fatal(err)
	}
	if ip := readGateway(p); ip == nil || ip.String() != "172.17.0.1" {
		t.Fatalf("gateway = %v, want 172.17.0.1", ip)
	}
}

func TestRecoveryCodesAreKeyed(t *testing.T) {
	e := newEnv(t)
	admin := e.client()
	e.setup(admin)
	_, out := admin.post("/api/account/recovery-codes", map[string]string{"password": pw})
	rc := out["recoveryCodes"].([]any)[0].(string)
	u, _ := e.srv.Store.GetUserByUsername(t.Context(), "admin")
	for _, h := range u.RecoveryCodes {
		if h == auth.HashRecoveryCode(rc) {
			t.Fatal("recovery code stored with an unkeyed hash")
		}
	}
	// Codes stored the old way still work, once.
	_ = e.srv.Store.SetRecoveryCodes(t.Context(), u.ID, []string{auth.HashRecoveryCode("abcd-efgh-jkmn")})
	if code, _ := login(t, e.client(), pw, "ABCD-EFGH-JKMN"); code != 200 {
		t.Fatalf("legacy recovery code rejected: %d", code)
	}
	if code, _ := login(t, e.client(), pw, "abcd-efgh-jkmn"); code != 401 {
		t.Fatal("legacy recovery code worked twice")
	}
}

func TestInvitesDieWithTheirAdmin(t *testing.T) {
	e := newEnv(t)
	admin := e.client()
	e.setup(admin)
	e.enableSignIn()
	// A second admin creates an invite, then is demoted.
	code, out := admin.post("/api/invites", map[string]any{"username": "boss2", "role": "admin"})
	if code != 201 {
		t.Fatalf("invite: %d %v", code, out)
	}
	link := out["url"].(string)
	token := link[strings.Index(link, "#")+1:]
	begin := e.signInPage("POST", "/.ryprox/api/invite/begin", "", map[string]string{"token": token}, visitor)
	secret := decode(begin)["totpSecret"].(string)
	fin := e.signInPage("POST", "/.ryprox/api/invite/finish", "", map[string]string{
		"token": token, "password": memberPW, "totpSecret": secret, "totpCode": mustCode(secret, 0)}, visitor)
	if fin.Code != 200 {
		t.Fatalf("finish: %d %s", fin.Code, fin.Body.String())
	}
	boss2, _ := e.srv.Store.GetUserByUsername(t.Context(), "boss2")
	inv := &store.Invite{TokenHash: auth.HashToken("pending"), Username: "pending", Role: store.RoleAdmin,
		CreatedBy: "boss2", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}
	if err := e.srv.Store.CreateInvite(t.Context(), inv); err != nil {
		t.Fatal(err)
	}
	if code, _ := admin.req("PUT", fmt.Sprintf("/api/people/%d", boss2.ID), map[string]any{"role": "member"}, nil); code != 200 {
		t.Fatal("demote failed")
	}
	if _, err := e.srv.Store.GetInviteByHash(t.Context(), auth.HashToken("pending")); err == nil {
		t.Fatal("invite from a demoted admin is still valid")
	}
}
