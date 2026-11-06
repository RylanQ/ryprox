// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/rylanq/ryprox/internal/auth"
	"github.com/rylanq/ryprox/internal/proxy"
)

func loginAs(t *testing.T, c *client, user, password, code string) (int, map[string]any) {
	t.Helper()
	status, out := c.post("/api/login", map[string]string{"username": user, "password": password})
	if status != 200 {
		return status, out
	}
	return c.post("/api/login/verify", map[string]string{"loginToken": out["loginToken"].(string), "code": code})
}

func headerBackend(t *testing.T) *httptest.Server {
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "user=%s auth=%s token=%s", r.Header.Get(proxy.UserHeader), r.Header.Get("Authorization"), r.Header.Get(proxy.TokenHeader))
	}))
	t.Cleanup(b.Close)
	return b
}

func (e *env) tokenReq(host, path string, hdr map[string]string) *httptest.ResponseRecorder {
	h := map[string]string{"Sec-Fetch-Mode": "cors"}
	for k, v := range hdr {
		h[k] = v
	}
	return e.send(e.engine, browserReq{method: "GET", url: "https://" + host + path, from: visitor, header: h})
}

func TestSitesToken(t *testing.T) {
	e := newEnv(t)
	admin := e.client()
	e.setup(admin)
	e.enableSignIn()
	b := headerBackend(t)
	id := e.privateRoute(admin, "api.example.com", b.URL, []int64{1})

	code, out := admin.post("/api/account/tokens", map[string]any{"name": "backup", "scope": "sites"})
	if code != 200 || !strings.HasPrefix(out["token"].(string), "ryp_") {
		t.Fatalf("create: %d %v", code, out)
	}
	tok := out["token"].(string)

	for _, hdr := range []map[string]string{{"X-RyProx-Token": tok}, {"Authorization": "Bearer " + tok}} {
		rec := e.tokenReq("api.example.com", "/", hdr)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "user=admin auth= token=") {
			t.Fatalf("with %v: %d %s", hdr, rec.Code, rec.Body.String())
		}
	}
	// The app's own Authorization header is left alone on public routes and
	// non-RyProx bearer tokens pass through.
	if rec := e.tokenReq("api.example.com", "/", map[string]string{"X-RyProx-Token": "ryp_wrong"}); rec.Code != 401 {
		t.Fatalf("wrong token: %d", rec.Code)
	}
	// Taken off the access list: refused.
	e.setAccess(admin, id, "api.example.com", b.URL, []int64{})
	if rec := e.tokenReq("api.example.com", "/", map[string]string{"X-RyProx-Token": tok}); rec.Code != 401 {
		t.Fatalf("removed from route: %d", rec.Code)
	}
	e.setAccess(admin, id, "api.example.com", b.URL, []int64{1})
	// A sites token can't use the admin API.
	if code, _ := admin.req("GET", "/api/routes", nil, map[string]string{"Authorization": "Bearer " + tok, "Cookie": ""}); code != 401 {
		t.Fatalf("sites token on admin API: %d", code)
	}
	// Deleted: refused.
	_, list := admin.req("GET", "/api/account/tokens", nil, nil)
	tid := int64(list["tokens"].([]any)[0].(map[string]any)["id"].(float64))
	if code, _ := admin.req("DELETE", fmt.Sprintf("/api/account/tokens/%d", tid), nil, nil); code != 200 {
		t.Fatal("delete failed")
	}
	if rec := e.tokenReq("api.example.com", "/", map[string]string{"X-RyProx-Token": tok}); rec.Code != 401 {
		t.Fatalf("deleted token: %d", rec.Code)
	}
}

func TestAdminToken(t *testing.T) {
	e := newEnv(t)
	admin := e.client()
	e.setup(admin)
	_, out := admin.post("/api/account/tokens", map[string]any{"name": "ci", "scope": "admin", "expiresDays": 30})
	tok := out["token"].(string)

	script := e.client() // no cookies, no CSRF header: like curl
	bearer := map[string]string{"Authorization": "Bearer " + tok, "X-RyProx": ""}
	if code, out := script.req("GET", "/api/routes", nil, bearer); code != 200 {
		t.Fatalf("admin token: %d %v", code, out)
	}
	if code, _ := script.req("POST", "/api/routes", map[string]any{"hostname": "x.example.com",
		"config": map[string]any{"targets": []map[string]string{{"url": "http://10.0.0.1"}}}}, bearer); code != 201 {
		t.Fatalf("create route with token: %d", code)
	}
	// Account security needs a person, not a token.
	for _, path := range []string{"/api/account/tokens", "/api/account/passkeys"} {
		if code, _ := script.req("GET", path, nil, bearer); code != 403 {
			t.Fatalf("%s with token: %d", path, code)
		}
	}
	if code, _ := script.req("GET", "/api/routes", nil, map[string]string{"Authorization": "Bearer ryp_nope"}); code != 401 {
		t.Fatalf("bad token: %d", code)
	}
}

func TestTokenScopesForMembers(t *testing.T) {
	e := newEnv(t)
	admin := e.client()
	e.setup(admin)
	e.enableSignIn()
	_, _, cookie := e.join(admin, "sam", nil)
	rec := e.signInPage("POST", "/.ryprox/api/tokens", cookie, map[string]any{"name": "x", "scope": "admin"}, visitor)
	if rec.Code != 403 {
		t.Fatalf("member made admin token: %d", rec.Code)
	}
	rec = e.signInPage("POST", "/.ryprox/api/tokens", cookie, map[string]any{"name": "x", "scope": "sites"}, visitor)
	if rec.Code != 200 {
		t.Fatalf("member sites token: %d %s", rec.Code, rec.Body.String())
	}
}

func TestPasskeyNeedsPassword(t *testing.T) {
	e := newEnv(t)
	byIP := e.client()
	e.setup(byIP)
	if code, _ := byIP.req("POST", "/api/account/passkeys/begin", map[string]string{"password": pw}, nil); code != 400 {
		t.Fatalf("IP address host: %d", code)
	}
	admin := e.client()
	admin.host = "localhost"
	secret := e.setupSecret
	totp, _ := auth.TOTPCodeAt(secret, time.Now().Add(30*time.Second))
	if code, out := loginAs(t, admin, "admin", pw, totp); code != 200 {
		t.Fatalf("login: %d %v", code, out)
	}
	local := map[string]string{}
	if code, _ := admin.req("POST", "/api/account/passkeys/begin", map[string]string{"password": "wrong"}, local); code != 403 {
		t.Fatalf("wrong password: %d", code)
	}
	code, out := admin.req("POST", "/api/account/passkeys/begin", map[string]string{"password": pw}, local)
	if code != 200 {
		t.Fatalf("begin: %d %v", code, out)
	}
	pk := out["publicKey"].(map[string]any)
	if pk["rp"].(map[string]any)["id"] != "localhost" || pk["authenticatorSelection"].(map[string]any)["userVerification"] != "required" {
		t.Fatalf("options: %v", pk)
	}
	// A finish without a valid response is refused, and the challenge is gone.
	if code, _ := admin.req("POST", "/api/account/passkeys/finish", map[string]string{}, local); code != 400 {
		t.Fatalf("bogus finish: %d", code)
	}
	code, out = admin.req("POST", "/api/login/passkey/begin", map[string]string{}, local)
	if code != 200 || out["options"].(map[string]any)["publicKey"].(map[string]any)["userVerification"] != "required" {
		t.Fatalf("login begin: %d %v", code, out)
	}
	if code, _ := admin.req("POST", "/api/login/passkey/finish?id="+out["id"].(string), map[string]string{}, local); code != 400 {
		t.Fatalf("bogus login finish: %d", code)
	}
}

func TestActivityExport(t *testing.T) {
	e := newEnv(t)
	admin := e.client()
	e.setup(admin)
	req, _ := http.NewRequestWithContext(t.Context(), "GET", e.ts.URL+"/api/activity/export?format=csv", nil)
	resp, err := admin.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/csv") ||
		!strings.Contains(resp.Header.Get("Content-Disposition"), "attachment") {
		t.Fatalf("export: %d %v", resp.StatusCode, resp.Header)
	}
	if csvSafe("=cmd()") != "'=cmd()" || csvSafe("ok") != "ok" {
		t.Fatal("csvSafe")
	}
}

// --- single sign-on -------------------------------------------------------

type fakeIdP struct {
	srv    *httptest.Server
	key    *rsa.PrivateKey
	mu     sync.Mutex
	nonces map[string]string // code → nonce
	claims map[string]any    // claims for the next token
}

func newFakeIdP(t *testing.T) *fakeIdP {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	f := &fakeIdP{key: key, nonces: map[string]string{}}
	mux := http.NewServeMux()
	f.srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.srv.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": f.srv.URL, "authorization_endpoint": f.srv.URL + "/auth",
			"token_endpoint": f.srv.URL + "/token", "jwks_uri": f.srv.URL + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"}})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		nonce, ok := f.nonces[r.Form.Get("code")]
		claims := map[string]any{}
		for k, v := range f.claims {
			claims[k] = v
		}
		f.mu.Unlock()
		if !ok || r.Form.Get("code_verifier") == "" {
			http.Error(w, `{"error":"invalid_grant"}`, 400)
			return
		}
		sig, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: "k1"}}, nil)
		claims["iss"], claims["aud"], claims["nonce"] = f.srv.URL, "ryprox", nonce
		claims["exp"], claims["iat"] = time.Now().Add(time.Hour).Unix(), time.Now().Unix()
		raw, _ := jwt.Signed(sig).Claims(claims).Serialize()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": raw})
	})
	return f
}

// signIn runs the browser side of a provider sign-in and returns the
// callback response.
func (f *fakeIdP) signIn(t *testing.T, e *env, claims map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	start := e.signInPage("GET", "/.ryprox/sso/test/start?site=d.example.com&rd=/x", "", nil, visitor)
	if start.Code != http.StatusFound {
		t.Fatalf("start: %d %s", start.Code, start.Body.String())
	}
	loc, _ := url.Parse(start.Header().Get("Location"))
	q := loc.Query()
	if loc.Path != "/auth" || q.Get("code_challenge_method") != "S256" || q.Get("redirect_uri") != "https://"+signInHost+"/.ryprox/sso/callback" {
		t.Fatalf("auth redirect %s", loc)
	}
	code := fmt.Sprintf("code-%d", time.Now().UnixNano())
	f.mu.Lock()
	f.nonces[code] = q.Get("nonce")
	f.claims = claims
	f.mu.Unlock()
	bind := sessionCookieNamed(start, ssoCookie)
	return e.signInPage("GET", "/.ryprox/sso/callback?"+url.Values{"state": {q.Get("state")}, "code": {code}}.Encode(), bind, nil, visitor)
}

func sessionCookieNamed(rec *httptest.ResponseRecorder, name string) string {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c.Name + "=" + c.Value
		}
	}
	return ""
}

func TestSSO(t *testing.T) {
	e := newEnv(t)
	admin := e.client()
	e.setup(admin)
	e.enableSignIn()
	idp := newFakeIdP(t)
	e.srv.HTTPClient = idp.srv.Client()
	code, out := admin.req("PUT", "/api/sso", map[string]any{"providers": []map[string]any{{"id": "test", "name": "Test",
		"issuer": idp.srv.URL, "clientId": "ryprox", "clientSecret": "s3cret"}}}, nil)
	if code != 200 || strings.Contains(fmt.Sprint(out), "s3cret") {
		t.Fatalf("save providers: %d %v", code, out)
	}
	samID, _, _ := e.join(admin, "sam", nil)

	// No email set: nobody matches, and accounts are never created.
	rec := idp.signIn(t, e, map[string]any{"sub": "g-1", "email": "sam@example.com", "email_verified": true})
	if rec.Code != 401 || sessionCookie(rec) != "" {
		t.Fatalf("unknown email: %d", rec.Code)
	}
	if c, _ := admin.req("PUT", fmt.Sprintf("/api/people/%d/email", samID), map[string]string{"email": "sam@example.com"}, nil); c != 200 {
		t.Fatal("set email")
	}
	// Unverified email is refused.
	if rec := idp.signIn(t, e, map[string]any{"sub": "g-1", "email": "sam@example.com", "email_verified": false}); rec.Code != 401 {
		t.Fatalf("unverified email: %d", rec.Code)
	}
	// Verified: signed in on the sign-in domain, then on to the site.
	rec = idp.signIn(t, e, map[string]any{"sub": "g-1", "email": "SAM@example.com", "email_verified": true})
	if rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), "/.ryprox/login?") || sessionCookie(rec) == "" {
		t.Fatalf("verified: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	state := decode(e.signInPage("GET", "/.ryprox/api/state", sessionCookie(rec), nil, visitor))
	if state["user"] != "sam" {
		t.Fatalf("state %v", state)
	}
	// The link is pinned: another provider account with the same email can't sign in.
	if rec := idp.signIn(t, e, map[string]any{"sub": "g-2", "email": "sam@example.com", "email_verified": true}); rec.Code != 401 {
		t.Fatalf("second account: %d", rec.Code)
	}
	// Changing the email unlinks the old account.
	admin.req("PUT", fmt.Sprintf("/api/people/%d/email", samID), map[string]string{"email": "new@example.com"}, nil)
	if rec := idp.signIn(t, e, map[string]any{"sub": "g-1", "email": "sam@example.com", "email_verified": true}); rec.Code != 401 {
		t.Fatalf("after email change: %d", rec.Code)
	}
}

func TestSSOStateBoundToBrowser(t *testing.T) {
	e := newEnv(t)
	admin := e.client()
	e.setup(admin)
	e.enableSignIn()
	idp := newFakeIdP(t)
	e.srv.HTTPClient = idp.srv.Client()
	admin.req("PUT", "/api/sso", map[string]any{"providers": []map[string]any{{"id": "test", "name": "Test",
		"issuer": idp.srv.URL, "clientId": "ryprox", "clientSecret": "s3cret", "trustEmail": true}}}, nil)
	samID, _, _ := e.join(admin, "sam", nil)
	admin.req("PUT", fmt.Sprintf("/api/people/%d/email", samID), map[string]string{"email": "sam@example.com"}, nil)

	start := e.signInPage("GET", "/.ryprox/sso/test/start", "", nil, visitor)
	loc, _ := url.Parse(start.Header().Get("Location"))
	cb := "/.ryprox/sso/callback?" + url.Values{"state": {loc.Query().Get("state")}, "code": {"c"}}.Encode()
	// A victim lured to the callback without the attacker's binding cookie is refused.
	if rec := e.signInPage("GET", cb, "", nil, visitor); rec.Code != 401 {
		t.Fatalf("missing binding cookie: %d", rec.Code)
	}
	// The state was used up by that attempt.
	if rec := e.signInPage("GET", cb, sessionCookieNamed(start, ssoCookie), nil, visitor); rec.Code != 401 {
		t.Fatalf("state reused: %d", rec.Code)
	}
	// SSO isn't offered on the dashboard.
	if code, _ := admin.req("GET", "/.ryprox/sso/test/start", nil, nil); code != 404 {
		t.Fatalf("dashboard sso: %d", code)
	}
}
