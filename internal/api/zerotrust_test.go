// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/rylanq/ryprox/internal/auth"
	"github.com/rylanq/ryprox/internal/proxy"
)

// site sends a request to a site through the proxy engine, from the given
// address, with an explicit cookie (each site has its own cookie jar).
func (e *env) site(method, host, path, cookie string, body any, from string) *httptest.ResponseRecorder {
	e.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequestWithContext(e.t.Context(), method, "http://"+host+path, rd)
	req.RemoteAddr = from
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-RyProx", "1")
	} else {
		req.Header.Set("Accept", "text/html")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	rec := httptest.NewRecorder()
	e.engine.ServeHTTP(rec, req)
	return rec
}

const local = "127.0.0.1:5555"

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

// privateRoute creates a private route via the admin API and returns its ID.
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

// join invites name with access to routes, and accepts the invite on host.
// It returns the new user's ID, TOTP secret and site cookie.
func (e *env) join(admin *client, name string, routes []int64, host string) (int64, string, string) {
	e.t.Helper()
	code, out := admin.post("/api/invites", map[string]any{"username": name, "role": "member", "routes": routes})
	if code != 201 {
		e.t.Fatalf("invite: %d %v", code, out)
	}
	path := out["path"].(string)
	if !strings.Contains(path, "#") {
		e.t.Fatal("invite token must be in the URL fragment")
	}
	token := path[strings.Index(path, "#")+1:]
	begin := e.site("POST", host, proxy.PortalPrefix+"api/invite/begin", "", map[string]string{"token": token}, local)
	secret := decode(begin)["totpSecret"].(string)
	totp, _ := auth.TOTPCodeAt(secret, time.Now())
	fin := e.site("POST", host, proxy.PortalPrefix+"api/invite/finish", "", map[string]string{
		"token": token, "password": "member password!!", "totpSecret": secret, "totpCode": totp}, local)
	if fin.Code != 200 {
		e.t.Fatalf("finish: %d %s", fin.Code, fin.Body.String())
	}
	// Invites are single-use.
	again := e.site("POST", host, proxy.PortalPrefix+"api/invite/begin", "", map[string]string{"token": token}, local)
	if again.Code != 404 {
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
	rec := e.site("GET", "d.example.com", "/photos?x=1", "", nil, "198.51.100.1:1")
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/.ryprox/login?rd="+url.QueryEscape("/photos?x=1") {
		t.Fatalf("anonymous visitor: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if strings.Contains(rec.Body.String(), "user=") {
		t.Fatal("backend reached without signing in")
	}
	// Non-browser requests get a status, not a redirect.
	req := httptest.NewRequestWithContext(t.Context(), "GET", "http://d.example.com/api/data", nil)
	req.Header.Set("Accept", "application/json")
	api := httptest.NewRecorder()
	e.engine.ServeHTTP(api, req)
	if api.Code != http.StatusUnauthorized {
		t.Fatalf("API call: %d", api.Code)
	}
}

func TestMemberAccessIsCheckedOnEveryRequest(t *testing.T) {
	e := newEnv(t)
	admin := e.client()
	e.setup(admin)
	b := identityBackend(t)
	photos := e.privateRoute(admin, "photos.example.com", b.URL, nil)
	_ = e.privateRoute(admin, "nas.example.com", b.URL, nil)

	sam, _, cookie := e.join(admin, "sam", []int64{photos}, "photos.example.com")
	if cookie == "" {
		t.Fatal("not signed in after accepting the invite on the site")
	}

	// Sam can open photos; the backend learns who it is, never sees the cookie.
	rec := e.site("GET", "photos.example.com", "/", cookie, nil, "198.51.100.1:1")
	if body := rec.Body.String(); body != "user=sam cookie=" {
		t.Fatalf("photos as sam: %d %q", rec.Code, body)
	}
	// A forged identity header from Sam is replaced.
	req := httptest.NewRequestWithContext(t.Context(), "GET", "http://photos.example.com/", nil)
	req.Header.Set("Cookie", cookie)
	req.Header.Set(proxy.UserHeader, "admin")
	forged := httptest.NewRecorder()
	e.engine.ServeHTTP(forged, req)
	if forged.Body.String() != "user=sam cookie=" {
		t.Fatalf("forged identity: %q", forged.Body.String())
	}

	// The photos session doesn't open nas, even once Sam is allowed there:
	// sessions are bound to the site that created them.
	_, routes := admin.req("GET", "/api/routes", nil, nil)
	var nasID int64
	for _, r := range routes["routes"].([]any) {
		if r.(map[string]any)["hostname"] == "nas.example.com" {
			nasID = int64(r.(map[string]any)["id"].(float64))
		}
	}
	e.setAccess(admin, nasID, "nas.example.com", b.URL, []int64{sam})
	if rec := e.site("GET", "nas.example.com", "/", cookie, nil, "198.51.100.1:1"); rec.Code != http.StatusFound ||
		!strings.HasPrefix(rec.Header().Get("Location"), "/.ryprox/login") {
		t.Fatalf("photos cookie opened nas: %d", rec.Code)
	}

	// Removing Sam from photos takes effect on the very next request.
	e.setAccess(admin, photos, "photos.example.com", b.URL, []int64{})
	if rec := e.site("GET", "photos.example.com", "/", cookie, nil, "198.51.100.1:1"); rec.Code != http.StatusFound ||
		rec.Header().Get("Location") != "/.ryprox/denied" {
		t.Fatalf("after removal: %d %q", rec.Code, rec.Header().Get("Location"))
	}

	// Disabling Sam signs them out everywhere.
	e.setAccess(admin, photos, "photos.example.com", b.URL, []int64{sam})
	if code, out := admin.req("PUT", fmt.Sprintf("/api/people/%d", sam), map[string]any{"role": "member", "disabled": true}, nil); code != 200 {
		t.Fatalf("disable: %d %v", code, out)
	}
	if rec := e.site("GET", "photos.example.com", "/", cookie, nil, "198.51.100.1:1"); rec.Code != http.StatusFound ||
		!strings.HasPrefix(rec.Header().Get("Location"), "/.ryprox/login") {
		t.Fatalf("disabled user still in: %d", rec.Code)
	}
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

func TestMembersCantUseTheDashboard(t *testing.T) {
	e := newEnv(t)
	admin := e.client()
	e.setup(admin)
	b := identityBackend(t)
	photos := e.privateRoute(admin, "photos.example.com", b.URL, nil)
	_, secret, cookie := e.join(admin, "sam", []int64{photos}, "photos.example.com")

	// Signing in to the dashboard as a member is refused after both steps.
	m := e.client()
	code, out := m.post("/api/login", map[string]string{"username": "sam", "password": "member password!!"})
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
	// The site cookie, renamed to the dashboard's, is worthless there.
	stolen := strings.Replace(cookie, "ryprox-access=", "ryprox=", 1)
	if code, _ := m.req("GET", "/api/routes", nil, map[string]string{"Cookie": stolen}); code != 401 {
		t.Fatal("site session accepted by the dashboard")
	}
}

func TestSiteLoginRequiresAccessAndHTTPS(t *testing.T) {
	e := newEnv(t)
	admin := e.client()
	secret := e.setup(admin)
	b := identityBackend(t)
	e.privateRoute(admin, "secret.example.com", b.URL, nil) // nobody on the list

	// Passwords are never accepted over plain HTTP from another machine.
	rec := e.site("POST", "secret.example.com", proxy.PortalPrefix+"api/login", "",
		map[string]string{"username": "admin", "password": pw}, "198.51.100.1:1")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("login over plain HTTP: %d", rec.Code)
	}

	// The admin isn't on this site's list, so even a full sign-in is refused.
	rec = e.site("POST", "secret.example.com", proxy.PortalPrefix+"api/login", "",
		map[string]string{"username": "admin", "password": pw}, local)
	token := decode(rec)["loginToken"].(string)
	next, _ := auth.TOTPCodeAt(secret, time.Now().Add(30*time.Second))
	rec = e.site("POST", "secret.example.com", proxy.PortalPrefix+"api/login/verify", "",
		map[string]string{"loginToken": token, "code": next}, local)
	if rec.Code != http.StatusForbidden || sessionCookie(rec) != "" {
		t.Fatalf("signed in without access: %d", rec.Code)
	}
	// A login token from the dashboard can't be finished on a site.
	_, dl := admin.post("/api/login", map[string]string{"username": "admin", "password": pw})
	rec = e.site("POST", "secret.example.com", proxy.PortalPrefix+"api/login/verify", "",
		map[string]string{"loginToken": dl["loginToken"].(string), "code": "000000"}, local)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("cross-realm login token: %d", rec.Code)
	}
}

func TestAdminSafetyRails(t *testing.T) {
	e := newEnv(t)
	admin := e.client()
	e.setup(admin)
	_, people := admin.req("GET", "/api/people", nil, nil)
	me := int64(people["me"].(float64))
	if code, _ := admin.req("PUT", fmt.Sprintf("/api/people/%d", me), map[string]any{"role": "member"}, nil); code != 400 {
		t.Fatal("admin demoted themselves")
	}
	if code, _ := admin.req("DELETE", fmt.Sprintf("/api/people/%d", me), nil, nil); code != 400 {
		t.Fatal("admin deleted themselves")
	}
	if code, _ := admin.post("/api/invites", map[string]any{"username": "Admin", "role": "member"}); code != 409 {
		t.Fatal("invite for an existing username")
	}
	if code, _ := admin.post("/api/invites", map[string]any{"username": "x y", "role": "member"}); code != 400 {
		t.Fatal("invalid username accepted")
	}
	if code, _ := admin.post("/api/invites", map[string]any{"username": "zed", "role": "owner"}); code != 400 {
		t.Fatal("invalid role accepted")
	}
	// A route can't list someone who doesn't exist.
	code, out := admin.post("/api/routes", map[string]any{"hostname": "z.example.com", "enabled": true,
		"config": map[string]any{"targets": []map[string]string{{"url": "http://127.0.0.1:9"}},
			"access": map[string]any{"mode": "private", "users": []int64{999}}}})
	if code != 400 || out["field"] != "access.users" {
		t.Fatalf("unknown user on access list: %d %v", code, out)
	}
}

func TestDeletedMemberLosesAccessImmediately(t *testing.T) {
	e := newEnv(t)
	admin := e.client()
	e.setup(admin)
	b := identityBackend(t)
	photos := e.privateRoute(admin, "photos.example.com", b.URL, nil)
	sam, _, cookie := e.join(admin, "sam", []int64{photos}, "photos.example.com")
	if code, _ := admin.req("DELETE", fmt.Sprintf("/api/people/%d", sam), nil, nil); code != 200 {
		t.Fatal("delete failed")
	}
	if rec := e.site("GET", "photos.example.com", "/", cookie, nil, "198.51.100.1:1"); rec.Code != http.StatusFound {
		t.Fatalf("deleted user still in: %d", rec.Code)
	}
	r, _ := e.srv.Store.GetRoute(t.Context(), photos)
	if len(r.Config.Access.Users) != 0 {
		t.Fatalf("deleted user left on access list: %v", r.Config.Access.Users)
	}
}
