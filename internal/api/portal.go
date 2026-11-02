// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"encoding/base64"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/rylanq/ryprox/internal/auth"
	"github.com/rylanq/ryprox/internal/proxy"
	"github.com/rylanq/ryprox/internal/store"
	"github.com/rylanq/ryprox/internal/version"
)

// Sign-in for private routes happens only on RyProx's own sign-in domain,
// never on a route's domain. A route's backend shares its origin with
// anything served there, so it could fake a sign-in page or install a
// service worker over it; on a separate origin it can do neither.
//
//  1. A visitor without a session for photos.example.com is redirected to
//     https://<sign-in domain>/.ryprox/login?site=photos.example.com&rd=/path
//  2. They sign in there (or are already signed in there) and RyProx issues
//     a one-time code for that site, bound to their IP address.
//  3. The browser is sent to https://photos.example.com/.ryprox/callback,
//     where RyProx redeems the code and sets a session for that site only.

const (
	inviteTTL  = 7 * 24 * time.Hour // how long an invite link works
	handoffTTL = time.Minute        // how long a one-time sign-in code works
)

// Files the sign-in portal may serve, on the sign-in domain only.
var portalFiles = map[string]string{
	"portal.js":   "text/javascript; charset=utf-8",
	"app.css":     "text/css; charset=utf-8",
	"favicon.svg": "image/svg+xml",
}

type handoff struct {
	userID  int64
	host    string
	ip      string
	expires time.Time
}

// --- the gate (implements proxy.Gate) -----------------------------------

// siteURL returns the HTTPS address of host, with the HTTPS port if it isn't 443.
func (s *Server) siteURL(host string) string {
	if s.HTTPSPort != "" && s.HTTPSPort != "443" {
		return "https://" + net.JoinHostPort(host, s.HTTPSPort)
	}
	return "https://" + host
}

// signInURL returns the address of a sign-in page, or "" if no sign-in
// domain is configured.
func (s *Server) signInURL(page string, q url.Values) string {
	h := s.Settings().SignInHostname()
	if h == "" || !s.Certs.Enabled() {
		return ""
	}
	u := s.siteURL(h) + proxy.PortalPrefix + page
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	return u
}

// Authorize checks every request to a private site: a valid session for
// this exact site, an enabled account, and a place on the site's access list.
func (s *Server) Authorize(w http.ResponseWriter, r *http.Request, route *store.Route) (string, func() bool, bool) {
	rl := realm{route.Hostname}
	u, sess := s.sessionFor(r, rl)
	if u == nil || !route.Config.Access.Allows(u.ID) {
		page, title, msg, code := "login", "Sign-in needed", "This site is private. Open it in a browser to sign in.", http.StatusUnauthorized
		if u != nil {
			page, title, msg, code = "denied", "No access", "Your account hasn't been given access to this site.", http.StatusForbidden
		}
		if !wantsPage(r) {
			proxy.WritePage(w, code, title, msg)
			return "", nil, false
		}
		target := s.signInURL(page, url.Values{"site": {route.Hostname}, "rd": {safeRedirectPath(r.URL.RequestURI())}})
		if target == "" {
			proxy.WritePage(w, http.StatusServiceUnavailable, "Sign-in isn't set up",
				"This site is private, but RyProx doesn't have a sign-in domain yet. An admin can set one under Settings.")
			return "", nil, false
		}
		http.Redirect(w, r, target, http.StatusFound)
		return "", nil, false
	}

	// Re-checked periodically for long-lived requests.
	tokenHash, userID, host := sess.TokenHash, u.ID, route.Hostname
	stillAllowed := func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cur, err := s.Store.GetSessionByHash(ctx, tokenHash)
		if err != nil || cur.Host != host || time.Now().After(cur.ExpiresAt) {
			return false
		}
		usr, err := s.Store.GetUser(ctx, userID)
		if err != nil || usr.Disabled {
			return false
		}
		rt, ok := s.Engine.Route(host)
		return ok && (rt.Config.Access.IsPublic() || rt.Config.Access.Allows(userID))
	}
	return u.Username, stillAllowed, true
}

// wantsPage reports whether the request is a browser opening a page, as
// opposed to an API call or a WebSocket, which get a status code instead.
func wantsPage(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if r.Header.Get("Upgrade") != "" {
		return false
	}
	if m := r.Header.Get("Sec-Fetch-Mode"); m != "" {
		return m == "navigate"
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// safeRedirectPath returns rd if it is a path on the same site, else "/".
func safeRedirectPath(rd string) string {
	if rd == "" || len(rd) > 2048 || !strings.HasPrefix(rd, "/") || strings.ContainsAny(rd, "\\\r\n\t\x00") {
		return "/"
	}
	u, err := url.Parse(rd)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil {
		return "/"
	}
	clean := path.Clean("/" + strings.TrimLeft(u.Path, "/"))
	if strings.HasPrefix(clean, "//") || strings.HasPrefix(clean, proxy.PortalPrefix) || clean+"/" == proxy.PortalPrefix {
		return "/"
	}
	if strings.HasSuffix(u.Path, "/") && clean != "/" {
		clean += "/"
	}
	out := (&url.URL{Path: clean, RawQuery: u.RawQuery}).String()
	if !strings.HasPrefix(out, "/") || strings.HasPrefix(out, "//") {
		return "/"
	}
	return out
}

// Portal handles /.ryprox/ requests. On a route's domain only the sign-in
// callback and sign-out exist; everything else is served on the sign-in
// domain (or the local dashboard, for accepting invites).
func (s *Server) Portal(w http.ResponseWriter, r *http.Request, route *store.Route) {
	if route != nil {
		s.sitePortal(w, r, route)
		return
	}
	s.portalOnce.Do(func() { s.portal = s.buildPortal() })
	s.portal.ServeHTTP(w, r)
}

// SignInHandler serves the sign-in domain.
func (s *Server) SignInHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, proxy.PortalPrefix) {
			http.Redirect(w, r, proxy.PortalPrefix+"login", http.StatusFound)
			return
		}
		s.Portal(w, r, nil)
	})
}

// portalRealm is the realm portal requests sign in to: the sign-in domain,
// or nil-equivalent dashboard realm when used locally.
func (s *Server) portalRealm(r *http.Request) (realm, bool) {
	h := s.Settings().SignInHostname()
	if h != "" && r.TLS != nil && proxy.NormalizeHost(r.Host) == h {
		return realm{"signin:" + h}, true
	}
	return dashboard, false
}

func (s *Server) sitePortal(w http.ResponseWriter, r *http.Request, route *store.Route) {
	s.securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == proxy.PortalPrefix+"callback":
			s.handleCallback(w, r, route)
		case r.Method == http.MethodGet && r.URL.Path == proxy.PortalPrefix+"logout":
			rl := realm{route.Hostname}
			if u, sess := s.sessionFor(r, rl); u != nil {
				_ = s.Store.DeleteSession(r.Context(), u.ID, sess.ID)
			}
			s.clearSessionCookie(w, r, rl)
			if target := s.signInURL("logout", nil); target != "" {
				http.Redirect(w, r, target, http.StatusFound)
				return
			}
			proxy.WritePage(w, http.StatusOK, "Signed out", "You've been signed out of this site.")
		default:
			proxy.WritePage(w, http.StatusNotFound, "Not found", "This page doesn't exist.")
		}
	})).ServeHTTP(w, r)
}

// handleCallback redeems a one-time code and starts a session for one site.
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request, route *store.Route) {
	code := r.URL.Query().Get("code")
	rd := safeRedirectPath(r.URL.Query().Get("rd"))
	key := string(auth.HashToken(code))
	s.mu.Lock()
	h, ok := s.handoffs[key]
	delete(s.handoffs, key) // single use, whatever happens next
	s.mu.Unlock()
	if code == "" || !ok || time.Now().After(h.expires) || h.host != route.Hostname || h.ip != clientIP(r) {
		target := s.signInURL("login", url.Values{"site": {route.Hostname}, "rd": {rd}})
		if target == "" {
			proxy.WritePage(w, http.StatusBadRequest, "Sign-in failed", "This sign-in link isn't valid. Please try again.")
			return
		}
		http.Redirect(w, r, target, http.StatusFound)
		return
	}
	u, err := s.Store.GetUser(r.Context(), h.userID)
	if err != nil || u.Disabled || !route.Config.Access.Allows(u.ID) {
		proxy.WritePage(w, http.StatusForbidden, "No access", "Your account hasn't been given access to this site.")
		return
	}
	if err := s.startSession(w, r, u.ID, realm{route.Hostname}); err != nil {
		s.Log.Error("could not start session", "err", err)
		proxy.WritePage(w, http.StatusInternalServerError, "Sign-in failed", "Something went wrong. Please try again.")
		return
	}
	// rd came through safeRedirectPath: always a path on this site.
	http.Redirect(w, r, rd, http.StatusFound) //nolint:gosec // validated above
}

func (s *Server) buildPortal() http.Handler {
	mux := http.NewServeMux()
	p := proxy.PortalPrefix

	page := func(w http.ResponseWriter, r *http.Request) {
		b, err := fs.ReadFile(s.UI, "portal.html")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(b)
	}
	for _, name := range []string{"", "login", "denied", "logout", "invite"} {
		mux.HandleFunc("GET "+p+name, page)
	}
	mux.HandleFunc("GET "+p+"static/{file}", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("file")
		ct, ok := portalFiles[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		b, err := fs.ReadFile(s.UI, name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", ct)
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// The name is checked against a fixed list and the bytes come from files
		// built into the binary, so no visitor input is ever written here.
		_, _ = w.Write(b) //nolint:gosec // see above
	})

	mux.HandleFunc("GET "+p+"api/state", s.handlePortalState)
	mux.HandleFunc("POST "+p+"api/login", func(w http.ResponseWriter, r *http.Request) {
		rl, ok := s.portalRealm(r)
		if !ok {
			writeError(w, http.StatusNotFound, "sign in on the dashboard instead")
			return
		}
		s.loginPassword(w, r, rl)
	})
	mux.HandleFunc("POST "+p+"api/login/verify", func(w http.ResponseWriter, r *http.Request) {
		rl, ok := s.portalRealm(r)
		if !ok {
			writeError(w, http.StatusNotFound, "sign in on the dashboard instead")
			return
		}
		s.loginVerify(w, r, rl, func(*store.User) string { return "" })
	})
	mux.HandleFunc("POST "+p+"api/continue", s.handleContinue)
	mux.HandleFunc("POST "+p+"api/logout", func(w http.ResponseWriter, r *http.Request) {
		rl, ok := s.portalRealm(r)
		if !ok {
			writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
			return
		}
		if u, sess := s.sessionFor(r, rl); u != nil {
			_ = s.Store.DeleteSession(r.Context(), u.ID, sess.ID)
			s.audit(r, u.Username, "logout", "signed out of the sign-in page")
		}
		s.clearSessionCookie(w, r, rl)
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST "+p+"api/invite/begin", s.handleInviteBegin)
	mux.HandleFunc("POST "+p+"api/invite/finish", s.handleInviteFinish)
	mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })

	return s.securityHeaders(s.csrfProtect(s.requireSecurePost(mux)))
}

// allowedSites lists the enabled private routes userID may open.
func (s *Server) allowedSites(userID int64) []string {
	out := []string{}
	for _, h := range s.Engine.Hostnames() {
		if rt, ok := s.Engine.Route(h); ok && !rt.Config.Access.IsPublic() && rt.Config.Access.Allows(userID) {
			out = append(out, h)
		}
	}
	return out
}

func (s *Server) handlePortalState(w http.ResponseWriter, r *http.Request) {
	rl, onSignIn := s.portalRealm(r)
	out := map[string]any{
		"signInDomain": onSignIn,
		"secure":       r.TLS != nil || s.isLocal(r),
		"version":      version.Version,
	}
	if onSignIn {
		if u, _ := s.sessionFor(r, rl); u != nil {
			out["user"] = u.Username
			out["sites"] = s.allowedSites(u.ID)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// handleContinue issues a one-time code that signs the visitor in to one
// site, if they're signed in on the sign-in domain and allowed there.
func (s *Server) handleContinue(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Site string `json:"site"`
		RD   string `json:"rd"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	rl, ok := s.portalRealm(r)
	if !ok {
		writeError(w, http.StatusNotFound, "not available here")
		return
	}
	u, _ := s.sessionFor(r, rl)
	if u == nil {
		writeError(w, http.StatusUnauthorized, "please sign in")
		return
	}
	host := proxy.NormalizeHost(in.Site)
	rt, ok := s.Engine.Route(host)
	if !ok || rt.Config.Access.IsPublic() {
		writeError(w, http.StatusNotFound, "that site isn't a private site on this RyProx")
		return
	}
	if !rt.Config.Access.Allows(u.ID) {
		s.audit(r, u.Username, "access.denied", host)
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "your account hasn't been given access to " + host, "denied": true})
		return
	}
	code, err := auth.NewToken()
	if err != nil {
		s.writeErr(w, err)
		return
	}
	s.mu.Lock()
	s.handoffs[string(auth.HashToken(code))] = handoff{userID: u.ID, host: host, ip: clientIP(r), expires: time.Now().Add(handoffTTL)}
	s.mu.Unlock()
	q := url.Values{"code": {code}, "rd": {safeRedirectPath(in.RD)}}
	writeJSON(w, http.StatusOK, map[string]string{"url": s.siteURL(host) + proxy.PortalPrefix + "callback?" + q.Encode()})
}

// --- invites -------------------------------------------------------------

func (s *Server) lookupInvite(w http.ResponseWriter, r *http.Request, token string) *store.Invite {
	ip := clientKey(r)
	if ok, _ := s.ipLimit.Check("invite:" + ip); !ok {
		writeError(w, http.StatusTooManyRequests, "too many attempts; try again later")
		return nil
	}
	if token == "" || len(token) > 100 {
		writeError(w, http.StatusNotFound, "this invite link isn't valid")
		return nil
	}
	inv, err := s.Store.GetInviteByHash(r.Context(), auth.HashToken(token))
	if err != nil {
		s.ipLimit.Fail("invite:" + ip)
		writeError(w, http.StatusNotFound, "this invite link isn't valid, or has expired or been used; ask for a new one")
		return nil
	}
	return inv
}

func (s *Server) handleInviteBegin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token string `json:"token"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	inv := s.lookupInvite(w, r, in.Token)
	if inv == nil {
		return
	}
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		s.writeErr(w, err)
		return
	}
	uri := auth.TOTPURI("RyProx", inv.Username, secret)
	png, err := qrcode.Encode(uri, qrcode.Medium, 256)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"username":   inv.Username,
		"totpSecret": secret,
		"qr":         "data:image/png;base64," + base64.StdEncoding.EncodeToString(png),
	})
}

func (s *Server) handleInviteFinish(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token      string `json:"token"`
		Password   string `json:"password"`
		TOTPSecret string `json:"totpSecret"`
		TOTPCode   string `json:"totpCode"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if inv := s.lookupInvite(w, r, in.Token); inv == nil {
		return
	}
	if err := auth.CheckPasswordPolicy(in.Password); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error(), Field: "password"})
		return
	}
	counter, ok := auth.ValidateTOTP(in.TOTPSecret, in.TOTPCode, time.Now())
	if !ok {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "that code didn't match; check your phone's clock and try the newest code", Field: "totpCode"})
		return
	}
	hash, err := auth.HashPassword(r.Context(), in.Password)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	sealed, err := s.Box.Seal(in.TOTPSecret, totpPurpose)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	codes, hashes, err := s.newRecoveryCodes()
	if err != nil {
		s.writeErr(w, err)
		return
	}
	u := &store.User{PasswordHash: hash, TOTPSecret: sealed, RecoveryCodes: hashes}
	inv, err := s.Store.AcceptInvite(r.Context(), auth.HashToken(in.Token), u)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "this invite has already been used or has expired")
			return
		}
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "that username has been taken since the invite was sent; ask for a new invite")
			return
		}
		s.writeErr(w, err)
		return
	}
	_, _ = s.Store.ClaimTOTPCounter(r.Context(), u.ID, counter)
	s.grantAccess(r, u.ID, inv.Routes)
	s.audit(r, u.Username, "user.joined", "accepted an invite from "+inv.CreatedBy)

	// On the sign-in domain, sign them straight in there.
	signedIn := false
	if rl, ok := s.portalRealm(r); ok {
		signedIn = s.startSession(w, r, u.ID, rl) == nil
	}
	writeJSON(w, http.StatusOK, map[string]any{"recoveryCodes": codes, "signedIn": signedIn, "username": u.Username})
}

// grantAccess adds a user to the access lists of the given routes.
func (s *Server) grantAccess(r *http.Request, userID int64, routeIDs []int64) {
	for _, id := range routeIDs {
		rt, err := s.Store.GetRoute(r.Context(), id)
		if err != nil || rt.Config.Access.Allows(userID) {
			continue
		}
		rt.Config.Access.Users = append(rt.Config.Access.Users, userID)
		all, err := s.Store.UpdateRoute(r.Context(), rt, s.check)
		if err != nil {
			s.Log.Error("could not grant access", "route", rt.Hostname, "err", err)
			continue
		}
		s.apply(all, "")
	}
}
