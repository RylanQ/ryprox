// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"encoding/base64"
	"errors"
	"io/fs"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/rylanq/ryprox/internal/auth"
	"github.com/rylanq/ryprox/internal/proxy"
	"github.com/rylanq/ryprox/internal/store"
	"github.com/rylanq/ryprox/internal/version"
)

// How long an invite link works.
const inviteTTL = 7 * 24 * time.Hour

// Files the sign-in portal may serve. Nothing else from the dashboard is
// ever reachable on a site.
var portalFiles = map[string]string{
	"portal.js":   "text/javascript; charset=utf-8",
	"app.css":     "text/css; charset=utf-8",
	"favicon.svg": "image/svg+xml",
}

type ctxRoute struct{}

// --- the gate (implements proxy.Gate) -----------------------------------

// Authorize checks every request to a private site: a valid session for
// this exact site, an enabled account, and a place on the site's access list.
func (s *Server) Authorize(w http.ResponseWriter, r *http.Request, route *store.Route) (string, bool) {
	u, _ := s.sessionFor(r, realm{route.Hostname})
	if u == nil {
		if wantsPage(r) {
			http.Redirect(w, r, proxy.PortalPrefix+"login?rd="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
		} else {
			proxy.WritePage(w, http.StatusUnauthorized, "Sign-in needed", "This site is private. Open it in a browser to sign in.")
		}
		return "", false
	}
	if !route.Config.Access.Allows(u.ID) {
		if wantsPage(r) {
			http.Redirect(w, r, proxy.PortalPrefix+"denied", http.StatusFound)
		} else {
			proxy.WritePage(w, http.StatusForbidden, "No access", "Your account hasn't been given access to this site.")
		}
		return "", false
	}
	return u.Username, true
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

// Portal serves the sign-in pages under /.ryprox/ on a private site.
func (s *Server) Portal(w http.ResponseWriter, r *http.Request, route *store.Route) {
	s.portalOnce.Do(func() { s.portal = s.buildPortal() })
	ctx := context.WithValue(r.Context(), ctxRoute{}, route)
	s.portal.ServeHTTP(w, r.WithContext(ctx))
}

// portalRealm returns the site the portal request is for, or the dashboard
// realm when the portal is opened on the dashboard (for accepting invites).
func portalRealm(r *http.Request) (realm, *store.Route) {
	if rt, ok := r.Context().Value(ctxRoute{}).(*store.Route); ok && rt != nil {
		return realm{rt.Hostname}, rt
	}
	return dashboard, nil
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
		_, _ = w.Write(b)
	})

	mux.HandleFunc("GET "+p+"api/state", s.handlePortalState)
	mux.HandleFunc("POST "+p+"api/login", func(w http.ResponseWriter, r *http.Request) {
		rl, rt := portalRealm(r)
		if rt == nil {
			writeError(w, http.StatusNotFound, "sign in on the dashboard instead")
			return
		}
		s.loginPassword(w, r, rl)
	})
	mux.HandleFunc("POST "+p+"api/login/verify", func(w http.ResponseWriter, r *http.Request) {
		rl, rt := portalRealm(r)
		if rt == nil {
			writeError(w, http.StatusNotFound, "sign in on the dashboard instead")
			return
		}
		s.loginVerify(w, r, rl, func(u *store.User) string {
			if !rt.Config.Access.Allows(u.ID) {
				return "your account hasn't been given access to " + rt.Hostname + "; ask whoever runs it"
			}
			return ""
		})
	})
	mux.HandleFunc("POST "+p+"api/logout", func(w http.ResponseWriter, r *http.Request) {
		rl, _ := portalRealm(r)
		if u, sess := s.sessionFor(r, rl); u != nil {
			_ = s.Store.DeleteSession(r.Context(), u.ID, sess.ID)
			s.audit(r, u.Username, "logout", "signed out of "+rl.host)
		}
		s.clearSessionCookie(w, r, rl)
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST "+p+"api/invite/begin", s.handleInviteBegin)
	mux.HandleFunc("POST "+p+"api/invite/finish", s.handleInviteFinish)
	mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })

	return s.securityHeaders(s.csrfProtect(requireSecurePost(mux)))
}

// requireSecurePost refuses to accept passwords over plain HTTP, except
// from the server itself (local use or an SSH tunnel).
func requireSecurePost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.TLS == nil && !isLoopback(r) {
			writeError(w, http.StatusForbidden, "signing in needs HTTPS; turn on automatic HTTPS in RyProx's settings")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handlePortalState(w http.ResponseWriter, r *http.Request) {
	rl, rt := portalRealm(r)
	out := map[string]any{
		"site":    rl.host,
		"secure":  r.TLS != nil || isLoopback(r),
		"version": version.Version,
	}
	if rt != nil {
		if u, _ := s.sessionFor(r, rl); u != nil {
			out["user"] = u.Username
			out["allowed"] = rt.Config.Access.Allows(u.ID)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// --- invites -------------------------------------------------------------

func (s *Server) lookupInvite(w http.ResponseWriter, r *http.Request, token string) *store.Invite {
	ip := clientIP(r)
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
	codes, hashes, err := auth.NewRecoveryCodes(10)
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

	// Sign them straight in if they accepted the invite on a site they can open.
	rl, rt := portalRealm(r)
	signedIn := false
	if rt != nil && slices.Contains(inv.Routes, rt.ID) {
		if err := s.startSession(w, r, u.ID, rl); err == nil {
			signedIn = true
		}
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
