// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/rylanq/ryprox/internal/auth"
	"github.com/rylanq/ryprox/internal/proxy"
	"github.com/rylanq/ryprox/internal/store"
)

// Single sign-on with OpenID Connect providers (Google, Microsoft Entra,
// Authentik, Keycloak, ...). It is only offered on the sign-in domain.
//
// Zero trust still applies: a provider account never creates a RyProx
// account. It signs in the person whose email an admin has set, and only
// when the provider says the address is verified (or the admin marked the
// provider as trusted for emails, e.g. a company's own Microsoft tenant).
// The first sign-in pins the provider's account ID, so a later account
// with the same address can't take over.

const (
	ssoSettingKey = "sso_providers"
	ssoSecretPurp = "sso-client-secret" //nolint:gosec // a sealing purpose label, not a credential
	ssoStateTTL   = 10 * time.Minute
	ssoCookie     = "__Host-ryprox-sso"
)

// SSOProvider is one configured provider.
type SSOProvider struct {
	ID           string `json:"id"`   // short slug used in URLs
	Name         string `json:"name"` // button label, e.g. "Google"
	Issuer       string `json:"issuer"`
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret,omitempty"` // sealed when stored; never sent to the browser
	TrustEmail   bool   `json:"trustEmail"`             // accept emails without email_verified
	HasSecret    bool   `json:"hasSecret"`
}

type ssoState struct {
	provider string
	nonce    string
	verifier string
	cookie   string // hash of the browser-binding cookie
	ip       string
	realm    realm
	site, rd string
	expires  time.Time
}

var slugRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,30}$`)

func (s *Server) ssoProviders(ctx context.Context) ([]SSOProvider, error) {
	raw, err := s.Store.GetJSONSetting(ctx, ssoSettingKey)
	if err != nil || raw == "" {
		return []SSOProvider{}, err
	}
	var out []SSOProvider
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, err
	}
	return out, nil
}

// publicProviders strips secrets for the dashboard and sign-in page.
func publicProviders(ps []SSOProvider) []SSOProvider {
	out := make([]SSOProvider, len(ps))
	for i, p := range ps {
		p.HasSecret = p.ClientSecret != ""
		p.ClientSecret = ""
		out[i] = p
	}
	return out
}

func (s *Server) handleGetSSO(w http.ResponseWriter, r *http.Request, _ *store.User, _ *store.Session) {
	ps, err := s.ssoProviders(r.Context())
	if err != nil {
		s.writeErr(w, err)
		return
	}
	cb := ""
	if host := s.Settings().SignInHostname(); host != "" {
		cb = s.siteURL(host) + proxy.PortalPrefix + "sso/callback"
	}
	writeJSON(w, http.StatusOK, map[string]any{"providers": publicProviders(ps), "callbackUrl": cb})
}

func (s *Server) handlePutSSO(w http.ResponseWriter, r *http.Request, u *store.User, _ *store.Session) {
	var in struct {
		Providers []SSOProvider `json:"providers"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	old, err := s.ssoProviders(r.Context())
	if err != nil {
		s.writeErr(w, err)
		return
	}
	oldByID := map[string]SSOProvider{}
	for _, p := range old {
		oldByID[p.ID] = p
	}
	if len(in.Providers) > 10 {
		writeError(w, http.StatusBadRequest, "at most 10 providers")
		return
	}
	seen := map[string]bool{}
	for i := range in.Providers {
		p := &in.Providers[i]
		f := func(name string) string { return "providers." + strconv.Itoa(i) + "." + name }
		p.ID = strings.ToLower(strings.TrimSpace(p.ID))
		p.Name = strings.TrimSpace(p.Name)
		p.Issuer = strings.TrimSuffix(strings.TrimSpace(p.Issuer), "/")
		p.ClientID = strings.TrimSpace(p.ClientID)
		if !slugRE.MatchString(p.ID) || seen[p.ID] {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "use a short unique ID of lowercase letters, numbers and dashes", Field: f("id")})
			return
		}
		seen[p.ID] = true
		if p.Name == "" || len(p.Name) > 40 {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "enter a name for the button, like Google", Field: f("name")})
			return
		}
		iu, err := url.Parse(p.Issuer)
		if err != nil || iu.Scheme != "https" || iu.Host == "" || iu.User != nil || iu.RawQuery != "" || iu.Fragment != "" {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "enter the provider's issuer address, starting with https://", Field: f("issuer")})
			return
		}
		if p.ClientID == "" || len(p.ClientID) > 300 {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "enter the client ID from the provider", Field: f("clientId")})
			return
		}
		switch {
		case p.ClientSecret != "":
			if len(p.ClientSecret) > 500 {
				writeJSON(w, http.StatusBadRequest, apiError{Error: "client secret is too long", Field: f("clientSecret")})
				return
			}
			sealed, err := s.Box.Seal(p.ClientSecret, ssoSecretPurp)
			if err != nil {
				s.writeErr(w, err)
				return
			}
			p.ClientSecret = sealed
		case oldByID[p.ID].ClientSecret != "" && oldByID[p.ID].Issuer == p.Issuer:
			p.ClientSecret = oldByID[p.ID].ClientSecret // unchanged
		default:
			writeJSON(w, http.StatusBadRequest, apiError{Error: "enter the client secret from the provider", Field: f("clientSecret")})
			return
		}
		p.HasSecret = false
	}
	b, err := json.Marshal(in.Providers) //nolint:gosec // client secrets are sealed above before saving
	if err != nil {
		s.writeErr(w, err)
		return
	}
	if err := s.Store.SetJSONSetting(r.Context(), ssoSettingKey, string(b)); err != nil {
		s.writeErr(w, err)
		return
	}
	s.ssoCache.Range(func(k, _ any) bool { s.ssoCache.Delete(k); return true })
	names := []string{}
	for _, p := range in.Providers {
		names = append(names, p.Name)
	}
	s.audit(r, u.Username, "settings.sso", strings.Join(names, ", "))
	writeJSON(w, http.StatusOK, map[string]any{"providers": publicProviders(in.Providers)})
}

type ssoClient struct {
	cfg      oauth2.Config
	verifier *oidc.IDTokenVerifier
}

// ssoClientFor discovers a provider (cached) and returns its OAuth client.
func (s *Server) ssoClientFor(_ context.Context, p SSOProvider, redirectURL string) (*ssoClient, error) {
	key := p.ID + "|" + p.Issuer + "|" + redirectURL
	if c, ok := s.ssoCache.Load(key); ok {
		return c.(*ssoClient), nil
	}
	secret, err := s.Box.Open(p.ClientSecret, ssoSecretPurp)
	if err != nil {
		return nil, err
	}
	// The provider keeps this context to fetch signing keys later, so it
	// must not be cancelled; the HTTP client's timeout bounds each request.
	prov, err := oidc.NewProvider(s.ssoContext(), p.Issuer)
	if err != nil {
		return nil, err
	}
	c := &ssoClient{
		cfg: oauth2.Config{ClientID: p.ClientID, ClientSecret: secret, Endpoint: prov.Endpoint(),
			RedirectURL: redirectURL, Scopes: []string{oidc.ScopeOpenID, "email", "profile"}},
		verifier: prov.Verifier(&oidc.Config{ClientID: p.ClientID}),
	}
	s.ssoCache.Store(key, c)
	return c, nil
}

// ssoContext carries the HTTP client used to talk to providers.
func (s *Server) ssoContext() context.Context {
	client := s.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	ctx := oidc.ClientContext(context.Background(), client)
	return context.WithValue(ctx, oauth2.HTTPClient, client)
}

func hashHex(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}

// handleSSOStart sends the visitor to the provider.
func (s *Server) handleSSOStart(w http.ResponseWriter, r *http.Request) {
	rl, ok := s.portalRealm(r)
	if !ok {
		proxy.WritePage(w, http.StatusNotFound, "Not found", "Single sign-on is only available on the sign-in page.")
		return
	}
	if ok, _ := s.ipLimit.Check("sso:" + clientKey(r)); !ok {
		proxy.WritePage(w, http.StatusTooManyRequests, "Too many attempts", "Please wait a while and try again.")
		return
	}
	ps, err := s.ssoProviders(r.Context())
	if err != nil {
		s.writeErr(w, err)
		return
	}
	var p *SSOProvider
	for i := range ps {
		if ps[i].ID == r.PathValue("id") {
			p = &ps[i]
		}
	}
	if p == nil {
		proxy.WritePage(w, http.StatusNotFound, "Not found", "That sign-in option isn't set up.")
		return
	}
	cb := s.siteURL(s.Settings().SignInHostname()) + proxy.PortalPrefix + "sso/callback"
	c, err := s.ssoClientFor(r.Context(), *p, cb)
	if err != nil {
		s.Log.Warn("sso discovery failed", "provider", p.ID, "err", err)
		proxy.WritePage(w, http.StatusBadGateway, "Sign-in provider unavailable", "RyProx couldn't reach "+p.Name+". Please try again later.")
		return
	}
	state, err1 := auth.NewToken()
	nonce, err2 := auth.NewToken()
	bind, err3 := auth.NewToken()
	if err := errors.Join(err1, err2, err3); err != nil {
		s.writeErr(w, err)
		return
	}
	verifier := oauth2.GenerateVerifier()
	q := r.URL.Query()
	s.mu.Lock()
	if s.ssoStates == nil {
		s.ssoStates = map[string]ssoState{}
	}
	for k, v := range s.ssoStates {
		if time.Now().After(v.expires) {
			delete(s.ssoStates, k)
		}
	}
	if len(s.ssoStates) > 10000 {
		s.mu.Unlock()
		proxy.WritePage(w, http.StatusServiceUnavailable, "Busy", "Too many sign-ins in progress. Please try again shortly.")
		return
	}
	s.ssoStates[hashHex(state)] = ssoState{provider: p.ID, nonce: nonce, verifier: verifier, cookie: hashHex(bind), ip: clientIP(r),
		realm: rl, site: proxy.NormalizeHost(q.Get("site")), rd: safeRedirectPath(q.Get("rd")), expires: time.Now().Add(ssoStateTTL)}
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: ssoCookie, Value: bind, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: int(ssoStateTTL.Seconds())})
	http.Redirect(w, r, c.cfg.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}

// handleSSOCallback finishes sign-in when the provider sends the visitor back.
func (s *Server) handleSSOCallback(w http.ResponseWriter, r *http.Request) {
	fail := func(msg string) {
		proxy.WritePage(w, http.StatusUnauthorized, "Sign-in failed", msg)
	}
	rl, ok := s.portalRealm(r)
	if !ok {
		proxy.WritePage(w, http.StatusNotFound, "Not found", "Single sign-on is only available on the sign-in page.")
		return
	}
	ipKey := "sso:" + clientKey(r)
	if ok, _ := s.ipLimit.Begin(ipKey); !ok {
		proxy.WritePage(w, http.StatusTooManyRequests, "Too many attempts", "Please wait a while and try again.")
		return
	}
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		fail("The sign-in provider didn't sign you in. You can try again or use your password.")
		return
	}
	key := hashHex(q.Get("state"))
	s.mu.Lock()
	st, found := s.ssoStates[key]
	delete(s.ssoStates, key)
	s.mu.Unlock()
	ck, _ := r.Cookie(ssoCookie)
	http.SetCookie(w, &http.Cookie{Name: ssoCookie, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	if !found || time.Now().After(st.expires) || st.realm != rl || st.ip != clientIP(r) || ck == nil ||
		subtle.ConstantTimeCompare([]byte(hashHex(ck.Value)), []byte(st.cookie)) != 1 {
		fail("This sign-in link expired or was opened in a different browser. Please start again.")
		return
	}
	ps, err := s.ssoProviders(r.Context())
	if err != nil {
		s.writeErr(w, err)
		return
	}
	var p *SSOProvider
	for i := range ps {
		if ps[i].ID == st.provider {
			p = &ps[i]
		}
	}
	if p == nil {
		fail("That sign-in option was removed.")
		return
	}
	c, err := s.ssoClientFor(r.Context(), *p, s.siteURL(s.Settings().SignInHostname())+proxy.PortalPrefix+"sso/callback")
	if err != nil {
		fail("RyProx couldn't reach " + p.Name + ". Please try again later.")
		return
	}
	ctx, cancel := context.WithTimeout(s.ssoContext(), 15*time.Second)
	defer cancel()
	tok, err := c.cfg.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(st.verifier))
	if err != nil {
		s.Log.Warn("sso code exchange failed", "provider", p.ID, "err", err)
		fail("The sign-in provider didn't confirm who you are. Please try again.")
		return
	}
	rawID, _ := tok.Extra("id_token").(string)
	idt, err := c.verifier.Verify(ctx, rawID)
	if err != nil || subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(st.nonce)) != 1 {
		s.Log.Warn("sso id token rejected", "provider", p.ID, "err", err)
		fail("The sign-in provider's answer couldn't be verified.")
		return
	}
	var claims struct {
		Email         string `json:"email"`
		EmailVerified *bool  `json:"email_verified"`
	}
	if err := idt.Claims(&claims); err != nil {
		fail("The sign-in provider's answer couldn't be read.")
		return
	}
	u, err := s.ssoMatchUser(r.Context(), *p, idt.Subject, claims.Email, claims.EmailVerified)
	if err != nil || u == nil {
		s.audit(r, claims.Email, "login.sso_rejected", p.Name)
		fail("No RyProx account is linked to this " + p.Name + " account. Ask whoever runs this RyProx to add your email address.")
		return
	}
	s.ipLimit.Reset(ipKey)
	if _, ok := s.finishLogin(newDiscard(w), r, u, rl, anyone, p.Name); !ok {
		fail("You couldn't be signed in.")
		return
	}
	next := proxy.PortalPrefix + "login"
	if st.site != "" {
		next += "?" + url.Values{"site": {st.site}, "rd": {st.rd}}.Encode()
	}
	http.Redirect(w, r, next, http.StatusFound)
}

// ssoMatchUser finds the RyProx account for a provider account.
func (s *Server) ssoMatchUser(ctx context.Context, p SSOProvider, subject, email string, verified *bool) (*store.User, error) {
	if subject == "" {
		return nil, errors.New("no subject")
	}
	if id, err := s.Store.GetIdentity(ctx, p.ID, subject); err == nil {
		u, err := s.Store.GetUser(ctx, id.UserID)
		if err != nil || u.Disabled || !strings.EqualFold(u.Email, id.Email) {
			return nil, errors.New("linked account unavailable")
		}
		return u, nil
	}
	trusted := p.TrustEmail || (verified != nil && *verified)
	if email == "" || !trusted {
		return nil, errors.New("email not verified")
	}
	u, err := s.Store.GetUserByEmail(ctx, email)
	if err != nil || u.Disabled {
		return nil, errors.New("no account")
	}
	// One provider account per person per provider: a second, different
	// account with the same email can't link.
	if has, err := s.Store.HasIdentity(ctx, u.ID, p.ID); err != nil || has {
		return nil, errors.New("already linked to another account")
	}
	if err := s.Store.LinkIdentity(ctx, store.Identity{UserID: u.ID, Provider: p.ID, Subject: subject, Email: u.Email}); err != nil {
		return nil, err
	}
	return u, nil
}

// discardWriter keeps headers (the session cookie) but drops the JSON body
// finishLogin would write, since SSO answers with a redirect instead.
type discardWriter struct{ w http.ResponseWriter }

func newDiscard(w http.ResponseWriter) http.ResponseWriter { return discardWriter{w} }
func (d discardWriter) Header() http.Header                { return d.w.Header() }
func (d discardWriter) Write(b []byte) (int, error)        { return len(b), nil }
func (d discardWriter) WriteHeader(int)                    {}
