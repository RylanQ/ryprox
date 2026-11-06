// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/rylanq/ryprox/internal/auth"
	"github.com/rylanq/ryprox/internal/proxy"
	"github.com/rylanq/ryprox/internal/store"
)

// Passkeys sign people in with their device (fingerprint, face or PIN)
// instead of a password and authenticator code. They are phishing-proof:
// a passkey only works on the domain it was created on, so passkeys added
// on the dashboard and on the sign-in domain are separate.
//
// A passkey must verify the person (biometric or PIN), so it counts as both
// factors. Adding one needs the account password, so a stolen session
// can't quietly add a way back in.

const (
	passkeyTTL      = 5 * time.Minute
	maxPasskeys     = 20
	maxCeremonyBody = 64 << 10
)

type ceremony struct {
	data    webauthn.SessionData
	userID  int64 // 0 for sign-in, where the user isn't known yet
	realm   realm
	ip      string
	expires time.Time
}

// waUser adapts a store user to the WebAuthn library.
type waUser struct {
	u     *store.User
	creds []webauthn.Credential
}

func userHandle(id int64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(id)) //nolint:gosec // IDs are positive
	return b
}

func (w *waUser) WebAuthnID() []byte                         { return userHandle(w.u.ID) }
func (w *waUser) WebAuthnName() string                       { return w.u.Username }
func (w *waUser) WebAuthnDisplayName() string                { return w.u.Username }
func (w *waUser) WebAuthnCredentials() []webauthn.Credential { return w.creds }

func (s *Server) loadWAUser(r *http.Request, u *store.User) (*waUser, error) {
	keys, err := s.Store.ListPasskeys(r.Context(), u.ID)
	if err != nil {
		return nil, err
	}
	wu := &waUser{u: u}
	for _, k := range keys {
		var c webauthn.Credential
		if json.Unmarshal([]byte(k.Data), &c) == nil {
			wu.creds = append(wu.creds, c)
		}
	}
	return wu, nil
}

// relyingParty returns the WebAuthn configuration for the domain the
// request arrived on. The host has already been checked against RyProx's
// own domains (restrictHosts / portalRealm).
func (s *Server) relyingParty(r *http.Request) (*webauthn.WebAuthn, error) {
	host := proxy.NormalizeHost(r.Host)
	if net.ParseIP(host) != nil {
		return nil, errors.New("passkeys need a domain name; open the dashboard as http://localhost instead of an IP address")
	}
	scheme := "https"
	if r.TLS == nil {
		if !s.isLocal(r) {
			return nil, errors.New("passkeys need HTTPS")
		}
		scheme = "http" // browsers allow passkeys on http://localhost
	}
	return webauthn.New(&webauthn.Config{
		RPID:          host,
		RPDisplayName: "RyProx",
		RPOrigins:     []string{scheme + "://" + strings.ToLower(r.Host)},
	})
}

func (s *Server) putCeremony(key string, c ceremony) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ceremonies == nil {
		s.ceremonies = map[string]ceremony{}
	}
	now := time.Now()
	for k, v := range s.ceremonies {
		if now.After(v.expires) {
			delete(s.ceremonies, k)
		}
	}
	s.ceremonies[key] = c
}

// takeCeremony returns and removes a ceremony: each challenge is used once.
func (s *Server) takeCeremony(key string) (ceremony, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.ceremonies[key]
	delete(s.ceremonies, key)
	return c, ok && time.Now().Before(c.expires)
}

// --- adding a passkey (signed in) ----------------------------------------

func (s *Server) passkeyRegisterBegin(w http.ResponseWriter, r *http.Request, u *store.User, rl realm) {
	var in struct {
		Password string `json:"password"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	pwKey := fmt.Sprintf("pw:%d", u.ID)
	if ok, wait := s.limiter.Begin(pwKey); !ok {
		writeError(w, http.StatusTooManyRequests, fmt.Sprintf("too many attempts; try again in %s", wait.Round(time.Second)))
		return
	}
	if ok, err := auth.VerifyPassword(r.Context(), in.Password, u.PasswordHash); err != nil || !ok {
		writeJSON(w, http.StatusForbidden, apiError{Error: "that password isn't right", Field: "password"})
		return
	}
	s.limiter.Reset(pwKey)
	wa, err := s.relyingParty(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	wu, err := s.loadWAUser(r, u)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	if len(wu.creds) >= maxPasskeys {
		writeError(w, http.StatusBadRequest, "you have the most passkeys allowed; remove one first")
		return
	}
	var exclude []protocol.CredentialDescriptor
	for _, c := range wu.creds {
		exclude = append(exclude, c.Descriptor())
	}
	opts, data, err := wa.BeginRegistration(wu,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		}),
		webauthn.WithExclusions(exclude))
	if err != nil {
		s.writeErr(w, err)
		return
	}
	s.putCeremony(fmt.Sprintf("reg:%d:%s", u.ID, rl.host), ceremony{data: *data, userID: u.ID, realm: rl, ip: clientIP(r), expires: time.Now().Add(passkeyTTL)})
	writeJSON(w, http.StatusOK, opts)
}

func (s *Server) passkeyRegisterFinish(w http.ResponseWriter, r *http.Request, u *store.User, rl realm) {
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		name = "Passkey"
	}
	if utf8.RuneCountInString(name) > 60 || strings.ContainsAny(name, "\r\n\x00") {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "use a shorter name", Field: "name"})
		return
	}
	c, ok := s.takeCeremony(fmt.Sprintf("reg:%d:%s", u.ID, rl.host))
	if !ok || c.ip != clientIP(r) || c.realm != rl {
		writeError(w, http.StatusBadRequest, "that took too long; please try again")
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(io.LimitReader(r.Body, maxCeremonyBody))
	if err != nil {
		writeError(w, http.StatusBadRequest, "your device's response couldn't be read")
		return
	}
	wa, err := s.relyingParty(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	wu, err := s.loadWAUser(r, u)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	cred, err := wa.CreateCredential(wu, c.data, parsed)
	if err != nil {
		s.Log.Warn("passkey registration failed", "user", u.Username, "err", err)
		writeError(w, http.StatusBadRequest, "your device's passkey couldn't be verified")
		return
	}
	data, err := json.Marshal(cred)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	where := proxy.NormalizeHost(r.Host)
	pk := &store.Passkey{UserID: u.ID, Name: name + " · " + where, CredentialID: cred.ID, Data: string(data)}
	if err := s.Store.AddPasskey(r.Context(), pk); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "this passkey is already added")
			return
		}
		s.writeErr(w, err)
		return
	}
	s.audit(r, u.Username, "passkey.add", pk.Name)
	writeJSON(w, http.StatusOK, pk)
}

func (s *Server) listPasskeys(w http.ResponseWriter, r *http.Request, u *store.User) {
	keys, err := s.Store.ListPasskeys(r.Context(), u.ID)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"passkeys": keys})
}

func (s *Server) deletePasskey(w http.ResponseWriter, r *http.Request, u *store.User) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusNotFound, "passkey not found")
		return
	}
	if err := s.Store.DeletePasskey(r.Context(), u.ID, id); err != nil {
		s.writeErr(w, err)
		return
	}
	s.audit(r, u.Username, "passkey.remove", strconv.FormatInt(id, 10))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// --- signing in with a passkey -------------------------------------------

func (s *Server) passkeyLoginBegin(w http.ResponseWriter, r *http.Request, rl realm) {
	if ok, wait := s.ipLimit.Check("passkey:" + clientKey(r)); !ok {
		writeError(w, http.StatusTooManyRequests, fmt.Sprintf("too many attempts; try again in %s", wait.Round(time.Second)))
		return
	}
	wa, err := s.relyingParty(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	opts, data, err := wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		s.writeErr(w, err)
		return
	}
	id, err := auth.NewToken()
	if err != nil {
		s.writeErr(w, err)
		return
	}
	s.putCeremony("login:"+id, ceremony{data: *data, realm: rl, ip: clientIP(r), expires: time.Now().Add(passkeyTTL)})
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "options": opts})
}

func (s *Server) passkeyLoginFinish(w http.ResponseWriter, r *http.Request, rl realm, authorize func(*store.User) string) {
	id := r.URL.Query().Get("id")
	ipKey := "passkey:" + clientKey(r)
	if ok, wait := s.ipLimit.Begin(ipKey); !ok {
		writeError(w, http.StatusTooManyRequests, fmt.Sprintf("too many attempts; try again in %s", wait.Round(time.Second)))
		return
	}
	c, ok := s.takeCeremony("login:" + id)
	if id == "" || !ok || c.ip != clientIP(r) || c.realm != rl {
		writeError(w, http.StatusBadRequest, "that took too long; please try again")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxCeremonyBody))
	if err != nil {
		writeError(w, http.StatusBadRequest, "your device's response couldn't be read")
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(body))
	if err != nil {
		writeError(w, http.StatusBadRequest, "your device's response couldn't be read")
		return
	}
	wa, err := s.relyingParty(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var found *store.User
	handler := func(_, handle []byte) (webauthn.User, error) {
		if len(handle) != 8 {
			return nil, errors.New("unknown passkey")
		}
		uid := int64(binary.BigEndian.Uint64(handle)) //nolint:gosec // round-trips userHandle
		u, err := s.Store.GetUser(r.Context(), uid)
		if err != nil || u.Disabled {
			return nil, errors.New("unknown passkey")
		}
		found = u
		return s.loadWAUser(r, u)
	}
	cred, err := wa.ValidateDiscoverableLogin(handler, c.data, parsed)
	if err != nil || found == nil {
		s.Log.Warn("passkey sign-in failed", "ip", clientIP(r), "err", err)
		writeError(w, http.StatusUnauthorized, "that passkey wasn't accepted")
		return
	}
	if cred.Authenticator.CloneWarning {
		s.Log.Warn("passkey signature counter went backwards; possible cloned key", "user", found.Username)
		s.audit(r, found.Username, "passkey.clone_warning", "")
		writeError(w, http.StatusUnauthorized, "that passkey wasn't accepted")
		return
	}
	if data, err := json.Marshal(cred); err == nil {
		_ = s.Store.UpdatePasskeyData(r.Context(), found.ID, cred.ID, string(data))
	}
	s.ipLimit.Reset(ipKey)
	out, ok := s.finishLogin(w, r, found, rl, authorize, "a passkey")
	if ok {
		writeJSON(w, http.StatusOK, out)
	}
}
