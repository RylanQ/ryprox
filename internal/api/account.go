// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/rylanq/ryprox/internal/auth"
	"github.com/rylanq/ryprox/internal/store"
)

const totpPurpose = "totp-secret"

// --- first-run setup -------------------------------------------------------

func (s *Server) checkSetupCode(w http.ResponseWriter, r *http.Request, code string) bool {
	ip := clientIP(r)
	if ok, wait := s.ipLimit.Check("setup:" + ip); !ok {
		writeError(w, http.StatusTooManyRequests, fmt.Sprintf("too many attempts; try again in %s", wait.Round(time.Second)))
		return false
	}
	s.mu.Lock()
	want := s.setupHash
	s.mu.Unlock()
	if want == nil {
		writeError(w, http.StatusConflict, "RyProx is already set up")
		return false
	}
	if subtle.ConstantTimeCompare(auth.HashToken(normalizeSetupCode(code)), want) != 1 {
		s.ipLimit.Fail("setup:" + ip)
		writeJSON(w, http.StatusForbidden, apiError{Error: "that setup code isn't right; find it in the RyProx logs", Field: "setupCode"})
		return false
	}
	return true
}

func (s *Server) handleSetupBegin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		SetupCode string `json:"setupCode"`
		Username  string `json:"username"`
	}
	if !readJSON(w, r, &in) || !s.checkSetupCode(w, r, in.SetupCode) {
		return
	}
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		s.writeErr(w, err)
		return
	}
	account := strings.TrimSpace(in.Username)
	if account == "" {
		account = "admin"
	}
	uri := auth.TOTPURI("RyProx", account, secret)
	png, err := qrcode.Encode(uri, qrcode.Medium, 256)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"totpSecret": secret,
		"totpURI":    uri,
		"qr":         "data:image/png;base64," + base64.StdEncoding.EncodeToString(png),
	})
}

func validUsername(u string) error {
	if len(u) < 3 || len(u) > 64 {
		return errors.New("username must be 3 to 64 characters")
	}
	for _, c := range u {
		if !(unicode.IsLetter(c) || unicode.IsDigit(c) || c == '.' || c == '_' || c == '-') {
			return errors.New("username can only contain letters, numbers, dots, dashes and underscores")
		}
	}
	return nil
}

func (s *Server) handleSetupFinish(w http.ResponseWriter, r *http.Request) {
	var in struct {
		SetupCode  string `json:"setupCode"`
		Username   string `json:"username"`
		Password   string `json:"password"`
		TOTPSecret string `json:"totpSecret"`
		TOTPCode   string `json:"totpCode"`
	}
	if !readJSON(w, r, &in) || !s.checkSetupCode(w, r, in.SetupCode) {
		return
	}
	in.Username = strings.TrimSpace(in.Username)
	if err := validUsername(in.Username); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error(), Field: "username"})
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
	u := &store.User{Username: in.Username, PasswordHash: hash, TOTPSecret: sealed, RecoveryCodes: hashes}
	if err := s.Store.CreateFirstUser(r.Context(), u); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "RyProx is already set up")
			return
		}
		s.writeErr(w, err)
		return
	}
	_, _ = s.Store.ClaimTOTPCounter(r.Context(), u.ID, counter)

	// The setup code is single-use.
	s.mu.Lock()
	s.setupHash = nil
	s.mu.Unlock()

	if err := s.startSession(w, r, u.ID); err != nil {
		s.writeErr(w, err)
		return
	}
	s.audit(r, u.Username, "setup.complete", "admin account created")
	writeJSON(w, http.StatusOK, map[string]any{"recoveryCodes": codes})
}

// --- login -------------------------------------------------------------

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	ip := clientIP(r)
	userKey := "user:" + strings.ToLower(strings.TrimSpace(in.Username))
	ipKey := "ip:" + ip
	if ok, wait := s.limiter.Check(userKey); !ok {
		writeError(w, http.StatusTooManyRequests, fmt.Sprintf("too many failed attempts; try again in %s", wait.Round(time.Second)))
		return
	}
	if ok, wait := s.ipLimit.Check(ipKey); !ok {
		writeError(w, http.StatusTooManyRequests, fmt.Sprintf("too many failed attempts; try again in %s", wait.Round(time.Second)))
		return
	}

	fail := func() {
		s.limiter.Fail(userKey)
		s.ipLimit.Fail(ipKey)
		s.Log.Warn("failed login", "username", in.Username, "ip", ip)
		// Same message whether the username or password was wrong.
		writeError(w, http.StatusUnauthorized, "wrong username or password")
	}

	u, err := s.Store.GetUserByUsername(r.Context(), strings.TrimSpace(in.Username))
	if errors.Is(err, store.ErrNotFound) {
		auth.VerifyDummy(r.Context(), in.Password)
		fail()
		return
	} else if err != nil {
		s.writeErr(w, err)
		return
	}
	ok, err := auth.VerifyPassword(r.Context(), in.Password, u.PasswordHash)
	if errors.Is(err, auth.ErrBusy) {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	if err != nil || !ok {
		fail()
		return
	}

	token, err := auth.NewToken()
	if err != nil {
		s.writeErr(w, err)
		return
	}
	s.mu.Lock()
	s.pending[string(auth.HashToken(token))] = pendingLogin{userID: u.ID, ip: ip, expires: time.Now().Add(pendingLoginTTL)}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"needCode": true, "loginToken": token})
}

func (s *Server) handleLoginVerify(w http.ResponseWriter, r *http.Request) {
	var in struct {
		LoginToken string `json:"loginToken"`
		Code       string `json:"code"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	key := string(auth.HashToken(in.LoginToken))
	s.mu.Lock()
	p, ok := s.pending[key]
	s.mu.Unlock()
	if !ok || time.Now().After(p.expires) || p.ip != clientIP(r) {
		writeError(w, http.StatusUnauthorized, "your login expired; please enter your password again")
		return
	}
	userKey := fmt.Sprintf("code:%d", p.userID)
	if ok, wait := s.limiter.Check(userKey); !ok {
		writeError(w, http.StatusTooManyRequests, fmt.Sprintf("too many wrong codes; try again in %s", wait.Round(time.Second)))
		return
	}
	u, err := s.Store.GetUser(r.Context(), p.userID)
	if err != nil {
		s.writeErr(w, err)
		return
	}

	valid, method := false, "authenticator code"
	if auth.LooksLikeRecoveryCode(in.Code) {
		method = "recovery code"
		valid, err = s.Store.ConsumeRecoveryCode(r.Context(), u.ID, auth.HashRecoveryCode(in.Code))
		if err != nil {
			s.writeErr(w, err)
			return
		}
	} else {
		secret, err := s.Box.Open(u.TOTPSecret, totpPurpose)
		if err != nil {
			s.writeErr(w, err)
			return
		}
		if counter, ok := auth.ValidateTOTP(secret, in.Code, time.Now()); ok {
			// Refuse a code that has already been used (replay).
			valid, err = s.Store.ClaimTOTPCounter(r.Context(), u.ID, counter)
			if err != nil {
				s.writeErr(w, err)
				return
			}
		}
	}
	if !valid {
		s.limiter.Fail(userKey)
		s.Log.Warn("wrong two-factor code", "username", u.Username, "ip", clientIP(r))
		writeJSON(w, http.StatusUnauthorized, apiError{Error: "that code isn't right", Field: "code"})
		return
	}

	s.mu.Lock()
	delete(s.pending, key)
	s.mu.Unlock()
	s.limiter.Reset(userKey)
	s.limiter.Reset("user:" + strings.ToLower(u.Username))
	s.ipLimit.Reset("ip:" + clientIP(r))

	if err := s.startSession(w, r, u.ID); err != nil {
		s.writeErr(w, err)
		return
	}
	s.audit(r, u.Username, "login", "signed in with "+method)
	out := map[string]any{"ok": true}
	if method == "recovery code" {
		latest, _ := s.Store.GetUser(r.Context(), u.ID)
		if latest != nil {
			out["recoveryCodesLeft"] = len(latest.RecoveryCodes)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, u *store.User, sess *store.Session) {
	_ = s.Store.DeleteSession(r.Context(), u.ID, sess.ID)
	s.clearSessionCookie(w, r)
	s.audit(r, u.Username, "logout", "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// --- account -----------------------------------------------------------

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request, u *store.User, sess *store.Session) {
	var in struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	key := fmt.Sprintf("pw:%d", u.ID)
	if ok, wait := s.limiter.Check(key); !ok {
		writeError(w, http.StatusTooManyRequests, fmt.Sprintf("too many attempts; try again in %s", wait.Round(time.Second)))
		return
	}
	if ok, _ := auth.VerifyPassword(r.Context(), in.Current, u.PasswordHash); !ok {
		s.limiter.Fail(key)
		writeJSON(w, http.StatusBadRequest, apiError{Error: "current password is wrong", Field: "current"})
		return
	}
	if err := auth.CheckPasswordPolicy(in.New); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error(), Field: "new"})
		return
	}
	hash, err := auth.HashPassword(r.Context(), in.New)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	if err := s.Store.UpdatePassword(r.Context(), u.ID, hash); err != nil {
		s.writeErr(w, err)
		return
	}
	// Sign out everywhere else: whoever knew the old password is now locked out.
	_ = s.Store.DeleteOtherSessions(r.Context(), u.ID, sess.ID)
	s.limiter.Reset(key)
	s.audit(r, u.Username, "account.password", "password changed; other sessions signed out")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request, u *store.User, sess *store.Session) {
	list, err := s.Store.ListSessions(r.Context(), u.ID)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	type out struct {
		ID        int64     `json:"id"`
		Current   bool      `json:"current"`
		CreatedAt time.Time `json:"createdAt"`
		LastSeen  time.Time `json:"lastSeen"`
		IP        string    `json:"ip"`
		UserAgent string    `json:"userAgent"`
	}
	res := []out{}
	for _, x := range list {
		res = append(res, out{x.ID, x.ID == sess.ID, x.CreatedAt, x.LastSeenAt, x.IP, x.UserAgent})
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleDeleteSession(w http.ResponseWriter, r *http.Request, u *store.User, _ *store.Session) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad id")
		return
	}
	if err := s.Store.DeleteSession(r.Context(), u.ID, id); err != nil {
		s.writeErr(w, err)
		return
	}
	s.audit(r, u.Username, "session.revoke", fmt.Sprintf("session %d", id))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleRevokeOthers(w http.ResponseWriter, r *http.Request, u *store.User, sess *store.Session) {
	if err := s.Store.DeleteOtherSessions(r.Context(), u.ID, sess.ID); err != nil {
		s.writeErr(w, err)
		return
	}
	s.audit(r, u.Username, "session.revoke_others", "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleNewRecoveryCodes(w http.ResponseWriter, r *http.Request, u *store.User, _ *store.Session) {
	var in struct {
		Password string `json:"password"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	key := fmt.Sprintf("pw:%d", u.ID)
	if ok, wait := s.limiter.Check(key); !ok {
		writeError(w, http.StatusTooManyRequests, fmt.Sprintf("too many attempts; try again in %s", wait.Round(time.Second)))
		return
	}
	if ok, _ := auth.VerifyPassword(r.Context(), in.Password, u.PasswordHash); !ok {
		s.limiter.Fail(key)
		writeJSON(w, http.StatusBadRequest, apiError{Error: "password is wrong", Field: "password"})
		return
	}
	codes, hashes, err := auth.NewRecoveryCodes(10)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	if err := s.Store.SetRecoveryCodes(r.Context(), u.ID, hashes); err != nil {
		s.writeErr(w, err)
		return
	}
	s.audit(r, u.Username, "account.recovery_codes", "new recovery codes generated")
	writeJSON(w, http.StatusOK, map[string]any{"recoveryCodes": codes})
}
