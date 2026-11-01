// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // TOTP (RFC 6238) uses HMAC-SHA1; every authenticator app expects it.
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP settings, matching what authenticator apps (Google Authenticator,
// 1Password, Aegis, etc.) use by default.
const (
	totpPeriod = 30
	totpDigits = 6
	// Accept codes from one period before or after, to allow for clock drift.
	totpSkew = 1
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a random 160-bit secret, base32-encoded.
func NewTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return b32.EncodeToString(b), nil
}

// totpCode computes the code for a counter value (RFC 4226 HOTP).
func totpCode(key []byte, counter uint64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for range digits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, v%mod)
}

func decodeSecret(secret string) ([]byte, error) {
	return b32.DecodeString(strings.ToUpper(strings.TrimRight(strings.ReplaceAll(secret, " ", ""), "=")))
}

// ValidateTOTP checks code against secret at time t. On success it returns
// the counter that matched, which the caller must record so the same code
// cannot be used twice.
func ValidateTOTP(secret, code string, t time.Time) (counter int64, ok bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != totpDigits {
		return 0, false
	}
	key, err := decodeSecret(secret)
	if err != nil {
		return 0, false
	}
	now := t.Unix() / totpPeriod
	for d := -totpSkew; d <= totpSkew; d++ {
		c := now + int64(d)
		if c < 0 {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(totpCode(key, uint64(c), totpDigits)), []byte(code)) == 1 {
			return c, true
		}
	}
	return 0, false
}

// TOTPURI returns the otpauth:// link that authenticator apps scan.
func TOTPURI(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(totpDigits))
	q.Set("period", fmt.Sprint(totpPeriod))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// TOTPCodeAt returns the current code for secret at time t. Used by tests
// and by the setup screen's self-check.
func TOTPCodeAt(secret string, t time.Time) (string, error) {
	key, err := decodeSecret(secret)
	if err != nil {
		return "", err
	}
	return totpCode(key, uint64(t.Unix()/totpPeriod), totpDigits), nil
}
