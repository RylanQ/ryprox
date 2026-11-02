// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

// NewToken returns a random 256-bit token, safe for URLs and cookies.
func NewToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashToken returns the SHA-256 of a token. Tokens are long and random, so
// a fast hash is safe here (unlike passwords).
func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// Recovery codes use letters and digits that are hard to confuse.
const recoveryAlphabet = "abcdefghjkmnpqrstuvwxyz23456789"

// NewRecoveryCodes returns n fresh codes (to show the user once) and their
// hashes (to store).
func NewRecoveryCodes(n int) (codes, hashes []string, err error) {
	for range n {
		b := make([]byte, 12)
		if _, err := rand.Read(b); err != nil {
			return nil, nil, err
		}
		var sb strings.Builder
		for i, x := range b {
			if i > 0 && i%4 == 0 {
				sb.WriteByte('-')
			}
			sb.WriteByte(recoveryAlphabet[int(x)%len(recoveryAlphabet)])
		}
		code := sb.String()
		codes = append(codes, code)
		hashes = append(hashes, HashRecoveryCode(code))
	}
	return codes, hashes, nil
}

// HashRecoveryCode normalises and hashes a recovery code.
func HashRecoveryCode(code string) string {
	norm := strings.ToLower(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(code)))
	sum := sha256.Sum256([]byte("ryprox-recovery:" + norm))
	return hex.EncodeToString(sum[:])
}

// LooksLikeRecoveryCode distinguishes a recovery code from a 6-digit TOTP code.
func LooksLikeRecoveryCode(s string) bool {
	return len(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(s))) == 12
}
