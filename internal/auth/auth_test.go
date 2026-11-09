// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"strings"
	"testing"
	"time"
)

func TestPasswordHashAndVerify(t *testing.T) {
	ctx := t.Context()
	h, err := HashPassword(ctx, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=2,p=1$") {
		t.Fatalf("unexpected hash format: %s", h)
	}
	if ok, _ := VerifyPassword(ctx, "correct horse battery staple", h); !ok {
		t.Fatal("correct password rejected")
	}
	if ok, _ := VerifyPassword(ctx, "correct horse battery stapl", h); ok {
		t.Fatal("wrong password accepted")
	}
	h2, _ := HashPassword(ctx, "correct horse battery staple")
	if h == h2 {
		t.Fatal("hashes are not salted")
	}
	if _, err := VerifyPassword(ctx, "x", "$argon2id$v=19$m=999999999,t=2,p=1$AAAA$AAAA"); err == nil {
		t.Fatal("absurd parameters accepted")
	}
	if ok, _ := VerifyPassword(ctx, strings.Repeat("a", MaxPasswordLen+1), h); ok {
		t.Fatal("over-long password accepted")
	}
}

func TestPasswordPolicy(t *testing.T) {
	if CheckPasswordPolicy("short") == nil {
		t.Fatal("short password allowed")
	}
	if CheckPasswordPolicy(strings.Repeat("a", MaxPasswordLen+1)) == nil {
		t.Fatal("huge password allowed")
	}
	if err := CheckPasswordPolicy("twelve chars"); err != nil {
		t.Fatal(err)
	}
}

// RFC 6238 appendix B test vectors (SHA-1, 8 digits).
func TestTOTPRFCVectors(t *testing.T) {
	key := []byte("12345678901234567890")
	cases := map[int64]string{
		59:          "94287082",
		1111111109:  "07081804",
		1111111111:  "14050471",
		1234567890:  "89005924",
		2000000000:  "69279037",
		20000000000: "65353130",
	}
	for ts, want := range cases {
		if got := totpCode(key, uint64(ts/30), 8); got != want {
			t.Errorf("t=%d: got %s, want %s", ts, got, want)
		}
	}
}

func TestValidateTOTP(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	key, _ := decodeSecret(secret)
	now := time.Unix(1_800_000_000, 0)
	c := now.Unix() / 30

	for _, d := range []int64{-1, 0, 1} {
		code := totpCode(key, uint64(c+d), 6)
		got, ok := ValidateTOTP(secret, code, now)
		if !ok || got != c+d {
			t.Errorf("skew %d: ok=%v counter=%d", d, ok, got)
		}
	}
	if _, ok := ValidateTOTP(secret, totpCode(key, uint64(c+3), 6), now); ok {
		t.Error("code from 90s in the future accepted")
	}
	if _, ok := ValidateTOTP(secret, "12345", now); ok {
		t.Error("5-digit code accepted")
	}
	if _, ok := ValidateTOTP(secret, "abcdef", now); ok {
		t.Error("non-numeric code accepted")
	}
	if !strings.HasPrefix(TOTPURI("RyProx", "admin", secret), "otpauth://totp/RyProx:admin?") {
		t.Error("bad otpauth URI")
	}
}

func TestRecoveryCodes(t *testing.T) {
	codes, hashes, err := NewRecoveryCodes(10)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for i, c := range codes {
		if len(c) != 14 || !LooksLikeRecoveryCode(c) {
			t.Errorf("bad code %q", c)
		}
		if seen[c] {
			t.Errorf("duplicate code %q", c)
		}
		seen[c] = true
		// Users may type them in upper case or without dashes.
		if HashRecoveryCode(strings.ToUpper(strings.ReplaceAll(c, "-", ""))) != hashes[i] {
			t.Errorf("normalisation failed for %q", c)
		}
	}
	if LooksLikeRecoveryCode("123456") {
		t.Error("TOTP code mistaken for recovery code")
	}
}

func TestTokens(t *testing.T) {
	a, _ := NewToken()
	b, _ := NewToken()
	if a == b || len(a) < 40 {
		t.Fatalf("weak tokens: %q %q", a, b)
	}
	if string(HashToken(a)) == string(HashToken(b)) {
		t.Fatal("hash collision")
	}
}

func TestLimiter(t *testing.T) {
	l := NewLimiter()
	clock := time.Unix(0, 0)
	l.now = func() time.Time { return clock }

	for i := range 5 {
		if ok, _ := l.Check("k"); !ok {
			t.Fatalf("locked after %d failures", i)
		}
		l.Fail("k")
	}
	if ok, _ := l.Check("k"); !ok {
		t.Fatal("5 failures should still be allowed to try once more")
	}
	l.Fail("k") // 6th failure → 30s lock
	if ok, wait := l.Check("k"); ok || wait != 30*time.Second {
		t.Fatalf("ok=%v wait=%v", ok, wait)
	}
	clock = clock.Add(31 * time.Second)
	if ok, _ := l.Check("k"); !ok {
		t.Fatal("still locked after lock expired")
	}
	l.Fail("k") // 7th → 60s
	if _, wait := l.Check("k"); wait != 60*time.Second {
		t.Fatalf("wait = %v, want 60s", wait)
	}
	// Other keys are unaffected.
	if ok, _ := l.Check("other"); !ok {
		t.Fatal("unrelated key locked")
	}
	l.Reset("k")
	if ok, _ := l.Check("k"); !ok {
		t.Fatal("reset did not unlock")
	}
	// Failures are forgotten after a quiet hour.
	for range 6 {
		l.Fail("z")
	}
	clock = clock.Add(2 * time.Hour)
	if ok, _ := l.Check("z"); !ok {
		t.Fatal("old failures not forgotten")
	}
}

func TestLimiterBeginCountsEveryAttempt(t *testing.T) {
	l := NewLimiter()
	allowed := 0
	for range 50 {
		if ok, _ := l.Begin("k"); ok {
			allowed++
		}
	}
	if allowed != 6 {
		t.Fatalf("%d attempts allowed before lockout, want 6", allowed)
	}
	l.Reset("k")
	if ok, _ := l.Begin("k"); !ok {
		t.Fatal("reset did not unlock")
	}
}
