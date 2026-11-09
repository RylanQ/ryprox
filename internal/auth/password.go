// SPDX-License-Identifier: AGPL-3.0-only

// Package auth handles passwords, two-factor codes, recovery codes,
// session tokens and login rate limiting.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters. 64 MiB of memory makes offline guessing expensive.
const (
	argonTime    = 2
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 1
	argonKeyLen  = 32
	saltLen      = 16
)

// Password length limits. The maximum stops huge inputs being used to slow
// the server down.
const (
	MinPasswordLen = 12
	MaxPasswordLen = 256
)

// hashSlots limits how many password hashes run at once, so a flood of
// login attempts cannot exhaust the server's memory.
var hashSlots = make(chan struct{}, 4)

// ErrBusy is returned when the server is too busy to check a password.
var ErrBusy = errors.New("too many login attempts in progress, try again shortly")

// hashWait is how long a password check may wait for a free slot.
const hashWait = 5 * time.Second

func acquire(ctx context.Context) error {
	t := time.NewTimer(hashWait)
	defer t.Stop()
	select {
	case hashSlots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ErrBusy
	case <-t.C:
		return ErrBusy
	}
}

func release() { <-hashSlots }

// CheckPasswordPolicy returns a user-friendly error if pw is unacceptable.
func CheckPasswordPolicy(pw string) error {
	n := utf8.RuneCountInString(pw)
	switch {
	case n < MinPasswordLen:
		return fmt.Errorf("password must be at least %d characters", MinPasswordLen)
	case len(pw) > MaxPasswordLen:
		return fmt.Errorf("password must be at most %d bytes", MaxPasswordLen)
	}
	return nil
}

// HashPassword returns an encoded Argon2id hash of pw.
func HashPassword(ctx context.Context, pw string) (string, error) {
	if err := acquire(ctx); err != nil {
		return "", err
	}
	defer release()
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// VerifyPassword reports whether pw matches the encoded hash.
func VerifyPassword(ctx context.Context, pw, encoded string) (bool, error) {
	if len(pw) > MaxPasswordLen {
		return false, nil
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errors.New("unsupported password hash")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, errors.New("unsupported argon2 version")
	}
	var m uint32
	var t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false, err
	}
	// Refuse absurd parameters from a tampered hash.
	if m == 0 || m > 1<<20 || t == 0 || t > 16 || p == 0 {
		return false, errors.New("invalid argon2 parameters")
	}
	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return false, err
	}
	want, err := b64.DecodeString(parts[5])
	if err != nil {
		return false, err
	}
	if len(want) < 16 || len(want) > 64 {
		return false, errors.New("invalid hash length")
	}
	if err := acquire(ctx); err != nil {
		return false, err
	}
	defer release()
	got := argon2.IDKey([]byte(pw), salt, t, m, p, uint32(len(want))) //nolint:gosec // length checked above
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// dummyHash is checked when a username doesn't exist, so a failed login
// takes the same time whether or not the user exists.
var dummyHash = func() string {
	h, err := HashPassword(context.Background(), "not-a-real-password-just-for-timing")
	if err != nil {
		panic(err)
	}
	return h
}()

// VerifyDummy burns the same time as a real password check.
func VerifyDummy(ctx context.Context, pw string) {
	_, _ = VerifyPassword(ctx, pw, dummyHash)
}
