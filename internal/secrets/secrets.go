// SPDX-License-Identifier: AGPL-3.0-only

// Package secrets encrypts sensitive values (like two-factor secrets)
// before they are written to the database, using a key kept in a separate
// file. A copied database alone is then not enough to read them.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const keySize = 32 // AES-256
const prefix = "v1:"

// Box seals and opens values with AES-256-GCM.
type Box struct {
	aead cipher.AEAD
}

// LoadOrCreate reads the key file at path, creating it (mode 0600) if missing.
func LoadOrCreate(path string) (*Box, error) {
	key, err := os.ReadFile(path) //nolint:gosec // path is the operator's own data folder
	switch {
	case errors.Is(err, os.ErrNotExist):
		key = make([]byte, keySize)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // as above
		if err != nil {
			return nil, err
		}
		if _, err := f.Write(key); err != nil {
			_ = f.Close()
			return nil, err
		}
		if err := f.Close(); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, err
	}
	if len(key) != keySize {
		return nil, fmt.Errorf("secret key %s has wrong size (%d bytes)", path, len(key))
	}
	return New(key)
}

// New creates a Box from a 32-byte key.
func New(key []byte) (*Box, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

// Seal encrypts plaintext. purpose binds the ciphertext to its use, so a
// value sealed for one purpose cannot be swapped in for another.
func (b *Box) Seal(plaintext, purpose string) (string, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out := b.aead.Seal(nonce, nonce, []byte(plaintext), []byte(purpose))
	return prefix + base64.RawStdEncoding.EncodeToString(out), nil
}

// Open decrypts a value produced by Seal with the same purpose.
func (b *Box) Open(sealed, purpose string) (string, error) {
	if !strings.HasPrefix(sealed, prefix) {
		return "", errors.New("unknown secret format")
	}
	raw, err := base64.RawStdEncoding.DecodeString(sealed[len(prefix):])
	if err != nil {
		return "", err
	}
	n := b.aead.NonceSize()
	if len(raw) < n {
		return "", errors.New("secret too short")
	}
	pt, err := b.aead.Open(nil, raw[:n], raw[n:], []byte(purpose))
	if err != nil {
		return "", errors.New("cannot decrypt secret (wrong key file?)")
	}
	return string(pt), nil
}
