// SPDX-License-Identifier: AGPL-3.0-only

package secrets

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRoundTripAndKeyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "secret.key")
	b, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode = %v, want 0600", info.Mode().Perm())
	}

	sealed, err := b.Seal("hello", "totp")
	if err != nil {
		t.Fatal(err)
	}
	// Loading again must give the same key.
	b2, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := b2.Open(sealed, "totp")
	if err != nil || got != "hello" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := b2.Open(sealed, "other"); err == nil {
		t.Fatal("opened with wrong purpose")
	}
	again, _ := b.Seal("hello", "totp")
	if again == sealed {
		t.Fatal("sealing is not randomised")
	}
}

func TestWrongKeyFails(t *testing.T) {
	a, _ := New(make([]byte, 32))
	k := make([]byte, 32)
	k[0] = 1
	b, _ := New(k)
	s, _ := a.Seal("x", "p")
	if _, err := b.Open(s, "p"); err == nil {
		t.Fatal("opened with wrong key")
	}
	if _, err := a.Open("garbage", "p"); err == nil {
		t.Fatal("opened garbage")
	}
}

func TestMAC(t *testing.T) {
	a, _ := New(make([]byte, 32))
	k := make([]byte, 32)
	k[0] = 1
	b, _ := New(k)
	if a2, _ := New(make([]byte, 32)); a.MAC("p", "x") != a2.MAC("p", "x") {
		t.Fatal("MAC not deterministic")
	}
	if a.MAC("p", "x") == b.MAC("p", "x") || a.MAC("p", "x") == a.MAC("q", "x") {
		t.Fatal("MAC ignores key or purpose")
	}
}
