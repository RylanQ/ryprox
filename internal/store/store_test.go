// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.Context(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestMigrationsAndReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r.db")
	s, err := Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	v, _ := s.SchemaVersion(t.Context())
	if v != len(migrations) {
		t.Fatalf("schema v%d, want v%d", v, len(migrations))
	}
	_ = s.Close()
	s2, err := Open(t.Context(), path) // reopening must not re-run migrations
	if err != nil {
		t.Fatal(err)
	}
	_ = s2.Close()
}

func TestOnlyOneFirstUser(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	// Many concurrent setup attempts: exactly one may succeed.
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			u := &User{Username: "admin" + string(rune('a'+i)), PasswordHash: "h", TOTPSecret: "s"}
			if err := s.CreateFirstUser(ctx, u); err == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			} else if !errors.Is(err, ErrConflict) {
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()
	if ok != 1 {
		t.Fatalf("%d users created, want exactly 1", ok)
	}
	if n, _ := s.CountUsers(ctx); n != 1 {
		t.Fatalf("count = %d", n)
	}
}

func TestUsernameCaseInsensitive(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	if err := s.CreateFirstUser(ctx, &User{Username: "Rylan", PasswordHash: "h", TOTPSecret: "s"}); err != nil {
		t.Fatal(err)
	}
	u, err := s.GetUserByUsername(ctx, "rYLAN")
	if err != nil || u.Username != "Rylan" {
		t.Fatalf("got %v, %v", u, err)
	}
	if _, err := s.GetUserByUsername(ctx, "nobody"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestTOTPCounterCannotBeReused(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	u := &User{Username: "a", PasswordHash: "h", TOTPSecret: "s"}
	if err := s.CreateFirstUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.ClaimTOTPCounter(ctx, u.ID, 100); !ok {
		t.Fatal("first use should succeed")
	}
	if ok, _ := s.ClaimTOTPCounter(ctx, u.ID, 100); ok {
		t.Fatal("same counter reused")
	}
	if ok, _ := s.ClaimTOTPCounter(ctx, u.ID, 99); ok {
		t.Fatal("older counter accepted")
	}
	if ok, _ := s.ClaimTOTPCounter(ctx, u.ID, 101); !ok {
		t.Fatal("newer counter rejected")
	}
}

func TestRecoveryCodesAreSingleUse(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	u := &User{Username: "a", PasswordHash: "h", TOTPSecret: "s", RecoveryCodes: []string{"x", "y"}}
	if err := s.CreateFirstUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.ConsumeRecoveryCode(ctx, u.ID, "x"); !ok {
		t.Fatal("valid code rejected")
	}
	if ok, _ := s.ConsumeRecoveryCode(ctx, u.ID, "x"); ok {
		t.Fatal("code used twice")
	}
	got, _ := s.GetUser(ctx, u.ID)
	if len(got.RecoveryCodes) != 1 || got.RecoveryCodes[0] != "y" {
		t.Fatalf("codes = %v", got.RecoveryCodes)
	}
}

func TestSessions(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	u := &User{Username: "a", PasswordHash: "h", TOTPSecret: "s"}
	_ = s.CreateFirstUser(ctx, u)
	n := time.Now()
	a := &Session{TokenHash: []byte("aaa"), UserID: u.ID, CreatedAt: n, LastSeenAt: n, ExpiresAt: n.Add(time.Hour)}
	b := &Session{TokenHash: []byte("bbb"), UserID: u.ID, CreatedAt: n, LastSeenAt: n, ExpiresAt: n.Add(-time.Second)}
	if err := s.CreateSession(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSession(ctx, b); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteExpiredSessions(ctx, n, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSessionByHash(ctx, []byte("bbb")); !errors.Is(err, ErrNotFound) {
		t.Fatal("expired session not removed")
	}
	got, err := s.GetSessionByHash(ctx, []byte("aaa"))
	if err != nil || got.UserID != u.ID {
		t.Fatalf("got %v, %v", got, err)
	}
	c := &Session{TokenHash: []byte("ccc"), UserID: u.ID, CreatedAt: n, LastSeenAt: n, ExpiresAt: n.Add(time.Hour)}
	_ = s.CreateSession(ctx, c)
	_ = s.DeleteOtherSessions(ctx, u.ID, c.ID)
	list, _ := s.ListSessions(ctx, u.ID)
	if len(list) != 1 || list[0].ID != c.ID {
		t.Fatalf("sessions = %v", list)
	}
}

func TestRouteCheckRollsBack(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	r := &Route{Hostname: "a.example.com", Enabled: true, Config: RouteConfig{Targets: []Target{{URL: "http://x"}}}}
	if _, err := s.CreateRoute(ctx, r, nil); err != nil {
		t.Fatal(err)
	}
	// A failing check must leave the database unchanged.
	bad := &Route{Hostname: "b.example.com", Enabled: true}
	_, err := s.CreateRoute(ctx, bad, func([]Route) error { return errors.New("nope") })
	if err == nil {
		t.Fatal("expected error")
	}
	list, _ := s.ListRoutes(ctx)
	if len(list) != 1 {
		t.Fatalf("rolled-back route was saved: %v", list)
	}
	// Duplicate hostname.
	dup := &Route{Hostname: "a.example.com"}
	if _, err := s.CreateRoute(ctx, dup, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("want ErrConflict, got %v", err)
	}
	// Update, toggle, delete.
	r.Config.HTTPSRedirect = true
	if _, err := s.UpdateRoute(ctx, r, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetRouteEnabled(ctx, r.ID, false, nil); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetRoute(ctx, r.ID)
	if got.Enabled || !got.Config.HTTPSRedirect {
		t.Fatalf("got %+v", got)
	}
	if _, err := s.DeleteRoute(ctx, r.ID, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteRoute(ctx, r.ID, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestSettingsAndAudit(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	st, _ := s.GetSettings(ctx)
	if st.TLSMode != TLSModeOff {
		t.Fatalf("default TLS mode = %q", st.TLSMode)
	}
	want := Settings{TLSMode: TLSModeACME, ACMEEmail: "a@b.c", ACMEStaging: true, AdminHostname: "admin.example.com"}
	if err := s.SaveSettings(ctx, want); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetSettings(ctx); got != want {
		t.Fatalf("got %+v", got)
	}
	_ = s.AddAudit(ctx, AuditEntry{Actor: "a", Action: "one"})
	_ = s.AddAudit(ctx, AuditEntry{Actor: "a", Action: "two"})
	list, _ := s.ListAudit(ctx, 10)
	if len(list) != 2 || list[0].Action != "two" {
		t.Fatalf("audit = %v", list)
	}
}
