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
	if n, _ := s.CountAdmins(ctx); n != 1 {
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

func TestInvitesAreSingleUse(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	admin := &User{Username: "admin", PasswordHash: "h", TOTPSecret: "s"}
	_ = s.CreateFirstUser(ctx, admin)

	inv := &Invite{TokenHash: []byte("tok"), Username: "Sam", Role: RoleMember, CreatedBy: "admin",
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}
	if err := s.CreateInvite(ctx, inv); err != nil {
		t.Fatal(err)
	}
	// Can't invite a name that's already a user.
	if err := s.CreateInvite(ctx, &Invite{TokenHash: []byte("x"), Username: "ADMIN", Role: RoleMember,
		ExpiresAt: time.Now().Add(time.Hour)}); !errors.Is(err, ErrConflict) {
		t.Fatalf("want ErrConflict, got %v", err)
	}
	u := &User{PasswordHash: "h", TOTPSecret: "s"}
	if _, err := s.AcceptInvite(ctx, []byte("tok"), u); err != nil {
		t.Fatal(err)
	}
	if u.Username != "Sam" || u.Role != RoleMember {
		t.Fatalf("got %+v", u)
	}
	if _, err := s.AcceptInvite(ctx, []byte("tok"), &User{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("invite used twice: %v", err)
	}
	// Expired invites don't work.
	_ = s.CreateInvite(ctx, &Invite{TokenHash: []byte("old"), Username: "old", Role: RoleMember,
		ExpiresAt: time.Now().Add(-time.Minute)})
	if _, err := s.GetInviteByHash(ctx, []byte("old")); !errors.Is(err, ErrNotFound) {
		t.Fatal("expired invite found")
	}
	if _, err := s.AcceptInvite(ctx, []byte("old"), &User{}); !errors.Is(err, ErrNotFound) {
		t.Fatal("expired invite accepted")
	}
}

func TestLastAdminProtection(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	admin := &User{Username: "admin", PasswordHash: "h", TOTPSecret: "s"}
	_ = s.CreateFirstUser(ctx, admin)
	if err := s.UpdateUserAccess(ctx, admin.ID, RoleMember, false); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("demoted the last admin: %v", err)
	}
	if err := s.UpdateUserAccess(ctx, admin.ID, RoleAdmin, true); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("disabled the last admin: %v", err)
	}
	if err := s.DeleteUser(ctx, admin.ID); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("deleted the last admin: %v", err)
	}
	got, _ := s.GetUser(ctx, admin.ID)
	if got.Role != RoleAdmin || got.Disabled {
		t.Fatal("failed change was not rolled back")
	}
}

func TestDisablingSignsOut(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	_ = s.CreateFirstUser(ctx, &User{Username: "admin", PasswordHash: "h", TOTPSecret: "s"})
	_ = s.CreateInvite(ctx, &Invite{TokenHash: []byte("t"), Username: "m", Role: RoleMember, ExpiresAt: time.Now().Add(time.Hour)})
	m := &User{PasswordHash: "h", TOTPSecret: "s"}
	_, _ = s.AcceptInvite(ctx, []byte("t"), m)
	n := time.Now()
	_ = s.CreateSession(ctx, &Session{TokenHash: []byte("ms"), UserID: m.ID, Host: "app.example.com", CreatedAt: n, LastSeenAt: n, ExpiresAt: n.Add(time.Hour)})
	if err := s.UpdateUserAccess(ctx, m.ID, RoleMember, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSessionByHash(ctx, []byte("ms")); !errors.Is(err, ErrNotFound) {
		t.Fatal("disabled user still has a session")
	}
	// reset-admin keeps members.
	if err := s.DeleteAllAdmins(ctx); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.CountAdmins(ctx); n != 0 {
		t.Fatal("admins remain")
	}
	if _, err := s.GetUser(ctx, m.ID); err != nil {
		t.Fatal("member removed by reset-admin")
	}
}

func TestUpgradeFromSchemaV1(t *testing.T) {
	// A database created by the first release must upgrade cleanly, and its
	// admin must stay an admin.
	path := filepath.Join(t.TempDir(), "v1.db")
	all := migrations
	migrations = all[:1]
	s, err := Open(t.Context(), path)
	if err != nil {
		migrations = all
		t.Fatal(err)
	}
	_, err = s.db.ExecContext(t.Context(),
		"INSERT INTO users (username, password_hash, totp_secret, created_at, updated_at) VALUES ('old', 'h', 's', 1, 1)")
	_ = s.Close()
	migrations = all
	if err != nil {
		t.Fatal(err)
	}

	s, err = Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if v, _ := s.SchemaVersion(t.Context()); v != len(migrations) {
		t.Fatalf("schema v%d", v)
	}
	u, err := s.GetUserByUsername(t.Context(), "old")
	if err != nil || u.Role != RoleAdmin || u.Disabled {
		t.Fatalf("upgraded user: %+v, %v", u, err)
	}
	if n, _ := s.CountAdmins(t.Context()); n != 1 {
		t.Fatal("upgraded admin not counted")
	}
}

func TestDeletedUserIDsAreNeverReused(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	_ = s.CreateFirstUser(ctx, &User{Username: "admin", PasswordHash: "h", TOTPSecret: "s"})
	invite := func(name string) *User {
		_ = s.CreateInvite(ctx, &Invite{TokenHash: []byte(name), Username: name, Role: RoleMember, ExpiresAt: time.Now().Add(time.Hour)})
		u := &User{PasswordHash: "h", TOTPSecret: "s"}
		if _, err := s.AcceptInvite(ctx, []byte(name), u); err != nil {
			t.Fatal(err)
		}
		return u
	}
	old := invite("old")
	r := &Route{Hostname: "p.example.com", Enabled: true, Config: RouteConfig{Access: Access{Mode: AccessPrivate, Users: []int64{old.ID}}}}
	if _, err := s.CreateRoute(ctx, r, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteUser(ctx, old.ID); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetRoute(ctx, r.ID)
	if len(got.Config.Access.Users) != 0 {
		t.Fatalf("deleted user still on access list: %v", got.Config.Access.Users)
	}
	newcomer := invite("new")
	if newcomer.ID == old.ID {
		t.Fatal("a new user received a deleted user's ID")
	}
}
