// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// Roles.
const (
	RoleAdmin  = "admin"  // can manage RyProx and open the sites they're given
	RoleMember = "member" // can only open the sites they're given
)

// User is a person who can sign in.
type User struct {
	ID              int64
	Username        string
	Role            string
	Disabled        bool
	PasswordHash    string
	TOTPSecret      string // sealed (encrypted) by the caller before storing
	TOTPLastCounter int64
	RecoveryCodes   []string // SHA-256 hashes of unused recovery codes
	CreatedAt       time.Time
	UpdatedAt       time.Time
	LastLoginAt     time.Time
}

// CountAdmins returns how many enabled admins exist. Zero means first-run
// setup is needed.
func (s *Store) CountAdmins(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0").Scan(&n)
	return n, err
}

// CreateFirstUser creates an admin only if no enabled admin exists yet,
// atomically. This prevents two setup requests racing to create two admins.
func (s *Store) CreateFirstUser(ctx context.Context, u *User) error {
	codes, err := json.Marshal(u.RecoveryCodes)
	if err != nil {
		return err
	}
	t := now()
	res, err := s.db.ExecContext(ctx, `
INSERT INTO users (username, role, password_hash, totp_secret, recovery_codes, created_at, updated_at)
SELECT ?, 'admin', ?, ?, ?, ?, ?
WHERE NOT EXISTS (SELECT 1 FROM users WHERE role = 'admin' AND disabled = 0)`,
		u.Username, u.PasswordHash, u.TOTPSecret, string(codes), t, t)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrConflict
		}
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrConflict
	}
	u.ID, err = res.LastInsertId()
	u.Role = RoleAdmin
	return err
}

const userCols = `id, username, role, disabled, password_hash, totp_secret, totp_last_counter, recovery_codes, created_at, updated_at, last_login_at`

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var u User
	var codes string
	var created, updated, last int64
	if err := row.Scan(&u.ID, &u.Username, &u.Role, &u.Disabled, &u.PasswordHash, &u.TOTPSecret, &u.TOTPLastCounter,
		&codes, &created, &updated, &last); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if err := json.Unmarshal([]byte(codes), &u.RecoveryCodes); err != nil {
		return nil, err
	}
	u.CreatedAt, u.UpdatedAt = time.Unix(created, 0), time.Unix(updated, 0)
	if last > 0 {
		u.LastLoginAt = time.Unix(last, 0)
	}
	return &u, nil
}

// GetUserByUsername looks a user up, ignoring case.
func (s *Store) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, "SELECT "+userCols+" FROM users WHERE username = ?", username))
}

// GetUser looks a user up by ID.
func (s *Store) GetUser(ctx context.Context, id int64) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, "SELECT "+userCols+" FROM users WHERE id = ?", id))
}

// ListUsers returns everyone, sorted by username.
func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+userCols+" FROM users ORDER BY username COLLATE NOCASE")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

// UpdatePassword replaces a user's password hash.
func (s *Store) UpdatePassword(ctx context.Context, userID int64, hash string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?", hash, now(), userID)
	return err
}

// RecordLogin notes when a user last signed in.
func (s *Store) RecordLogin(ctx context.Context, userID int64) error {
	_, err := s.db.ExecContext(ctx, "UPDATE users SET last_login_at = ? WHERE id = ?", now(), userID)
	return err
}

// ErrLastAdmin is returned when a change would leave nobody able to manage RyProx.
var ErrLastAdmin = errors.New("there must always be at least one enabled admin")

// UpdateUserAccess changes a user's role and disabled flag. Disabling a
// user also signs them out everywhere. It refuses to remove the last admin.
func (s *Store) UpdateUserAccess(ctx context.Context, userID int64, role string, disabled bool) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, "UPDATE users SET role = ?, disabled = ?, updated_at = ? WHERE id = ?", role, disabled, now(), userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if err := checkAdminsRemain(ctx, tx); err != nil {
		return err
	}
	if disabled {
		if _, err := tx.ExecContext(ctx, "DELETE FROM sessions WHERE user_id = ?", userID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// DeleteUser removes a user and their sessions. It refuses to remove the last admin.
func (s *Store) DeleteUser(ctx context.Context, userID int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, "DELETE FROM users WHERE id = ?", userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if err := checkAdminsRemain(ctx, tx); err != nil {
		return err
	}
	if err := removeUserFromRoutes(ctx, tx, userID); err != nil {
		return err
	}
	return tx.Commit()
}

// removeUserFromRoutes takes a user off every route's access list.
func removeUserFromRoutes(ctx context.Context, tx *sql.Tx, userID int64) error {
	routes, err := listRoutes(ctx, tx)
	if err != nil {
		return err
	}
	for _, r := range routes {
		if !r.Config.Access.Allows(userID) {
			continue
		}
		kept := []int64{}
		for _, id := range r.Config.Access.Users {
			if id != userID {
				kept = append(kept, id)
			}
		}
		r.Config.Access.Users = kept
		cfg, err := json.Marshal(r.Config)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "UPDATE routes SET config = ?, updated_at = ? WHERE id = ?", string(cfg), now(), r.ID); err != nil {
			return err
		}
	}
	return nil
}

func checkAdminsRemain(ctx context.Context, tx *sql.Tx) error {
	var n int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0").Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return ErrLastAdmin
	}
	return nil
}

// ClaimTOTPCounter records that the TOTP code for counter has been used.
// It returns false if that counter (or a later one) was already used, which
// stops the same code being replayed, even by two simultaneous requests.
func (s *Store) ClaimTOTPCounter(ctx context.Context, userID, counter int64) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		"UPDATE users SET totp_last_counter = ? WHERE id = ? AND totp_last_counter < ?",
		counter, userID, counter)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// ConsumeRecoveryCode removes one recovery-code hash if present.
// It returns false if the code was not found (or already used).
func (s *Store) ConsumeRecoveryCode(ctx context.Context, userID int64, codeHash string) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()

	u, err := scanUser(tx.QueryRowContext(ctx, "SELECT "+userCols+" FROM users WHERE id = ?", userID))
	if err != nil {
		return false, err
	}
	kept := u.RecoveryCodes[:0]
	found := false
	for _, h := range u.RecoveryCodes {
		if !found && h == codeHash {
			found = true
			continue
		}
		kept = append(kept, h)
	}
	if !found {
		return false, nil
	}
	b, err := json.Marshal(kept)
	if err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE users SET recovery_codes = ?, updated_at = ? WHERE id = ?", string(b), now(), userID); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// SetRecoveryCodes replaces all of a user's recovery-code hashes.
func (s *Store) SetRecoveryCodes(ctx context.Context, userID int64, hashes []string) error {
	b, err := json.Marshal(hashes)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, "UPDATE users SET recovery_codes = ?, updated_at = ? WHERE id = ?", string(b), now(), userID)
	return err
}

// DeleteAllAdmins removes every admin account (and their sessions). Members
// are kept. Used by "ryprox reset-admin" to recover a locked-out install.
func (s *Store) DeleteAllAdmins(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM users WHERE role = 'admin'")
	if err == nil {
		err = s.AddAudit(ctx, AuditEntry{Actor: "system", Action: "admin.reset", Detail: "admin accounts removed from the command line"})
	}
	return err
}

// --- invites -----------------------------------------------------------

// Invite lets a new person create their own account with a one-time link.
type Invite struct {
	ID        int64     `json:"id"`
	TokenHash []byte    `json:"-"`
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	Routes    []int64   `json:"routes"`
	CreatedBy string    `json:"createdBy"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// CreateInvite stores an invite. The username must not be taken by a user
// or another pending invite.
func (s *Store) CreateInvite(ctx context.Context, inv *Invite) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var taken int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE username = ?", inv.Username).Scan(&taken); err != nil {
		return err
	}
	if taken > 0 {
		return ErrConflict
	}
	// Replace any earlier invite for the same name.
	if _, err := tx.ExecContext(ctx, "DELETE FROM invites WHERE username = ?", inv.Username); err != nil {
		return err
	}
	routes, err := json.Marshal(inv.Routes)
	if err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx,
		"INSERT INTO invites (token_hash, username, role, routes, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		inv.TokenHash, inv.Username, inv.Role, string(routes), inv.CreatedBy, inv.CreatedAt.Unix(), inv.ExpiresAt.Unix())
	if err != nil {
		return err
	}
	if inv.ID, err = res.LastInsertId(); err != nil {
		return err
	}
	return tx.Commit()
}

const inviteCols = "id, token_hash, username, role, routes, created_by, created_at, expires_at"

func scanInvite(row interface{ Scan(...any) error }) (*Invite, error) {
	var inv Invite
	var c, e int64
	var routes string
	if err := row.Scan(&inv.ID, &inv.TokenHash, &inv.Username, &inv.Role, &routes, &inv.CreatedBy, &c, &e); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if err := json.Unmarshal([]byte(routes), &inv.Routes); err != nil {
		return nil, err
	}
	inv.CreatedAt, inv.ExpiresAt = time.Unix(c, 0), time.Unix(e, 0)
	return &inv, nil
}

// GetInviteByHash finds an unexpired invite.
func (s *Store) GetInviteByHash(ctx context.Context, hash []byte) (*Invite, error) {
	inv, err := scanInvite(s.db.QueryRowContext(ctx, "SELECT "+inviteCols+" FROM invites WHERE token_hash = ?", hash))
	if err != nil {
		return nil, err
	}
	if time.Now().After(inv.ExpiresAt) {
		return nil, ErrNotFound
	}
	return inv, nil
}

// ListInvites returns pending, unexpired invites.
func (s *Store) ListInvites(ctx context.Context) ([]Invite, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+inviteCols+" FROM invites WHERE expires_at > ? ORDER BY created_at DESC", now())
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []Invite{}
	for rows.Next() {
		inv, err := scanInvite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *inv)
	}
	return out, rows.Err()
}

// DeleteInvite cancels an invite.
func (s *Store) DeleteInvite(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM invites WHERE id = ?", id)
	return err
}

// AcceptInvite turns an invite into a user, atomically: the invite can only
// ever be used once.
func (s *Store) AcceptInvite(ctx context.Context, tokenHash []byte, u *User) (*Invite, error) {
	inv, err := s.acceptInvite(ctx, tokenHash, u)
	return inv, err
}

func (s *Store) acceptInvite(ctx context.Context, tokenHash []byte, u *User) (*Invite, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	inv, err := scanInvite(tx.QueryRowContext(ctx, "SELECT "+inviteCols+" FROM invites WHERE token_hash = ?", tokenHash))
	if err != nil {
		return nil, err
	}
	if time.Now().After(inv.ExpiresAt) {
		return nil, ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM invites WHERE id = ?", inv.ID); err != nil {
		return nil, err
	}
	codes, err := json.Marshal(u.RecoveryCodes)
	if err != nil {
		return nil, err
	}
	t := now()
	res, err := tx.ExecContext(ctx,
		"INSERT INTO users (username, role, password_hash, totp_secret, recovery_codes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		inv.Username, inv.Role, u.PasswordHash, u.TOTPSecret, string(codes), t, t)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, ErrConflict
		}
		return nil, err
	}
	if u.ID, err = res.LastInsertId(); err != nil {
		return nil, err
	}
	u.Username, u.Role = inv.Username, inv.Role
	return inv, tx.Commit()
}
