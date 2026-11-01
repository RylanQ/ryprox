// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// User is an admin account.
type User struct {
	ID              int64
	Username        string
	PasswordHash    string
	TOTPSecret      string // sealed (encrypted) by the caller before storing
	TOTPLastCounter int64
	RecoveryCodes   []string // SHA-256 hashes of unused recovery codes
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// CountUsers returns how many users exist. Zero means first-run setup is needed.
func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&n)
	return n, err
}

// CreateFirstUser creates a user only if no users exist yet, atomically.
// This prevents two setup requests racing to create two admins.
func (s *Store) CreateFirstUser(ctx context.Context, u *User) error {
	codes, err := json.Marshal(u.RecoveryCodes)
	if err != nil {
		return err
	}
	t := now()
	res, err := s.db.ExecContext(ctx, `
INSERT INTO users (username, password_hash, totp_secret, recovery_codes, created_at, updated_at)
SELECT ?, ?, ?, ?, ?, ?
WHERE NOT EXISTS (SELECT 1 FROM users)`,
		u.Username, u.PasswordHash, u.TOTPSecret, string(codes), t, t)
	if err != nil {
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
	return err
}

const userCols = `id, username, password_hash, totp_secret, totp_last_counter, recovery_codes, created_at, updated_at`

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var u User
	var codes string
	var created, updated int64
	if err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.TOTPSecret, &u.TOTPLastCounter, &codes, &created, &updated); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if err := json.Unmarshal([]byte(codes), &u.RecoveryCodes); err != nil {
		return nil, err
	}
	u.CreatedAt, u.UpdatedAt = time.Unix(created, 0), time.Unix(updated, 0)
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

// UpdatePassword replaces a user's password hash.
func (s *Store) UpdatePassword(ctx context.Context, userID int64, hash string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?", hash, now(), userID)
	return err
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

// DeleteAllUsers removes every admin account (and, via cascade, every
// session). Used by "ryprox reset-admin" to recover a locked-out install.
func (s *Store) DeleteAllUsers(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM users")
	if err == nil {
		err = s.AddAudit(ctx, AuditEntry{Actor: "system", Action: "admin.reset", Detail: "admin account removed from the command line"})
	}
	return err
}
