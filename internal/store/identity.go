// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Token scopes.
const (
	ScopeSites = "sites" // open private sites the owner has access to
	ScopeAdmin = "admin" // use the admin API (admins only)
)

// Token is a long-lived credential for scripts and API clients.
type Token struct {
	ID         int64     `json:"id"`
	UserID     int64     `json:"userId"`
	Name       string    `json:"name"`
	Hash       []byte    `json:"-"`
	Scope      string    `json:"scope"`
	CreatedAt  time.Time `json:"createdAt"`
	ExpiresAt  time.Time `json:"expiresAt"` // zero: never
	LastUsedAt time.Time `json:"lastUsedAt"`
}

func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func timeOrZero(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(n, 0)
}

// CreateToken stores a token.
func (s *Store) CreateToken(ctx context.Context, t *Token) error {
	t.CreatedAt = time.Unix(now(), 0)
	res, err := s.db.ExecContext(ctx, "INSERT INTO tokens (user_id, name, token_hash, scope, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
		t.UserID, t.Name, t.Hash, t.Scope, t.CreatedAt.Unix(), unixOrZero(t.ExpiresAt))
	if err != nil {
		return err
	}
	t.ID, err = res.LastInsertId()
	return err
}

const tokenCols = "id, user_id, name, token_hash, scope, created_at, expires_at, last_used_at"

func scanToken(row interface{ Scan(...any) error }) (*Token, error) {
	var t Token
	var c, e, l int64
	if err := row.Scan(&t.ID, &t.UserID, &t.Name, &t.Hash, &t.Scope, &c, &e, &l); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	t.CreatedAt, t.ExpiresAt, t.LastUsedAt = time.Unix(c, 0), timeOrZero(e), timeOrZero(l)
	return &t, nil
}

// GetTokenByHash finds a token.
func (s *Store) GetTokenByHash(ctx context.Context, hash []byte) (*Token, error) {
	return scanToken(s.db.QueryRowContext(ctx, "SELECT "+tokenCols+" FROM tokens WHERE token_hash = ?", hash))
}

// ListTokens returns a user's tokens, newest first.
func (s *Store) ListTokens(ctx context.Context, userID int64) ([]Token, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+tokenCols+" FROM tokens WHERE user_id = ? ORDER BY id DESC", userID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []Token{}
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

// TouchToken records that a token was used (at most once a minute).
func (s *Store) TouchToken(ctx context.Context, id int64) error {
	t := now()
	_, err := s.db.ExecContext(ctx, "UPDATE tokens SET last_used_at = ? WHERE id = ? AND last_used_at < ?", t, id, t-60)
	return err
}

// DeleteToken removes one of a user's tokens.
func (s *Store) DeleteToken(ctx context.Context, userID, id int64) error {
	res, err := s.db.ExecContext(ctx, "DELETE FROM tokens WHERE id = ? AND user_id = ?", id, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteAdminTokens removes a user's admin-scope tokens (on demotion).
func (s *Store) DeleteAdminTokens(ctx context.Context, userID int64) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM tokens WHERE user_id = ? AND scope = ?", userID, ScopeAdmin)
	return err
}

// Passkey is a WebAuthn credential. Data is the library's JSON encoding.
type Passkey struct {
	ID           int64     `json:"id"`
	UserID       int64     `json:"-"`
	Name         string    `json:"name"`
	CredentialID []byte    `json:"-"`
	Data         string    `json:"-"`
	CreatedAt    time.Time `json:"createdAt"`
	LastUsedAt   time.Time `json:"lastUsedAt"`
}

// AddPasskey stores a new passkey.
func (s *Store) AddPasskey(ctx context.Context, p *Passkey) error {
	p.CreatedAt = time.Unix(now(), 0)
	res, err := s.db.ExecContext(ctx, "INSERT INTO passkeys (user_id, name, credential_id, data, created_at) VALUES (?, ?, ?, ?, ?)",
		p.UserID, p.Name, p.CredentialID, p.Data, p.CreatedAt.Unix())
	if err != nil {
		if isUniqueViolation(err) {
			return ErrConflict
		}
		return err
	}
	p.ID, err = res.LastInsertId()
	return err
}

// ListPasskeys returns a user's passkeys.
func (s *Store) ListPasskeys(ctx context.Context, userID int64) ([]Passkey, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id, user_id, name, credential_id, data, created_at, last_used_at FROM passkeys WHERE user_id = ? ORDER BY id", userID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []Passkey{}
	for rows.Next() {
		var p Passkey
		var c, l int64
		if err := rows.Scan(&p.ID, &p.UserID, &p.Name, &p.CredentialID, &p.Data, &c, &l); err != nil {
			return nil, err
		}
		p.CreatedAt, p.LastUsedAt = time.Unix(c, 0), timeOrZero(l)
		out = append(out, p)
	}
	return out, rows.Err()
}

// UpdatePasskeyData saves a passkey after use (its signature counter and
// flags change) and records when it was used.
func (s *Store) UpdatePasskeyData(ctx context.Context, userID int64, credentialID []byte, data string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE passkeys SET data = ?, last_used_at = ? WHERE user_id = ? AND credential_id = ?",
		data, now(), userID, credentialID)
	return err
}

// DeletePasskey removes one of a user's passkeys.
func (s *Store) DeletePasskey(ctx context.Context, userID, id int64) error {
	res, err := s.db.ExecContext(ctx, "DELETE FROM passkeys WHERE id = ? AND user_id = ?", id, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Identity links a single sign-on account (provider + subject) to a user.
type Identity struct {
	UserID   int64
	Provider string
	Subject  string
	Email    string
}

// GetIdentity finds the user linked to a provider account.
func (s *Store) GetIdentity(ctx context.Context, provider, subject string) (*Identity, error) {
	var i Identity
	err := s.db.QueryRowContext(ctx, "SELECT user_id, provider, subject, email FROM identities WHERE provider = ? AND subject = ?", provider, subject).
		Scan(&i.UserID, &i.Provider, &i.Subject, &i.Email)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &i, err
}

// LinkIdentity links a provider account to a user. Once linked, a user's
// account for a provider can't silently change to a different subject.
func (s *Store) LinkIdentity(ctx context.Context, i Identity) error {
	_, err := s.db.ExecContext(ctx, "INSERT INTO identities (user_id, provider, subject, email, created_at) VALUES (?, ?, ?, ?, ?)",
		i.UserID, i.Provider, i.Subject, i.Email, now())
	if isUniqueViolation(err) {
		return ErrConflict
	}
	return err
}

// HasIdentity reports whether a user already has an account linked for provider.
func (s *Store) HasIdentity(ctx context.Context, userID int64, provider string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM identities WHERE user_id = ? AND provider = ?", userID, provider).Scan(&n)
	return n > 0, err
}

// UnlinkIdentities removes a user's sign-on links.
func (s *Store) UnlinkIdentities(ctx context.Context, userID int64) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM identities WHERE user_id = ?", userID)
	return err
}

// GetJSONSetting loads a JSON-encoded setting ("" if unset).
func (s *Store) GetJSONSetting(ctx context.Context, key string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, "SELECT value FROM settings WHERE key = ?", key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

// SetJSONSetting saves a JSON-encoded setting.
func (s *Store) SetJSONSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", key, value)
	return err
}
