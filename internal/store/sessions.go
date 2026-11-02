// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Session is a logged-in browser. Only a hash of the session token is
// stored, so a leaked database cannot be used to log in.
type Session struct {
	ID         int64
	TokenHash  []byte
	UserID     int64
	Host       string // the site this session is valid on; "" for the dashboard
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
	IP         string
	UserAgent  string
}

// CreateSession stores a new session.
func (s *Store) CreateSession(ctx context.Context, sess *Session) error {
	res, err := s.db.ExecContext(ctx, `
INSERT INTO sessions (token_hash, user_id, host, created_at, last_seen_at, expires_at, ip, user_agent)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		sess.TokenHash, sess.UserID, sess.Host, sess.CreatedAt.Unix(), sess.LastSeenAt.Unix(), sess.ExpiresAt.Unix(), sess.IP, sess.UserAgent)
	if err != nil {
		return err
	}
	sess.ID, err = res.LastInsertId()
	return err
}

const sessionCols = `id, token_hash, user_id, host, created_at, last_seen_at, expires_at, ip, user_agent`

func scanSession(row interface{ Scan(...any) error }) (*Session, error) {
	var x Session
	var c, l, e int64
	if err := row.Scan(&x.ID, &x.TokenHash, &x.UserID, &x.Host, &c, &l, &e, &x.IP, &x.UserAgent); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	x.CreatedAt, x.LastSeenAt, x.ExpiresAt = time.Unix(c, 0), time.Unix(l, 0), time.Unix(e, 0)
	return &x, nil
}

// GetSessionByHash finds a session by its token hash.
func (s *Store) GetSessionByHash(ctx context.Context, hash []byte) (*Session, error) {
	return scanSession(s.db.QueryRowContext(ctx, "SELECT "+sessionCols+" FROM sessions WHERE token_hash = ?", hash))
}

// TouchSession updates when a session was last used.
func (s *Store) TouchSession(ctx context.Context, id int64, t time.Time) error {
	_, err := s.db.ExecContext(ctx, "UPDATE sessions SET last_seen_at = ? WHERE id = ?", t.Unix(), id)
	return err
}

// ListSessions returns a user's sessions, newest first.
func (s *Store) ListSessions(ctx context.Context, userID int64) ([]Session, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+sessionCols+" FROM sessions WHERE user_id = ? ORDER BY last_seen_at DESC", userID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Session
	for rows.Next() {
		x, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *x)
	}
	return out, rows.Err()
}

// DeleteSession removes one session belonging to userID.
func (s *Store) DeleteSession(ctx context.Context, userID, id int64) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE id = ? AND user_id = ?", id, userID)
	return err
}

// DeleteOtherSessions removes all of a user's sessions except keepID.
func (s *Store) DeleteOtherSessions(ctx context.Context, userID, keepID int64) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE user_id = ? AND id != ?", userID, keepID)
	return err
}

// DeleteExpiredSessions removes sessions past their expiry or idle limit.
func (s *Store) DeleteExpiredSessions(ctx context.Context, now time.Time, idle time.Duration) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE expires_at <= ? OR last_seen_at <= ?",
		now.Unix(), now.Add(-idle).Unix())
	return err
}
