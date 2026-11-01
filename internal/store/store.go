// SPDX-License-Identifier: AGPL-3.0-only

// Package store keeps all of RyProx's state in a single SQLite database.
// The database is the source of truth: the proxy's live configuration is
// always rebuilt from it.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/ncruces/go-sqlite3/driver" // registers the "sqlite3" driver
)

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

// ErrConflict is returned when a unique value (like a hostname) is taken.
var ErrConflict = errors.New("already exists")

// Store wraps the SQLite database.
type Store struct {
	db *sql.DB
}

// Open opens (or creates) the database at path and runs migrations.
func Open(ctx context.Context, path string) (*Store, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	q.Add("_txlock", "immediate")
	q.Add("_pragma", "busy_timeout(10000)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "journal_mode(wal)")
	q.Add("_pragma", "synchronous(normal)")
	dsn := (&url.URL{Scheme: "file", OmitHost: true, Path: filepath.ToSlash(abs), RawQuery: q.Encode()}).String()

	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}
	// SQLite allows one writer at a time; a small pool avoids lock contention.
	db.SetMaxOpenConns(4)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("open database: %w", err)
	}
	s := &Store{db: db}
	if err := s.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// migrations are applied in order; their index+1 is the schema version.
// Never edit a migration that has shipped: add a new one instead.
var migrations = []string{
	// 1: initial schema
	`
CREATE TABLE users (
	id                INTEGER PRIMARY KEY,
	username          TEXT    NOT NULL UNIQUE COLLATE NOCASE,
	password_hash     TEXT    NOT NULL,
	totp_secret       TEXT    NOT NULL,
	totp_last_counter INTEGER NOT NULL DEFAULT 0,
	recovery_codes    TEXT    NOT NULL DEFAULT '[]',
	created_at        INTEGER NOT NULL,
	updated_at        INTEGER NOT NULL
);
CREATE TABLE sessions (
	id           INTEGER PRIMARY KEY,
	token_hash   BLOB    NOT NULL UNIQUE,
	user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	created_at   INTEGER NOT NULL,
	last_seen_at INTEGER NOT NULL,
	expires_at   INTEGER NOT NULL,
	ip           TEXT    NOT NULL DEFAULT '',
	user_agent   TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX sessions_user ON sessions(user_id);
CREATE TABLE routes (
	id         INTEGER PRIMARY KEY,
	hostname   TEXT    NOT NULL UNIQUE,
	enabled    INTEGER NOT NULL DEFAULT 1,
	config     TEXT    NOT NULL,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL
);
CREATE TABLE settings (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
CREATE TABLE audit_log (
	id     INTEGER PRIMARY KEY,
	at     INTEGER NOT NULL,
	actor  TEXT    NOT NULL,
	action TEXT    NOT NULL,
	detail TEXT    NOT NULL DEFAULT '',
	ip     TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX audit_at ON audit_log(at);
`,
}

func (s *Store) migrate(ctx context.Context) error {
	var version int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version > len(migrations) {
		return fmt.Errorf("database schema v%d is newer than this RyProx (v%d); upgrade RyProx", version, len(migrations))
	}
	for i := version; i < len(migrations); i++ {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, migrations[i]); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", i+1)); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// SchemaVersion returns the current schema version (for tests and diagnostics).
func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	var v int
	err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&v)
	return v, err
}

func now() int64 { return time.Now().Unix() }

func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}
