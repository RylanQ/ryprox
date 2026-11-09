// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Followers mirror a primary server's configuration. A snapshot holds every
// table that describes configuration; sessions, the activity log and the
// followers list stay local to each server.
var syncTables = []string{"users", "routes", "settings", "invites", "tokens", "passkeys", "identities", "sites"}

// Snapshot is a copy of the configuration tables. Values are JSON-friendly:
// integers, strings, and binary as {"b64": "..."}.
type Snapshot map[string][]map[string]any

// ExportConfig reads the configuration tables.
func (s *Store) ExportConfig(ctx context.Context) (Snapshot, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	out := Snapshot{}
	for _, t := range syncTables {
		rows, err := tx.QueryContext(ctx, "SELECT * FROM "+t) //nolint:gosec // table names are a fixed list
		if err != nil {
			return nil, err
		}
		cols, err := rows.Columns()
		if err != nil {
			_ = rows.Close()
			return nil, err
		}
		list := []map[string]any{}
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				_ = rows.Close()
				return nil, err
			}
			row := map[string]any{}
			for i, c := range cols {
				if b, ok := vals[i].([]byte); ok {
					row[c] = map[string]any{"b64": base64.StdEncoding.EncodeToString(b)}
				} else {
					row[c] = vals[i]
				}
			}
			list = append(list, row)
		}
		_ = rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
		out[t] = list
	}
	return out, nil
}

// ImportConfig replaces this server's configuration with a snapshot, in one
// transaction. Local sessions of people who no longer exist are removed.
func (s *Store) ImportConfig(ctx context.Context, snap Snapshot) error {
	for _, t := range syncTables {
		if _, ok := snap[t]; !ok {
			return fmt.Errorf("snapshot is missing %s", t)
		}
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	// Rows are replaced wholesale; don't let the user deletes cascade into
	// local sessions while that happens.
	if _, err := conn.ExecContext(ctx, "PRAGMA foreign_keys = OFF"); err != nil {
		return err
	}
	defer func() { _, _ = conn.ExecContext(context.Background(), "PRAGMA foreign_keys = ON") }()
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for i := len(syncTables) - 1; i >= 0; i-- {
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+syncTables[i]); err != nil { //nolint:gosec // fixed list
			return err
		}
	}
	for _, t := range syncTables {
		cols, err := tableColumns(ctx, tx, t)
		if err != nil {
			return err
		}
		for _, row := range snap[t] {
			var names, marks []string
			var args []any
			for _, c := range cols {
				v, ok := row[c]
				if !ok {
					continue // an older primary without this column: keep the default
				}
				if m, ok := v.(map[string]any); ok {
					b, err := base64.StdEncoding.DecodeString(fmt.Sprint(m["b64"]))
					if err != nil {
						return fmt.Errorf("%s.%s: %w", t, c, err)
					}
					v = b
				}
				switch n := v.(type) {
				case json.Number:
					if i, err := n.Int64(); err == nil {
						v = i
					} else if f, err := n.Float64(); err == nil {
						v = f
					}
				case float64:
					if n == float64(int64(n)) {
						v = int64(n)
					}
				}
				names = append(names, `"`+c+`"`)
				marks = append(marks, "?")
				args = append(args, v)
			}
			q := "INSERT INTO " + t + " (" + strings.Join(names, ", ") + ") VALUES (" + strings.Join(marks, ", ") + ")" //nolint:gosec // names come from the schema
			if _, err := tx.ExecContext(ctx, q, args...); err != nil {
				return fmt.Errorf("%s: %w", t, err)
			}
		}
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM sessions WHERE user_id NOT IN (SELECT id FROM users)"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE disabled = 1)"); err != nil {
		return err
	}
	return tx.Commit()
}

func tableColumns(ctx context.Context, tx *sql.Tx, table string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, "SELECT name FROM pragma_table_info(?)", table)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var cols []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		cols = append(cols, c)
	}
	if len(cols) == 0 {
		return nil, errors.New("unknown table " + table)
	}
	return cols, rows.Err()
}

// Node is a follower server allowed to mirror this one.
type Node struct {
	ID         int64     `json:"id"`
	Name       string    `json:"name"`
	TokenHash  []byte    `json:"-"`
	CreatedAt  time.Time `json:"createdAt"`
	LastSeenAt time.Time `json:"lastSeenAt"`
	LastIP     string    `json:"lastIp"`
}

// CreateNode stores a new follower.
func (s *Store) CreateNode(ctx context.Context, n *Node) error {
	n.CreatedAt = time.Unix(now(), 0)
	res, err := s.db.ExecContext(ctx, "INSERT INTO nodes (name, token_hash, created_at) VALUES (?, ?, ?)", n.Name, n.TokenHash, n.CreatedAt.Unix())
	if err != nil {
		if isUniqueViolation(err) {
			return ErrConflict
		}
		return err
	}
	n.ID, err = res.LastInsertId()
	return err
}

const nodeCols = "id, name, token_hash, created_at, last_seen_at, last_ip"

func scanNode(row interface{ Scan(...any) error }) (*Node, error) {
	var n Node
	var c, l int64
	if err := row.Scan(&n.ID, &n.Name, &n.TokenHash, &c, &l, &n.LastIP); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	n.CreatedAt, n.LastSeenAt = time.Unix(c, 0), timeOrZero(l)
	return &n, nil
}

// ListNodes returns the followers.
func (s *Store) ListNodes(ctx context.Context) ([]Node, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+nodeCols+" FROM nodes ORDER BY name COLLATE NOCASE")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []Node{}
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *n)
	}
	return out, rows.Err()
}

// GetNodeByToken finds the follower a token belongs to.
func (s *Store) GetNodeByToken(ctx context.Context, hash []byte) (*Node, error) {
	return scanNode(s.db.QueryRowContext(ctx, "SELECT "+nodeCols+" FROM nodes WHERE token_hash = ?", hash))
}

// TouchNode records a follower's sync.
func (s *Store) TouchNode(ctx context.Context, id int64, ip string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE nodes SET last_seen_at = ?, last_ip = ? WHERE id = ?", now(), ip, id)
	return err
}

// DeleteNode removes a follower; it can no longer sync.
func (s *Store) DeleteNode(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, "DELETE FROM nodes WHERE id = ?", id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
