// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Site is a remote network reached through a tunnel agent.
type Site struct {
	ID         int64     `json:"id"`
	Name       string    `json:"name"`
	TokenHash  []byte    `json:"-"`
	CreatedAt  time.Time `json:"createdAt"`
	LastSeenAt time.Time `json:"lastSeenAt"`
}

// CreateSite stores a new site.
func (s *Store) CreateSite(ctx context.Context, site *Site) error {
	site.CreatedAt = time.Unix(now(), 0)
	res, err := s.db.ExecContext(ctx, "INSERT INTO sites (name, token_hash, created_at) VALUES (?, ?, ?)", site.Name, site.TokenHash, site.CreatedAt.Unix())
	if err != nil {
		if isUniqueViolation(err) {
			return ErrConflict
		}
		return err
	}
	site.ID, err = res.LastInsertId()
	return err
}

const siteCols = "id, name, token_hash, created_at, last_seen_at"

func scanSite(row interface{ Scan(...any) error }) (*Site, error) {
	var x Site
	var c, l int64
	if err := row.Scan(&x.ID, &x.Name, &x.TokenHash, &c, &l); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	x.CreatedAt, x.LastSeenAt = time.Unix(c, 0), timeOrZero(l)
	return &x, nil
}

// ListSites returns all sites by name.
func (s *Store) ListSites(ctx context.Context) ([]Site, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+siteCols+" FROM sites ORDER BY name COLLATE NOCASE")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []Site{}
	for rows.Next() {
		x, err := scanSite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *x)
	}
	return out, rows.Err()
}

// GetSiteByToken finds the site a tunnel token belongs to.
func (s *Store) GetSiteByToken(ctx context.Context, hash []byte) (*Site, error) {
	return scanSite(s.db.QueryRowContext(ctx, "SELECT "+siteCols+" FROM sites WHERE token_hash = ?", hash))
}

// SetSiteToken replaces a site's token (the old one stops working).
func (s *Store) SetSiteToken(ctx context.Context, id int64, hash []byte) error {
	res, err := s.db.ExecContext(ctx, "UPDATE sites SET token_hash = ? WHERE id = ?", hash, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// TouchSite records that a site's agent connected.
func (s *Store) TouchSite(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, "UPDATE sites SET last_seen_at = ? WHERE id = ?", now(), id)
	return err
}

// ErrSiteInUse means routes still use the site.
var ErrSiteInUse = errors.New("routes still use this site; move them first")

// DeleteSite removes a site if no route uses it.
func (s *Store) DeleteSite(ctx context.Context, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	routes, err := listRoutes(ctx, tx)
	if err != nil {
		return err
	}
	for _, r := range routes {
		if r.Config.Console.Site == id {
			return ErrSiteInUse
		}
		for _, t := range r.Config.AllTargets() {
			if t.Site == id {
				return ErrSiteInUse
			}
		}
	}
	res, err := tx.ExecContext(ctx, "DELETE FROM sites WHERE id = ?", id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}

// SiteExists reports whether a site ID is valid.
func (s *Store) SiteExists(ctx context.Context, id int64) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sites WHERE id = ?", id).Scan(&n)
	return n > 0, err
}
