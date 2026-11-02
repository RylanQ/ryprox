// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// Route sends requests for one hostname to one or more backend targets.
type Route struct {
	ID        int64       `json:"id"`
	Hostname  string      `json:"hostname"`
	Enabled   bool        `json:"enabled"`
	Config    RouteConfig `json:"config"`
	CreatedAt time.Time   `json:"createdAt"`
	UpdatedAt time.Time   `json:"updatedAt"`
}

// RouteConfig holds everything about a route except its identity.
// It is stored as JSON so new options can be added without migrations.
type RouteConfig struct {
	Targets         []Target     `json:"targets"`
	LoadBalancing   string       `json:"loadBalancing"` // "round_robin" or "failover"
	TLSSkipVerify   bool         `json:"tlsSkipVerify"` // for backends with self-signed certificates
	Websockets      bool         `json:"websockets"`
	HTTPSRedirect   bool         `json:"httpsRedirect"`
	PreserveHost    bool         `json:"preserveHost"` // send the visitor's Host header to the backend
	RequestHeaders  []HeaderRule `json:"requestHeaders"`
	ResponseHeaders []HeaderRule `json:"responseHeaders"`
	HealthCheck     HealthCheck  `json:"healthCheck"`
	Access          Access       `json:"access"`
}

// Access modes.
const (
	AccessPrivate = "private" // only signed-in people on the list (the default)
	AccessPublic  = "public"  // anyone on the internet
)

// Access decides who may open a route. Routes are private unless an admin
// explicitly makes them public: zero trust means deny by default.
type Access struct {
	Mode  string  `json:"mode"`
	Users []int64 `json:"users"` // who may open a private route
}

// IsPublic reports whether anyone may open the route. Anything other than
// an explicit "public" (including a missing value) is private.
func (a Access) IsPublic() bool { return a.Mode == AccessPublic }

// Allows reports whether userID is on the route's access list.
func (a Access) Allows(userID int64) bool {
	for _, id := range a.Users {
		if id == userID {
			return true
		}
	}
	return false
}

// Target is one backend server, e.g. http://10.0.0.5:8080.
type Target struct {
	URL string `json:"url"`
}

// HeaderRule sets or removes one header.
type HeaderRule struct {
	Action string `json:"action"` // "set" or "remove"
	Name   string `json:"name"`
	Value  string `json:"value,omitempty"`
}

// HealthCheck controls background checks of a route's targets.
type HealthCheck struct {
	Enabled         bool   `json:"enabled"`
	Path            string `json:"path"`
	IntervalSeconds int    `json:"intervalSeconds"`
}

// RouteCheck is called with the complete list of routes as they would be
// after a change. If it returns an error, the change is rolled back. This is
// how RyProx guarantees an invalid configuration is never saved.
type RouteCheck func([]Route) error

const routeCols = `id, hostname, enabled, config, created_at, updated_at`

type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func scanRoute(row interface{ Scan(...any) error }) (*Route, error) {
	var r Route
	var cfg string
	var c, u int64
	if err := row.Scan(&r.ID, &r.Hostname, &r.Enabled, &cfg, &c, &u); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if err := json.Unmarshal([]byte(cfg), &r.Config); err != nil {
		return nil, err
	}
	r.CreatedAt, r.UpdatedAt = time.Unix(c, 0), time.Unix(u, 0)
	return &r, nil
}

func listRoutes(ctx context.Context, q querier) ([]Route, error) {
	rows, err := q.QueryContext(ctx, "SELECT "+routeCols+" FROM routes ORDER BY hostname")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []Route{}
	for rows.Next() {
		r, err := scanRoute(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

// ListRoutes returns all routes sorted by hostname.
func (s *Store) ListRoutes(ctx context.Context) ([]Route, error) {
	return listRoutes(ctx, s.db)
}

// GetRoute returns one route.
func (s *Store) GetRoute(ctx context.Context, id int64) (*Route, error) {
	return scanRoute(s.db.QueryRowContext(ctx, "SELECT "+routeCols+" FROM routes WHERE id = ?", id))
}

// changeRoutes runs change inside a transaction, then calls check with the
// resulting route list. The transaction only commits if check passes.
func (s *Store) changeRoutes(ctx context.Context, change func(*sql.Tx) error, check RouteCheck) ([]Route, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	if err := change(tx); err != nil {
		if isUniqueViolation(err) {
			return nil, ErrConflict
		}
		return nil, err
	}
	all, err := listRoutes(ctx, tx)
	if err != nil {
		return nil, err
	}
	if check != nil {
		if err := check(all); err != nil {
			return nil, err
		}
	}
	return all, tx.Commit()
}

// CreateRoute adds a route. It returns the full route list after the change.
func (s *Store) CreateRoute(ctx context.Context, r *Route, check RouteCheck) ([]Route, error) {
	cfg, err := json.Marshal(r.Config)
	if err != nil {
		return nil, err
	}
	return s.changeRoutes(ctx, func(tx *sql.Tx) error {
		t := now()
		res, err := tx.ExecContext(ctx,
			"INSERT INTO routes (hostname, enabled, config, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
			r.Hostname, r.Enabled, string(cfg), t, t)
		if err != nil {
			return err
		}
		r.ID, err = res.LastInsertId()
		r.CreatedAt, r.UpdatedAt = time.Unix(t, 0), time.Unix(t, 0)
		return err
	}, check)
}

// UpdateRoute replaces a route's hostname, enabled flag and config.
func (s *Store) UpdateRoute(ctx context.Context, r *Route, check RouteCheck) ([]Route, error) {
	cfg, err := json.Marshal(r.Config)
	if err != nil {
		return nil, err
	}
	return s.changeRoutes(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx,
			"UPDATE routes SET hostname = ?, enabled = ?, config = ?, updated_at = ? WHERE id = ?",
			r.Hostname, r.Enabled, string(cfg), now(), r.ID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return nil
	}, check)
}

// SetRouteEnabled turns a route on or off.
func (s *Store) SetRouteEnabled(ctx context.Context, id int64, enabled bool, check RouteCheck) ([]Route, error) {
	return s.changeRoutes(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, "UPDATE routes SET enabled = ?, updated_at = ? WHERE id = ?", enabled, now(), id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return nil
	}, check)
}

// DeleteRoute removes a route.
func (s *Store) DeleteRoute(ctx context.Context, id int64, check RouteCheck) ([]Route, error) {
	return s.changeRoutes(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, "DELETE FROM routes WHERE id = ?", id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return nil
	}, check)
}
