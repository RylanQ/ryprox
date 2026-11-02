// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"strconv"
	"time"
)

// TLS modes.
const (
	TLSModeACME = "acme" // automatic HTTPS with Let's Encrypt
	TLSModeOff  = "off"  // HTTP only (e.g. behind another proxy, or for testing)
)

// Settings are instance-wide options edited on the Settings page.
type Settings struct {
	TLSMode       string `json:"tlsMode"`
	ACMEEmail     string `json:"acmeEmail"`
	ACMEStaging   bool   `json:"acmeStaging"`   // use Let's Encrypt's test servers
	AdminHostname string `json:"adminHostname"` // optional: serve the admin UI on this domain over HTTPS
	AuthHostname  string `json:"authHostname"`  // optional: the sign-in domain for private routes
}

// SignInHostname is the domain where people sign in to private routes: the
// sign-in domain if set, otherwise the dashboard domain. "" means sign-in
// from other devices isn't set up.
func (s Settings) SignInHostname() string {
	if s.AuthHostname != "" {
		return s.AuthHostname
	}
	return s.AdminHostname
}

// DefaultSettings are used for anything not yet saved.
func DefaultSettings() Settings {
	return Settings{TLSMode: TLSModeOff}
}

// GetSettings loads all settings, filling in defaults.
func (s *Store) GetSettings(ctx context.Context) (Settings, error) {
	out := DefaultSettings()
	rows, err := s.db.QueryContext(ctx, "SELECT key, value FROM settings")
	if err != nil {
		return out, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return out, err
		}
		switch k {
		case "tls_mode":
			out.TLSMode = v
		case "acme_email":
			out.ACMEEmail = v
		case "acme_staging":
			out.ACMEStaging, _ = strconv.ParseBool(v)
		case "admin_hostname":
			out.AdminHostname = v
		case "auth_hostname":
			out.AuthHostname = v
		}
	}
	return out, rows.Err()
}

// SaveSettings stores all settings.
func (s *Store) SaveSettings(ctx context.Context, st Settings) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for k, v := range map[string]string{
		"tls_mode":       st.TLSMode,
		"acme_email":     st.ACMEEmail,
		"acme_staging":   strconv.FormatBool(st.ACMEStaging),
		"admin_hostname": st.AdminHostname,
		"auth_hostname":  st.AuthHostname,
	} {
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", k, v); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// AuditEntry records one admin action.
type AuditEntry struct {
	ID     int64     `json:"id"`
	At     time.Time `json:"at"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Detail string    `json:"detail"`
	IP     string    `json:"ip"`
}

// AddAudit appends to the audit log.
func (s *Store) AddAudit(ctx context.Context, e AuditEntry) error {
	_, err := s.db.ExecContext(ctx, "INSERT INTO audit_log (at, actor, action, detail, ip) VALUES (?, ?, ?, ?, ?)",
		now(), e.Actor, e.Action, e.Detail, e.IP)
	return err
}

// ListAudit returns the most recent audit entries, newest first.
func (s *Store) ListAudit(ctx context.Context, limit int) ([]AuditEntry, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id, at, actor, action, detail, ip FROM audit_log ORDER BY id DESC LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		var at int64
		if err := rows.Scan(&e.ID, &at, &e.Actor, &e.Action, &e.Detail, &e.IP); err != nil {
			return nil, err
		}
		e.At = time.Unix(at, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}
