// SPDX-License-Identifier: AGPL-3.0-only

// Package importer reads other reverse proxies' configuration and turns it
// into RyProx routes for the admin to review before saving.
package importer

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	_ "github.com/ncruces/go-sqlite3/driver" // the "sqlite3" driver

	"github.com/rylanq/ryprox/internal/store"
)

// Proposal is one route to create, with notes about anything that couldn't
// be carried over.
type Proposal struct {
	Route store.Route `json:"route"`
	Notes []string    `json:"notes"`
	From  string      `json:"from"`
}

// NPM reads an Nginx Proxy Manager database (data/database.sqlite) and
// proposes routes for its proxy hosts and redirection hosts. The file is
// opened read-only with untrusted schema features turned off.
func NPM(ctx context.Context, path string) ([]Proposal, error) {
	dsn := "file:" + url.PathEscape(path) + "?mode=ro&_pragma=query_only(1)&_pragma=trusted_schema(0)"
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)

	var out []Proposal
	proxies, err := npmProxyHosts(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("this doesn't look like a Nginx Proxy Manager database: %w", err)
	}
	out = append(out, proxies...)
	redirects, err := npmRedirects(ctx, db)
	if err == nil { // older versions may lack the table
		out = append(out, redirects...)
	}
	return out, nil
}

func domains(raw string) []string {
	var d []string
	_ = json.Unmarshal([]byte(raw), &d)
	return d
}

// target builds "scheme://host:port[/path]" from NPM's fields. NPM lets the
// host field carry a path, e.g. "10.0.0.5/app".
func target(scheme, host string, port int) string {
	if scheme != "https" {
		scheme = "http"
	}
	host = strings.TrimSpace(host)
	path := ""
	if i := strings.IndexByte(host, '/'); i >= 0 {
		host, path = host[:i], host[i:]
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return scheme + "://" + host + ":" + strconv.Itoa(port) + strings.TrimSuffix(path, "/")
}

type npmLocation struct {
	Path           string `json:"path"`
	ForwardScheme  string `json:"forward_scheme"`
	ForwardHost    string `json:"forward_host"`
	ForwardPort    any    `json:"forward_port"`
	AdvancedConfig string `json:"advanced_config"`
}

func portOf(v any) int {
	switch p := v.(type) {
	case float64:
		return int(p)
	case string:
		n, _ := strconv.Atoi(p)
		return n
	}
	return 0
}

func npmProxyHosts(ctx context.Context, db *sql.DB) ([]Proposal, error) {
	rows, err := db.QueryContext(ctx, `SELECT id, domain_names, forward_scheme, forward_host, forward_port,
		enabled, allow_websocket_upgrade, ssl_forced, COALESCE(locations, '[]'), COALESCE(advanced_config, ''), access_list_id
		FROM proxy_host WHERE is_deleted = 0`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Proposal
	for rows.Next() {
		var (
			id, port, accessList           int
			doms, scheme, host, locs, adv  string
			enabled, websockets, sslForced bool
		)
		if err := rows.Scan(&id, &doms, &scheme, &host, &port, &enabled, &websockets, &sslForced, &locs, &adv, &accessList); err != nil {
			return nil, err
		}
		cfg := store.RouteConfig{
			Kind:          store.KindProxy,
			Targets:       []store.Target{{URL: target(scheme, host, port)}},
			Websockets:    websockets,
			HTTPSRedirect: true,
			PreserveHost:  true, // nginx passes the visitor's Host by default
			Access:        store.Access{Mode: store.AccessPrivate},
		}
		var notes []string
		var locations []npmLocation
		_ = json.Unmarshal([]byte(locs), &locations)
		for _, l := range locations {
			p := strings.TrimSpace(l.Path)
			if p == "" || p == "/" {
				continue
			}
			cfg.Paths = append(cfg.Paths, store.PathRule{Prefix: strings.TrimSuffix(p, "/"),
				Targets: []store.Target{{URL: target(l.ForwardScheme, l.ForwardHost, portOf(l.ForwardPort))}}})
			if strings.TrimSpace(l.AdvancedConfig) != "" {
				notes = append(notes, "custom nginx settings on "+p+" weren't copied")
			}
		}
		if strings.TrimSpace(adv) != "" {
			notes = append(notes, "custom nginx settings weren't copied")
		}
		if accessList != 0 {
			notes = append(notes, "its access list wasn't copied; choose who can open it instead")
		}
		for _, d := range domains(doms) {
			if strings.Contains(d, "*") {
				notes := append([]string{"wildcard domains aren't supported yet"}, notes...)
				out = append(out, Proposal{Route: store.Route{Hostname: d, Enabled: false, Config: cfg}, Notes: notes, From: fmt.Sprintf("proxy host #%d", id)})
				continue
			}
			out = append(out, Proposal{Route: store.Route{Hostname: d, Enabled: enabled, Config: cfg}, Notes: notes, From: fmt.Sprintf("proxy host #%d", id)})
		}
	}
	return out, rows.Err()
}

func npmRedirects(ctx context.Context, db *sql.DB) ([]Proposal, error) {
	rows, err := db.QueryContext(ctx, `SELECT id, domain_names, forward_scheme, forward_domain_name, preserve_path,
		forward_http_code, enabled FROM redirection_host WHERE is_deleted = 0`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Proposal
	for rows.Next() {
		var (
			id, code           int
			doms, scheme, dest string
			preserve, enabled  bool
		)
		if err := rows.Scan(&id, &doms, &scheme, &dest, &preserve, &code, &enabled); err != nil {
			return nil, err
		}
		if scheme != "http" {
			scheme = "https" // "auto" and "https"
		}
		switch code {
		case 301, 302, 307, 308:
		default:
			code = 301
		}
		cfg := store.RouteConfig{Kind: store.KindRedirect, HTTPSRedirect: true,
			Redirect: store.Redirect{To: scheme + "://" + strings.TrimSuffix(dest, "/"), Code: code, KeepPath: preserve},
			// Redirects are usually meant for everyone (www → bare domain).
			Access: store.Access{Mode: store.AccessPublic}}
		for _, d := range domains(doms) {
			out = append(out, Proposal{Route: store.Route{Hostname: d, Enabled: enabled, Config: cfg},
				From: fmt.Sprintf("redirection host #%d", id)})
		}
	}
	return out, rows.Err()
}
