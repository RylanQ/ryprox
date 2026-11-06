// SPDX-License-Identifier: AGPL-3.0-only

package importer

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/rylanq/ryprox/internal/store"
)

func TestNPM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "database.sqlite")
	db, err := sql.Open("sqlite3", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`CREATE TABLE proxy_host (id INTEGER PRIMARY KEY, is_deleted INT, domain_names TEXT, forward_scheme TEXT, forward_host TEXT,
			forward_port INT, enabled INT, allow_websocket_upgrade INT, ssl_forced INT, locations TEXT, advanced_config TEXT, access_list_id INT)`,
		`CREATE TABLE redirection_host (id INTEGER PRIMARY KEY, is_deleted INT, domain_names TEXT, forward_scheme TEXT,
			forward_domain_name TEXT, preserve_path INT, forward_http_code INT, enabled INT)`,
		`INSERT INTO proxy_host VALUES (1, 0, '["app.example.com","APP2.example.com"]', 'http', '10.0.0.5/sub', 8080, 1, 1, 1,
			'[{"path":"/api/","forward_scheme":"https","forward_host":"10.0.0.6","forward_port":"9443","advanced_config":""}]', 'proxy_buffering off;', 3)`,
		`INSERT INTO proxy_host VALUES (2, 1, '["deleted.example.com"]', 'http', 'x', 80, 1, 0, 0, NULL, NULL, 0)`,
		`INSERT INTO redirection_host VALUES (1, 0, '["www.example.com"]', 'auto', 'example.com', 1, 302, 1)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(q, err)
		}
	}
	_ = db.Close()

	got, err := NPM(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d proposals: %+v", len(got), got)
	}
	a := got[0].Route
	if a.Hostname != "app.example.com" || a.Config.Targets[0].URL != "http://10.0.0.5:8080/sub" || !a.Config.Websockets ||
		a.Config.Access.Mode != store.AccessPrivate || a.Config.Paths[0].Prefix != "/api" || a.Config.Paths[0].Targets[0].URL != "https://10.0.0.6:9443" {
		t.Fatalf("proxy host: %+v", a)
	}
	if len(got[0].Notes) != 2 {
		t.Fatalf("notes: %v", got[0].Notes)
	}
	r := got[2].Route
	if r.Hostname != "www.example.com" || r.Config.Redirect.To != "https://example.com" || r.Config.Redirect.Code != 302 || !r.Config.Redirect.KeepPath {
		t.Fatalf("redirect: %+v", r)
	}
	if _, err := NPM(t.Context(), filepath.Join(t.TempDir(), "nothing.sqlite")); err == nil {
		t.Fatal("missing file accepted")
	}
}
