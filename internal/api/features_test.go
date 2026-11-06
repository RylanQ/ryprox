// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestImportNPM(t *testing.T) {
	e := newEnv(t)
	admin := e.client()
	e.setup(admin)
	admin.post("/api/routes", map[string]any{"hostname": "taken.example.com",
		"config": map[string]any{"targets": []map[string]string{{"url": "http://10.0.0.1"}}}})

	path := filepath.Join(t.TempDir(), "database.sqlite")
	db, err := sql.Open("sqlite3", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`CREATE TABLE proxy_host (id INTEGER PRIMARY KEY, is_deleted INT, domain_names TEXT, forward_scheme TEXT, forward_host TEXT,
			forward_port INT, enabled INT, allow_websocket_upgrade INT, ssl_forced INT, locations TEXT, advanced_config TEXT, access_list_id INT)`,
		`INSERT INTO proxy_host VALUES (1, 0, '["new.example.com","taken.example.com","*.wild.example.com"]', 'http', '10.0.0.5', 8080, 1, 1, 1, '[]', '', 0)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	_ = db.Close()
	raw, _ := os.ReadFile(path)

	req, _ := http.NewRequestWithContext(t.Context(), "POST", e.ts.URL+"/api/import/npm", bytes.NewReader(raw))
	req.Header.Set("X-RyProx", "1")
	resp, err := admin.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out struct {
		Items []struct {
			Route   map[string]any `json:"route"`
			Problem string         `json:"problem"`
		} `json:"items"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode != 200 || len(out.Items) != 3 {
		t.Fatalf("import: %d %+v", resp.StatusCode, out)
	}
	if out.Items[0].Problem != "" || !strings.Contains(out.Items[1].Problem, "already exists") || out.Items[2].Problem == "" {
		t.Fatalf("problems: %+v", out.Items)
	}
	users := out.Items[0].Route["config"].(map[string]any)["access"].(map[string]any)["users"].([]any)
	if len(users) != 1 {
		t.Fatalf("imported route should be private to the importer: %v", users)
	}
	// Junk is refused.
	req, _ = http.NewRequestWithContext(t.Context(), "POST", e.ts.URL+"/api/import/npm", strings.NewReader("not a database"))
	req.Header.Set("X-RyProx", "1")
	resp2, _ := admin.c.Do(req)
	_ = resp2.Body.Close()
	if resp2.StatusCode != 400 {
		t.Fatalf("junk: %d", resp2.StatusCode)
	}
}

func TestCrowdSecSettings(t *testing.T) {
	e := newEnv(t)
	admin := e.client()
	e.setup(admin)
	if code, _ := admin.req("PUT", "/api/crowdsec", map[string]any{"enabled": true, "url": "http://127.0.0.1:1"}, nil); code != 400 {
		t.Fatalf("missing key: %d", code)
	}
	if code, _ := admin.req("PUT", "/api/crowdsec", map[string]any{"enabled": true, "url": "http://127.0.0.1:1", "apiKey": "abc"}, nil); code != 200 {
		t.Fatalf("save: %d", code)
	}
	code, out := admin.req("GET", "/api/crowdsec", nil, nil)
	if code != 200 || out["hasKey"] != true || strings.Contains(strings.ToLower(jsonString(out)), "abc") {
		t.Fatalf("get: %d %v", code, out)
	}
	// Saving again without the key keeps it.
	if code, _ := admin.req("PUT", "/api/crowdsec", map[string]any{"enabled": false, "url": "http://127.0.0.1:1"}, nil); code != 200 {
		t.Fatalf("keep key: %d", code)
	}
}

func jsonString(v any) string { b, _ := json.Marshal(v); return string(b) }
