// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/rylanq/ryprox/internal/auth"
	"github.com/rylanq/ryprox/internal/certs"
	"github.com/rylanq/ryprox/internal/cluster"
	"github.com/rylanq/ryprox/internal/proxy"
	"github.com/rylanq/ryprox/internal/secrets"
	"github.com/rylanq/ryprox/internal/store"
)

func TestFollower(t *testing.T) {
	// The primary, with its sign-in domain served over TLS.
	p := newEnv(t)
	admin := p.client()
	p.setup(admin)
	p.enableSignIn()
	ts := httptest.NewTLSServer(p.srv.SignInHandler())
	t.Cleanup(ts.Close)
	if err := os.MkdirAll(filepath.Join(p.srv.DataDir, "certs", "letsencrypt"), 0o700); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(p.srv.DataDir, "certs", "letsencrypt", "app.example.com"), []byte("CERT"), 0o600)
	admin.post("/api/routes", map[string]any{"hostname": "app.example.com", "enabled": true,
		"config": map[string]any{"targets": []map[string]string{{"url": "http://10.0.0.1"}}}})
	code, out := admin.post("/api/nodes", map[string]string{"name": "backup"})
	if code != 201 {
		t.Fatalf("create node: %d %v", code, out)
	}
	token := out["token"].(string)

	// The follower: an empty server.
	dir := t.TempDir()
	st, err := store.Open(t.Context(), filepath.Join(dir, "ryprox.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	addr := ts.Listener.Addr().String()
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test server
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		},
	}}
	f := &cluster.Follower{Primary: "https://" + signInHost, Token: token, DataDir: dir, Store: st, Log: slog.New(slog.DiscardHandler), HTTPClient: client}
	if err := f.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	// Same secret key, configuration and certificates.
	k1, _ := os.ReadFile(filepath.Join(p.srv.DataDir, "secret.key"))
	k2, _ := os.ReadFile(filepath.Join(dir, "secret.key"))
	if !bytes.Equal(k1, k2) {
		t.Fatal("secret key not copied")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "certs", "letsencrypt", "app.example.com")); string(b) != "CERT" {
		t.Fatal("certificate not copied")
	}
	routes, _ := st.ListRoutes(t.Context())
	if len(routes) != 1 || routes[0].Hostname != "app.example.com" {
		t.Fatalf("routes: %+v", routes)
	}
	u, err := st.GetUserByUsername(t.Context(), "admin")
	if err != nil || len(u.PasswordHash) == 0 {
		t.Fatalf("admin not copied: %v", err)
	}

	// A server built on the follower's data: sign-in works, changes don't.
	box, _ := secrets.LoadOrCreate(filepath.Join(dir, "secret.key"))
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	eng := proxy.NewEngine(log)
	t.Cleanup(eng.Close)
	fs := &Server{Store: st, Engine: eng, Box: box, Log: log, DataDir: dir, Follower: f, UI: p.srv.UI}
	fs.Certs = certs.New(filepath.Join(dir, "certs"), func(string) bool { return false }, log)
	if _, err := New(t.Context(), fs); err != nil {
		t.Fatal(err)
	}
	if err := fs.Reload(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !eng.HasHost("app.example.com") {
		t.Fatal("follower doesn't serve the route")
	}
	fts := httptest.NewServer(fs.Handler())
	t.Cleanup(fts.Close)
	fe := &env{t: t, srv: fs, ts: fts, engine: eng}
	fc := fe.client()
	totp, _ := auth.TOTPCodeAt(p.setupSecret, time.Now().Add(30*time.Second))
	if code, out := loginAs(t, fc, "admin", pw, totp); code != 200 {
		t.Fatalf("follower login: %d %v", code, out)
	}
	if code, _ := fc.req("GET", "/api/routes", nil, nil); code != 200 {
		t.Fatal("follower can't read")
	}
	if code, out := fc.post("/api/routes", map[string]any{"hostname": "x.example.com",
		"config": map[string]any{"targets": []map[string]string{{"url": "http://10.0.0.2"}}}}); code != http.StatusConflict {
		t.Fatalf("follower accepted a change: %d %v", code, out)
	}
	_, state := fc.req("GET", "/api/state", nil, nil)
	if state["follower"] == nil {
		t.Fatal("state doesn't say this is a follower")
	}

	// Local sessions survive the next sync; nothing changed means 304.
	f.HTTPClient = client
	if err := f.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	if code, _ := fc.req("GET", "/api/routes", nil, nil); code != 200 {
		t.Fatal("follower session lost after sync")
	}
	// A change on the primary arrives.
	admin.post("/api/routes", map[string]any{"hostname": "new.example.com", "enabled": true,
		"config": map[string]any{"targets": []map[string]string{{"url": "http://10.0.0.3"}}}})
	if err := f.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	routes, _ = st.ListRoutes(t.Context())
	if len(routes) != 2 {
		t.Fatalf("change not mirrored: %d routes", len(routes))
	}

	// A deleted node can't sync; bad tokens are refused.
	_, list := admin.req("GET", "/api/nodes", nil, nil)
	id := int64(list["nodes"].([]any)[0].(map[string]any)["id"].(float64))
	admin.req("DELETE", "/api/nodes/"+strconv.FormatInt(id, 10), nil, nil)
	f2 := &cluster.Follower{Primary: f.Primary, Token: token, DataDir: t.TempDir(), Store: st, Log: f.Log, HTTPClient: client}
	if err := f2.Sync(t.Context()); err == nil {
		t.Fatal("deleted node still syncs")
	}
}
