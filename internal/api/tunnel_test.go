// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rylanq/ryprox/internal/tunnel"
)

// tunnelEnv serves the sign-in domain over TLS so agents can connect.
func tunnelEnv(t *testing.T) (*env, *client, *httptest.Server) {
	e := newEnv(t)
	admin := e.client()
	e.setup(admin)
	e.enableSignIn()
	hub := tunnel.NewHub(slog.New(slog.DiscardHandler))
	e.srv.Tunnels = hub
	e.engine.SetTunnels(hub)
	ts := httptest.NewTLSServer(e.srv.SignInHandler())
	t.Cleanup(ts.Close)
	return e, admin, ts
}

func startAgent(t *testing.T, ts *httptest.Server, token string, allow []string) context.CancelFunc {
	addr := ts.Listener.Addr().String()
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test server
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		},
	}}
	ctx, cancel := context.WithCancel(context.Background())
	a := &tunnel.Agent{Server: "https://" + signInHost, Token: token, Allow: allow, Log: slog.New(slog.DiscardHandler), HTTPClient: client}
	go func() { _ = a.Run(ctx) }()
	t.Cleanup(cancel)
	return cancel
}

func waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	for i := 0; i < 300; i++ {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out")
}

func TestTunnel(t *testing.T) {
	e, admin, ts := tunnelEnv(t)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "hello from home %s", r.URL.Path)
	}))
	defer backend.Close()

	code, out := admin.post("/api/sites", map[string]string{"name": "Home"})
	if code != 201 || !strings.HasPrefix(out["token"].(string), "ryt_") {
		t.Fatalf("create site: %d %v", code, out)
	}
	siteID := int64(out["site"].(map[string]any)["id"].(float64))
	token := out["token"].(string)

	code, out = admin.post("/api/routes", map[string]any{"hostname": "home.example.com", "enabled": true,
		"config": map[string]any{"access": map[string]any{"mode": "public"},
			"targets": []map[string]any{{"url": backend.URL, "site": siteID}}}})
	if code != 201 {
		t.Fatalf("route: %d %v", code, out)
	}
	// Offline: a clear error, not a direct connection.
	if rec := e.site("GET", "home.example.com", "/x", "", visitor); rec.Code != http.StatusBadGateway {
		t.Fatalf("offline: %d %s", rec.Code, rec.Body.String())
	}

	// Only addresses the agent allows can be reached.
	stopDenying := startAgent(t, ts, token, []string{"10.0.0.0/8"})
	waitUntil(t, func() bool { return e.srv.Tunnels.Online(siteID) })
	if rec := e.site("GET", "home.example.com", "/x", "", visitor); rec.Code != http.StatusBadGateway {
		t.Fatalf("outside --allow: %d", rec.Code)
	}
	stopDenying()
	waitUntil(t, func() bool { return !e.srv.Tunnels.Online(siteID) })

	// Two agents: requests go through, and keep working when one stops.
	stop1 := startAgent(t, ts, token, []string{"127.0.0.0/8"})
	startAgent(t, ts, token, nil)
	waitUntil(t, func() bool { return len(e.srv.Tunnels.Status()[siteID]) == 2 })
	for i := 0; i < 4; i++ {
		rec := e.site("GET", "home.example.com", fmt.Sprintf("/p%d", i), "", visitor)
		if rec.Code != 200 || rec.Body.String() != fmt.Sprintf("hello from home /p%d", i) {
			t.Fatalf("through tunnel: %d %s", rec.Code, rec.Body.String())
		}
	}
	stop1()
	waitUntil(t, func() bool { return len(e.srv.Tunnels.Status()[siteID]) == 1 })
	if rec := e.site("GET", "home.example.com", "/after", "", visitor); rec.Code != 200 {
		t.Fatalf("after one agent stopped: %d", rec.Code)
	}

	// The site can't be deleted while used; a new token disconnects agents.
	if code, _ := admin.req("DELETE", fmt.Sprintf("/api/sites/%d", siteID), nil, nil); code != 409 {
		t.Fatalf("delete in use: %d", code)
	}
	if code, _ := admin.post(fmt.Sprintf("/api/sites/%d/token", siteID), map[string]any{}); code != 200 {
		t.Fatal("new token")
	}
	waitUntil(t, func() bool { return !e.srv.Tunnels.Online(siteID) })
}

func TestTunnelNeedsToken(t *testing.T) {
	_, _, ts := tunnelEnv(t)
	req, _ := http.NewRequestWithContext(t.Context(), "GET", ts.URL+"/.ryprox/tunnel", nil)
	req.Host = signInHost
	req.Header.Set("Authorization", "Bearer ryt_wrong")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad token: %d", resp.StatusCode)
	}
}

func TestAllowList(t *testing.T) {
	// A route referring to a missing site is refused.
	e := newEnv(t)
	admin := e.client()
	e.setup(admin)
	code, _ := admin.post("/api/routes", map[string]any{"hostname": "x.example.com",
		"config": map[string]any{"targets": []map[string]any{{"url": "http://10.0.0.1", "site": 99}}}})
	if code != 400 {
		t.Fatalf("missing site: %d", code)
	}
}
