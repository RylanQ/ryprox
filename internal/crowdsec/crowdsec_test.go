// SPDX-License-Identifier: AGPL-3.0-only

package crowdsec

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestBouncerSync(t *testing.T) {
	var mu sync.Mutex
	calls := []string{}
	next := streamResponse{New: []decision{
		{Value: "203.0.113.5", Scope: "Ip", Type: "ban", Duration: "4h"},
		{Value: "198.51.100.0/24", Scope: "Range", Type: "ban", Duration: "1h"},
		{Value: "192.0.2.9", Scope: "Ip", Type: "throttle", Duration: "1h"},
		{Value: "AS1234", Scope: "AS", Type: "ban", Duration: "1h"},
	}}
	lapi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != "k" {
			w.WriteHeader(403)
			return
		}
		mu.Lock()
		calls = append(calls, r.URL.Query().Get("startup"))
		resp := next
		next = streamResponse{}
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer lapi.Close()

	b := New(slog.New(slog.NewTextHandler(io.Discard, nil)))
	b.Interval = 20 * time.Millisecond
	b.Configure(Config{Enabled: true, URL: lapi.URL, APIKey: "k"})
	defer b.Close()
	waitFor(t, func() bool { return b.Status().Decisions == 2 })

	cases := map[string]bool{
		"203.0.113.5:1234": true, "198.51.100.77:80": true, "[::ffff:203.0.113.5]:1": true,
		"203.0.113.6:1": false, "192.0.2.9:1": false, "garbage": false,
	}
	for addr, want := range cases {
		if got := b.Blocked(addr); got != want {
			t.Errorf("%s: blocked=%v", addr, got)
		}
	}
	mu.Lock()
	next = streamResponse{Deleted: []decision{{Value: "203.0.113.5", Scope: "Ip", Type: "ban"}}}
	mu.Unlock()
	waitFor(t, func() bool { return !b.Blocked("203.0.113.5:1") })
	mu.Lock()
	if calls[0] != "true" || calls[1] != "false" {
		t.Errorf("startup flags %v", calls)
	}
	mu.Unlock()

	// A wrong key is reported, and turning off clears the bans.
	b.Configure(Config{Enabled: true, URL: lapi.URL, APIKey: "wrong"})
	waitFor(t, func() bool { return b.Status().LastError != "" })
	b.Configure(Config{})
	if b.Blocked("198.51.100.77:80") {
		t.Fatal("still blocking after turning off")
	}
}

func TestExpiry(t *testing.T) {
	now := time.Now()
	tab := apply(&table{ips: nil, prefixes: nil}, &streamResponse{New: []decision{{Value: "10.0.0.1", Scope: "ip", Type: "ban", Duration: "1s"}}}, now)
	a := mustAddr("10.0.0.1")
	if !tab.blocked(a, now) || tab.blocked(a, now.Add(2*time.Second)) {
		t.Fatal("expiry not honoured")
	}
}

func TestCheck(t *testing.T) {
	if Check(Config{Enabled: true, URL: "ftp://x", APIKey: "k"}) == nil || Check(Config{Enabled: true, URL: "http://x:8080"}) == nil {
		t.Fatal("bad config accepted")
	}
	if Check(Config{Enabled: true, URL: "http://127.0.0.1:8080", APIKey: "k"}) != nil {
		t.Fatal("good config refused")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out")
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }
