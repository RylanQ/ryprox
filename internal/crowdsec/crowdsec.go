// SPDX-License-Identifier: AGPL-3.0-only

// Package crowdsec is a CrowdSec bouncer: it keeps a local copy of the
// decisions (bans) from a CrowdSec Local API and blocks matching visitors
// before their request reaches any site or the sign-in page.
//
// It uses the LAPI's stream endpoint, so lookups are in memory and never
// wait on the network. If the LAPI is unreachable the last known decisions
// keep applying.
package crowdsec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Config is set from the dashboard.
type Config struct {
	Enabled bool   `json:"enabled"`
	URL     string `json:"url"`    // e.g. http://127.0.0.1:8080
	APIKey  string `json:"apiKey"` // bouncer key from `cscli bouncers add ryprox`
}

// Status is shown in the dashboard.
type Status struct {
	Enabled   bool      `json:"enabled"`
	Connected bool      `json:"connected"`
	Decisions int       `json:"decisions"`
	LastSync  time.Time `json:"lastSync"`
	LastError string    `json:"lastError,omitempty"`
	Blocked   int64     `json:"blocked"` // requests blocked since start
}

type decision struct {
	Value    string `json:"value"`
	Scope    string `json:"scope"`
	Type     string `json:"type"`
	Duration string `json:"duration"`
}

type streamResponse struct {
	New     []decision `json:"new"`
	Deleted []decision `json:"deleted"`
}

// table is an immutable set of decisions swapped atomically.
type table struct {
	ips      map[netip.Addr]time.Time
	prefixes map[netip.Prefix]time.Time
}

func (t *table) blocked(a netip.Addr, now time.Time) bool {
	if t == nil {
		return false
	}
	a = a.Unmap()
	if exp, ok := t.ips[a]; ok && now.Before(exp) {
		return true
	}
	for p, exp := range t.prefixes {
		if p.Contains(a) && now.Before(exp) {
			return true
		}
	}
	return false
}

// Bouncer syncs decisions in the background.
type Bouncer struct {
	log     *slog.Logger
	client  *http.Client
	tab     atomic.Pointer[table]
	blocked atomic.Int64

	mu     sync.Mutex
	cfg    Config
	cancel context.CancelFunc
	status Status
	done   chan struct{}

	// Interval between stream polls (tests shorten it).
	Interval time.Duration
}

// New returns an idle bouncer.
func New(log *slog.Logger) *Bouncer {
	return &Bouncer{log: log, client: &http.Client{Timeout: 15 * time.Second}, Interval: 10 * time.Second}
}

// Check validates a configuration.
func Check(c Config) error {
	if !c.Enabled {
		return nil
	}
	u, err := url.Parse(c.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return errors.New("enter the Local API address, like http://127.0.0.1:8080")
	}
	if c.APIKey == "" || len(c.APIKey) > 200 || strings.ContainsAny(c.APIKey, "\r\n ") {
		return errors.New("enter the bouncer API key from `cscli bouncers add ryprox`")
	}
	return nil
}

// Configure starts, restarts or stops syncing.
func (b *Bouncer) Configure(c Config) {
	b.mu.Lock()
	if b.cancel != nil {
		b.cancel()
		done := b.done
		b.mu.Unlock()
		<-done
		b.mu.Lock()
	}
	b.cfg = c
	b.cancel = nil
	b.status = Status{Enabled: c.Enabled}
	if !c.Enabled {
		b.tab.Store(nil)
		b.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	b.cancel, b.done = cancel, make(chan struct{})
	done := b.done
	b.mu.Unlock()
	go b.run(ctx, c, done)
}

// Close stops syncing.
func (b *Bouncer) Close() { b.Configure(Config{}) }

// Status reports the current state.
func (b *Bouncer) Status() Status {
	b.mu.Lock()
	defer b.mu.Unlock()
	st := b.status
	st.Blocked = b.blocked.Load()
	if t := b.tab.Load(); t != nil {
		st.Decisions = len(t.ips) + len(t.prefixes)
	}
	return st
}

// Blocked reports whether a request's address is banned. remoteAddr is
// http.Request.RemoteAddr.
func (b *Bouncer) Blocked(remoteAddr string) bool {
	t := b.tab.Load()
	if t == nil {
		return false
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	if t.blocked(a, time.Now()) {
		b.blocked.Add(1)
		return true
	}
	return false
}

// Middleware blocks banned visitors.
func (b *Bouncer) Middleware(next http.Handler, deny func(http.ResponseWriter)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if b.Blocked(r.RemoteAddr) {
			deny(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (b *Bouncer) run(ctx context.Context, c Config, done chan struct{}) {
	defer close(done)
	startup := true
	cur := &table{ips: map[netip.Addr]time.Time{}, prefixes: map[netip.Prefix]time.Time{}}
	for {
		resp, err := b.poll(ctx, c, startup)
		b.mu.Lock()
		if err != nil {
			if ctx.Err() == nil {
				b.status.Connected, b.status.LastError = false, err.Error()
				b.log.Warn("crowdsec sync failed", "err", err)
			}
		} else {
			if startup {
				cur = &table{ips: map[netip.Addr]time.Time{}, prefixes: map[netip.Prefix]time.Time{}}
			}
			cur = apply(cur, resp, time.Now())
			b.tab.Store(cur)
			startup = false
			b.status.Connected, b.status.LastError, b.status.LastSync = true, "", time.Now()
		}
		b.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-time.After(b.Interval):
		}
	}
}

func (b *Bouncer) poll(ctx context.Context, c Config, startup bool) (*streamResponse, error) {
	u := strings.TrimSuffix(c.URL, "/") + "/v1/decisions/stream?startup=" + fmt.Sprint(startup)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Api-Key", c.APIKey)
	req.Header.Set("User-Agent", "ryprox-bouncer")
	resp, err := b.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		return nil, errors.New("the API key was refused")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("local API answered HTTP %d", resp.StatusCode)
	}
	var out streamResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256<<20)).Decode(&out); err != nil {
		return nil, fmt.Errorf("reading decisions: %w", err)
	}
	return &out, nil
}

// apply returns a new table with the stream's changes. Bans and captchas
// both block (RyProx can't show a captcha).
func apply(old *table, s *streamResponse, now time.Time) *table {
	t := &table{ips: make(map[netip.Addr]time.Time, len(old.ips)), prefixes: make(map[netip.Prefix]time.Time, len(old.prefixes))}
	for k, v := range old.ips {
		if now.Before(v) {
			t.ips[k] = v
		}
	}
	for k, v := range old.prefixes {
		if now.Before(v) {
			t.prefixes[k] = v
		}
	}
	for _, d := range s.Deleted {
		if a, p, ok := parse(d); ok {
			if p.IsValid() {
				delete(t.prefixes, p)
			} else {
				delete(t.ips, a)
			}
		}
	}
	for _, d := range s.New {
		if !strings.EqualFold(d.Type, "ban") && !strings.EqualFold(d.Type, "captcha") {
			continue
		}
		dur, err := time.ParseDuration(d.Duration)
		if err != nil || dur <= 0 {
			dur = 4 * time.Hour
		}
		exp := now.Add(dur)
		if a, p, ok := parse(d); ok {
			if p.IsValid() {
				if exp.After(t.prefixes[p]) {
					t.prefixes[p] = exp
				}
			} else if exp.After(t.ips[a]) {
				t.ips[a] = exp
			}
		}
	}
	return t
}

func parse(d decision) (netip.Addr, netip.Prefix, bool) {
	switch strings.ToLower(d.Scope) {
	case "ip":
		a, err := netip.ParseAddr(d.Value)
		return a.Unmap(), netip.Prefix{}, err == nil
	case "range":
		p, err := netip.ParsePrefix(d.Value)
		if err != nil {
			return netip.Addr{}, netip.Prefix{}, false
		}
		return netip.Addr{}, p.Masked(), true
	}
	return netip.Addr{}, netip.Prefix{}, false
}
