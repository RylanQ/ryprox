// SPDX-License-Identifier: AGPL-3.0-only

package proxy

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rylanq/ryprox/internal/store"
)

// Health states.
const (
	StateUnknown = "unknown"
	StateUp      = "up"
	StateDown    = "down"
)

// TargetHealth is the shared health record for one target of one route.
type TargetHealth struct {
	mu        sync.Mutex
	state     string
	lastCheck time.Time
	lastError string
	latency   time.Duration
	failUntil atomic.Int64 // unix nanos; set by passive checks
	hours     [historyHours]hourStat
}

// historyHours is how far back uptime is kept (in memory; reset on restart).
const historyHours = 24

type hourStat struct {
	hour     int64 // unix hour this slot holds
	up, down int32
}

func (h *TargetHealth) record(state string, now time.Time) {
	hr := now.Unix() / 3600
	slot := &h.hours[hr%historyHours]
	if slot.hour != hr {
		*slot = hourStat{hour: hr}
	}
	switch state {
	case StateUp:
		slot.up++
	case StateDown:
		slot.down++
	}
}

// history returns uptime per hour, oldest first (-1 where there's no data),
// and the overall uptime across those hours (-1 if no checks ran).
func (h *TargetHealth) history(now time.Time) ([]float64, float64) {
	cur := now.Unix() / 3600
	out := make([]float64, historyHours)
	var up, total int32
	for i := range historyHours {
		hr := cur - int64(historyHours-1-i)
		slot := h.hours[((hr%historyHours)+historyHours)%historyHours]
		n := slot.up + slot.down
		if slot.hour != hr || n == 0 {
			out[i] = -1
			continue
		}
		out[i] = float64(slot.up) / float64(n)
		up += slot.up
		total += n
	}
	if total == 0 {
		return out, -1
	}
	return out, float64(up) / float64(total)
}

// Usable reports whether traffic should be sent to this target.
func (h *TargetHealth) Usable() bool {
	if time.Now().UnixNano() < h.failUntil.Load() {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.state != StateDown
}

// MarkFailed avoids the target for d after a failed request.
func (h *TargetHealth) MarkFailed(d time.Duration) {
	h.failUntil.Store(time.Now().Add(d).UnixNano())
}

func (h *TargetHealth) set(state, errMsg string, latency time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.state, h.lastError, h.latency, h.lastCheck = state, errMsg, latency, time.Now()
	h.record(state, h.lastCheck)
}

// TargetStatus is a snapshot of a target's health for the UI.
type TargetStatus struct {
	URL       string    `json:"url"`
	State     string    `json:"state"`
	LastCheck time.Time `json:"lastCheck"`
	LastError string    `json:"lastError,omitempty"`
	LatencyMs int64     `json:"latencyMs"`
	Uptime    float64   `json:"uptime"`  // last 24 hours, 0–1, or -1 without data
	History   []float64 `json:"history"` // per hour, oldest first, -1 without data
}

func (h *TargetHealth) status(url string) TargetStatus {
	h.mu.Lock()
	defer h.mu.Unlock()
	st := h.state
	if st != StateDown && time.Now().UnixNano() < h.failUntil.Load() {
		st = StateDown
	}
	hist, up := h.history(time.Now())
	return TargetStatus{URL: url, State: st, LastCheck: h.lastCheck, LastError: h.lastError, LatencyMs: h.latency.Milliseconds(), Uptime: up, History: hist}
}

type healthKey struct {
	routeID int64
	url     string
}

type checker struct {
	cancel context.CancelFunc
	spec   string // path + interval + tls; a change restarts the checker
}

// HealthChecker runs background checks for routes that enable them.
type HealthChecker struct {
	mu       sync.Mutex
	records  map[healthKey]*TargetHealth
	checkers map[healthKey]*checker
	routes   map[int64][]string // routeID → target URLs, in order
	log      *slog.Logger
	wg       sync.WaitGroup
}

// NewHealthChecker returns an idle checker.
func NewHealthChecker(log *slog.Logger) *HealthChecker {
	return &HealthChecker{
		records:  map[healthKey]*TargetHealth{},
		checkers: map[healthKey]*checker{},
		routes:   map[int64][]string{},
		log:      log,
	}
}

// Get returns the (shared) health record for a target, creating it if needed.
func (hc *HealthChecker) Get(routeID int64, url string) *TargetHealth {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	k := healthKey{routeID, url}
	h := hc.records[k]
	if h == nil {
		h = &TargetHealth{state: StateUnknown}
		hc.records[k] = h
	}
	return h
}

// Sync starts and stops checkers to match routes.
func (hc *HealthChecker) Sync(routes []store.Route) {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	want := map[healthKey]string{}
	hc.routes = map[int64][]string{}
	for _, r := range routes {
		if !r.Enabled {
			continue
		}
		for _, t := range r.Config.AllTargets() {
			k := healthKey{r.ID, t.URL}
			if contains(hc.routes[r.ID], t.URL) {
				continue
			}
			hc.routes[r.ID] = append(hc.routes[r.ID], t.URL)
			if r.Config.HealthCheck.Enabled {
				want[k] = fmt.Sprintf("%s|%d|%t", r.Config.HealthCheck.Path, r.Config.HealthCheck.IntervalSeconds, r.Config.TLSSkipVerify)
			}
		}
	}
	for k, c := range hc.checkers {
		if spec, ok := want[k]; !ok || spec != c.spec {
			c.cancel()
			delete(hc.checkers, k)
		}
	}
	for k := range hc.records {
		if _, ok := want[k]; !ok {
			if urls, ok := hc.routes[k.routeID]; ok && contains(urls, k.url) {
				// Target still exists but checks are off: state becomes unknown.
				hc.records[k].set(StateUnknown, "", 0)
				continue
			}
			delete(hc.records, k)
		}
	}
	for _, r := range routes {
		if !r.Enabled || !r.Config.HealthCheck.Enabled {
			continue
		}
		for _, t := range r.Config.AllTargets() {
			k := healthKey{r.ID, t.URL}
			if _, running := hc.checkers[k]; running {
				continue
			}
			h := hc.records[k]
			if h == nil {
				h = &TargetHealth{state: StateUnknown}
				hc.records[k] = h
			}
			ctx, cancel := context.WithCancel(context.Background())
			hc.checkers[k] = &checker{cancel: cancel, spec: want[k]}
			hc.wg.Add(1)
			go hc.run(ctx, h, t.URL, r.Config.HealthCheck, r.Config.TLSSkipVerify)
		}
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func (hc *HealthChecker) run(ctx context.Context, h *TargetHealth, target string, cfg store.HealthCheck, skipVerify bool) {
	defer hc.wg.Done()
	client := &http.Client{
		Transport: newTransport(skipVerify),
		Timeout:   5 * time.Second,
		// Don't follow redirects: a redirect still means the service is up.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer client.CloseIdleConnections()
	url := strings.TrimSuffix(target, "/") + cfg.Path
	tick := time.NewTicker(time.Duration(cfg.IntervalSeconds) * time.Second)
	defer tick.Stop()
	for {
		state, msg, lat := probe(ctx, client, url)
		if ctx.Err() != nil {
			return
		}
		h.set(state, msg, lat)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func probe(ctx context.Context, client *http.Client, url string) (string, string, time.Duration) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return StateDown, err.Error(), 0
	}
	req.Header.Set("User-Agent", "RyProx-HealthCheck")
	start := time.Now()
	resp, err := client.Do(req)
	lat := time.Since(start)
	if err != nil {
		return StateDown, err.Error(), lat
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
	if resp.StatusCode >= 500 {
		return StateDown, fmt.Sprintf("HTTP %d", resp.StatusCode), lat
	}
	return StateUp, "", lat
}

// Status returns every target's health, keyed by route ID.
func (hc *HealthChecker) Status() map[int64][]TargetStatus {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	out := map[int64][]TargetStatus{}
	for id, urls := range hc.routes {
		for _, u := range urls {
			if h := hc.records[healthKey{id, u}]; h != nil {
				out[id] = append(out[id], h.status(u))
			}
		}
	}
	return out
}

// Close stops all checkers and waits for them.
func (hc *HealthChecker) Close() {
	hc.mu.Lock()
	for k, c := range hc.checkers {
		c.cancel()
		delete(hc.checkers, k)
	}
	hc.mu.Unlock()
	hc.wg.Wait()
}

// TestTarget makes one request to a target, for the UI's "Test" button.
func TestTarget(ctx context.Context, target string, skipVerify bool) TargetStatus {
	client := &http.Client{
		Transport:     newTransport(skipVerify),
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer client.CloseIdleConnections()
	state, msg, lat := probe(ctx, client, target)
	return TargetStatus{URL: target, State: state, LastError: msg, LatencyMs: lat.Milliseconds(), LastCheck: time.Now(), Uptime: -1}
}
