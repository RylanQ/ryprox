// SPDX-License-Identifier: AGPL-3.0-only

package proxy

import (
	"net"
	"sync"
	"time"
)

// rateLimiter allows a fixed number of requests per address per minute.
// It uses a sliding estimate over two one-minute windows, which smooths the
// burst a plain fixed window would allow at each minute boundary.
type rateLimiter struct {
	limit int
	mu    sync.Mutex
	cur   map[string]int
	prev  map[string]int
	start time.Time
	now   func() time.Time
}

// maxTracked bounds memory if a flood comes from many addresses.
const maxTracked = 100_000

func newRateLimiter(perMinute int) *rateLimiter {
	return &rateLimiter{limit: perMinute, cur: map[string]int{}, prev: map[string]int{}, now: time.Now}
}

func (l *rateLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	switch el := now.Sub(l.start); {
	case el >= 2*time.Minute:
		l.prev, l.cur, l.start = map[string]int{}, map[string]int{}, now.Truncate(time.Minute)
	case el >= time.Minute:
		l.prev, l.cur, l.start = l.cur, map[string]int{}, l.start.Add(time.Minute)
	}
	weight := 1 - float64(now.Sub(l.start))/float64(time.Minute)
	est := float64(l.prev[key])*weight + float64(l.cur[key])
	if est >= float64(l.limit) {
		return false
	}
	if len(l.cur) >= maxTracked {
		// Under a flood from very many addresses, start counting afresh
		// rather than locking out everyone new.
		l.cur = map[string]int{}
	}
	l.cur[key]++
	return true
}

// clientKey identifies a visitor for rate limiting: the IPv4 address, or
// the /64 network for IPv6 (one home or server usually owns a whole /64).
func clientKey(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return host
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}
