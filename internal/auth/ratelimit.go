// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"sync"
	"time"
)

// Limiter slows down repeated failed attempts (password guessing).
// After freeAttempts failures, each further failure locks the key out for
// twice as long as the last time, up to maxLock.
type Limiter struct {
	mu           sync.Mutex
	entries      map[string]*limitEntry
	freeAttempts int
	baseLock     time.Duration
	maxLock      time.Duration
	forget       time.Duration
	now          func() time.Time
}

type limitEntry struct {
	failures    int
	lockedUntil time.Time
	lastFailure time.Time
}

// NewLimiter returns a limiter with sensible defaults for logins:
// 5 free attempts, then 30s, 1m, 2m, ... up to 1h. Failures are forgotten
// after an hour without new ones.
func NewLimiter() *Limiter {
	return &Limiter{
		entries:      map[string]*limitEntry{},
		freeAttempts: 5,
		baseLock:     30 * time.Second,
		maxLock:      time.Hour,
		forget:       time.Hour,
		now:          time.Now,
	}
}

// Check reports whether key may try now, and if not, how long to wait.
func (l *Limiter) Check(key string) (ok bool, retryAfter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[key]
	if e == nil {
		return true, 0
	}
	now := l.now()
	if now.Sub(e.lastFailure) > l.forget {
		delete(l.entries, key)
		return true, 0
	}
	if now.Before(e.lockedUntil) {
		return false, e.lockedUntil.Sub(now)
	}
	return true, 0
}

// Fail records a failed attempt for key.
func (l *Limiter) Fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	e := l.entries[key]
	if e == nil || now.Sub(e.lastFailure) > l.forget {
		e = &limitEntry{}
		l.entries[key] = e
	}
	e.failures++
	e.lastFailure = now
	if over := e.failures - l.freeAttempts; over > 0 {
		lock := l.baseLock
		for i := 1; i < over && lock < l.maxLock; i++ {
			lock *= 2
		}
		if lock > l.maxLock {
			lock = l.maxLock
		}
		e.lockedUntil = now.Add(lock)
	}
	// Opportunistic cleanup so the map can't grow forever.
	if len(l.entries) > 10000 {
		for k, v := range l.entries {
			if now.Sub(v.lastFailure) > l.forget {
				delete(l.entries, k)
			}
		}
	}
}

// Reset clears key after a successful login.
func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}
