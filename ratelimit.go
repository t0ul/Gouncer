package gouncer

import (
	"sync"
	"time"
)

// limiterSet is a per-client token-bucket rate limiter (stdlib only).
// Buckets refill lazily and stale ones are swept so the map can't grow unbounded.
type limiterSet struct {
	mu      sync.Mutex
	buckets map[string]*tbucket
	rate    float64 // tokens per second
	burst   float64 // bucket capacity
	lastGC  time.Time
}

type tbucket struct {
	tokens float64
	seen   time.Time
}

func newLimiterSet(ratePerSec, burst float64) *limiterSet {
	return &limiterSet{
		buckets: make(map[string]*tbucket),
		rate:    ratePerSec,
		burst:   burst,
		lastGC:  time.Now(),
	}
}

// allow consumes one token for key, returning false when the bucket is empty.
func (l *limiterSet) allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	if now.Sub(l.lastGC) > time.Minute {
		for k, b := range l.buckets {
			if now.Sub(b.seen) > 5*time.Minute {
				delete(l.buckets, k)
			}
		}
		l.lastGC = now
	}

	b := l.buckets[key]
	if b == nil {
		b = &tbucket{tokens: l.burst, seen: now}
		l.buckets[key] = b
	}
	b.tokens += now.Sub(b.seen).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.seen = now
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}
