package middleware

import (
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"

	"github.com/finnapigo/finnapigo/internal/response"
)

type CounterStore interface {
	IncrBy(key string, delta int64, ttl time.Duration) int64
}

// visitor pairs a token-bucket limiter with the last time it was seen.
type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// RateLimiter is a per-IP token-bucket limiter with TTL-based eviction.
// Entries that haven't been accessed in entryTTL are periodically purged,
// bounding memory even under sustained traffic from many IPs (§1.3).
type RateLimiter struct {
	mu       sync.Mutex
	visitors map[string]*visitor
	rps      rate.Limit
	burst    int
	entryTTL time.Duration
	shared   CounterStore
	window   time.Duration
	stopCh   chan struct{}
	stopped  bool
}

// NewRateLimiter builds a limiter with the given requests/sec, burst, and
// per-entry TTL. A background sweeper purges stale entries every sweepInterval.
func NewRateLimiter(rps float64, burst int, entryTTL time.Duration, shared ...CounterStore) *RateLimiter {
	window := time.Second
	if rps > 0 && burst > 0 {
		window = time.Duration(float64(time.Second) * float64(burst) / rps)
		if window < time.Second {
			window = time.Second
		}
	}
	rl := &RateLimiter{
		visitors: make(map[string]*visitor),
		rps:      rate.Limit(rps),
		burst:    burst,
		entryTTL: entryTTL,
		window:   window,
		stopCh:   make(chan struct{}),
	}
	if len(shared) > 0 {
		rl.shared = shared[0]
	}
	if entryTTL > 0 {
		go rl.sweepLoop()
	}
	return rl
}

func (rl *RateLimiter) get(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	v, ok := rl.visitors[ip]
	if !ok {
		v = &visitor{limiter: rate.NewLimiter(rl.rps, rl.burst)}
		rl.visitors[ip] = v
	}
	v.lastSeen = time.Now()
	return v.limiter
}

// Handler returns the gin middleware. When the bucket is exhausted it
// responds 429 Too Many Requests.
func (rl *RateLimiter) Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		if rl.shared != nil {
			// Redis INCRBY is atomic across instances. On a store failure the
			// shared counter returns MaxInt64 (fail CLOSED), which lands here
			// as a denial — a Redis outage must not fail open to unlimited
			// traffic.
			if n := rl.shared.IncrBy("rate:ip:"+ip, 1, rl.window); n > 0 {
				if n > int64(rl.burst) {
					response.Respond(c, 429, "too many requests, please slow down", nil)
					c.Abort()
					return
				}
				c.Next()
				return
			}
		}
		if !rl.get(ip).Allow() {
			response.Respond(c, 429, "too many requests, please slow down", nil)
			c.Abort()
			return
		}
		c.Next()
	}
}

// sweepLoop periodically evicts stale entries to bound memory.
func (rl *RateLimiter) sweepLoop() {
	ticker := time.NewTicker(rl.entryTTL / 2) // sweep twice per TTL
	defer ticker.Stop()
	for {
		select {
		case <-rl.stopCh:
			return
		case <-ticker.C:
			rl.sweep()
		}
	}
}

func (rl *RateLimiter) sweep() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	cutoff := time.Now().Add(-rl.entryTTL)
	for ip, v := range rl.visitors {
		if v.lastSeen.Before(cutoff) {
			delete(rl.visitors, ip)
		}
	}
}

// Close stops the background sweeper. Safe to call multiple times.
func (rl *RateLimiter) Close() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if rl.stopped {
		return
	}
	rl.stopped = true
	close(rl.stopCh)
}
