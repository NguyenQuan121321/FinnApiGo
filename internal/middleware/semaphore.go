package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/finnapigo/finnapigo/internal/response"
)

// ConcurrencyLimiter caps how many requests may run concurrently through a
// route group. It uses a buffered channel as a lightweight counting semaphore:
// a token is taken on entry and released on exit. Crucially, the acquire is
// NON-BLOCKING — when no token is available the request is rejected with 429
// immediately, so a flood of CPU-bound work (e.g. TOTP validations during a
// brute-force/DDoS) cannot queue up and starve the worker pool.
//
// Unlike the token-bucket RateLimiter (which throttles request *rate* per IP),
// this guards *global concurrency* regardless of source IP — the right knob for
// CPU-bound endpoints where the cost is per-validation, not per-client.
type ConcurrencyLimiter struct {
	tokens chan struct{}
}

// NewConcurrencyLimiter builds a limiter that allows at most max concurrent
// requests. max <= 0 returns a no-op limiter (nil limiter is also valid and
// never blocks), so callers can unconditionally install it.
func NewConcurrencyLimiter(max int) *ConcurrencyLimiter {
	if max <= 0 {
		return &ConcurrencyLimiter{} // tokens is nil => Handler is a passthrough
	}
	cl := &ConcurrencyLimiter{tokens: make(chan struct{}, max)}
	for i := 0; i < max; i++ {
		cl.tokens <- struct{}{}
	}
	return cl
}

// Handler returns the gin middleware. When the semaphore is exhausted it
// responds 429 Too Many Requests without entering the handler — protecting the
// downstream service and DB pool from saturation. A nil/empty limiter is a
// pure passthrough (used when the gate is disabled in config / tests).
func (cl *ConcurrencyLimiter) Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		if cl == nil || cl.tokens == nil {
			c.Next()
			return
		}
		// Non-blocking acquire: prefer rejecting over queuing under load.
		select {
		case <-cl.tokens:
			defer func() { cl.tokens <- struct{}{} }()
			c.Next()
		default:
			response.Respond(c, http.StatusTooManyRequests, "server busy, please retry shortly", nil)
			c.Abort()
		}
	}
}

// Available reports how many tokens are free right now. Primarily for
// observability / tests; do not use it for admission decisions (use Handler).
func (cl *ConcurrencyLimiter) Available() int {
	if cl == nil || cl.tokens == nil {
		return -1
	}
	return len(cl.tokens)
}

// Capacity reports the configured max concurrency, or -1 when disabled.
func (cl *ConcurrencyLimiter) Capacity() int {
	if cl == nil || cl.tokens == nil {
		return -1
	}
	return cap(cl.tokens)
}
