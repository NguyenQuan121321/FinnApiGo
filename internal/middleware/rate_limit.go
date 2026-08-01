package middleware

import (
	"sync"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"

	"github.com/finnapigo/finnapigo/internal/utils"
)

// RateLimiter is a per-IP token-bucket limiter. It protects brute-force-prone
// endpoints (/login, /mfa/send-otp) from a single IP flooding requests.
type RateLimiter struct {
	mu       sync.Mutex
	visitors map[string]*rate.Limiter
	rps      rate.Limit
	burst    int
}

// NewRateLimiter builds a limiter with the given requests/sec and burst.
func NewRateLimiter(rps float64, burst int) *RateLimiter {
	return &RateLimiter{
		visitors: make(map[string]*rate.Limiter),
		rps:      rate.Limit(rps),
		burst:    burst,
	}
}

func (rl *RateLimiter) get(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if l, ok := rl.visitors[ip]; ok {
		return l
	}
	l := rate.NewLimiter(rl.rps, rl.burst)
	rl.visitors[ip] = l
	return l
}

// Handler returns the gin middleware. When the bucket is exhausted it
// responds 429 Too Many Requests.
func (rl *RateLimiter) Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		if !rl.get(ip).Allow() {
			utils.Respond(c, 429, "too many requests, please slow down", nil)
			c.Abort()
			return
		}
		c.Next()
	}
}
