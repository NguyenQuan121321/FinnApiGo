package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// CORS is a strict allowlist middleware for browser clients. An Origin that
// matches the configured list gets the standard ACAO headers; anything else
// gets NO CORS headers at all (the browser blocks the response — the server
// never reflects an unlisted origin, which is what makes wildcard-reflect
// misconfigurations dangerous). Empty list = zero CORS behavior, exactly the
// pre-middleware deployment posture (native clients / Bruno are unaffected:
// they don't send Origin and don't enforce CORS).
//
// Credentials are deliberately NOT granted (no Allow-Credentials): this API
// authenticates with the Authorization header, not cookies, so a stolen-token
// CSRF-via-CORS channel is not worth opening.
func CORS(allowedOrigins []string) gin.HandlerFunc {
	allowed := make(map[string]struct{}, len(allowedOrigins))
	for _, o := range allowedOrigins {
		if trimmed := strings.TrimRight(strings.TrimSpace(o), "/"); trimmed != "" {
			allowed[strings.TrimRight(trimmed, "/")] = struct{}{}
		}
	}
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin == "" {
			c.Next() // non-browser or same-origin request — nothing to do
			return
		}
		if _, ok := allowed[strings.TrimRight(origin, "/")]; !ok {
			c.Next() // unlisted origin: pass through without CORS headers
			return
		}
		c.Header("Vary", "Origin")
		c.Header("Access-Control-Allow-Origin", origin)
		// Preflight: OPTIONS + Access-Control-Request-Method. Short-circuit
		// here — the OPTIONS request has no route of its own (all API verbs
		// are POST/GET/DELETE) and must never reach the 404 fallback.
		if c.Request.Method == http.MethodOptions && c.GetHeader("Access-Control-Request-Method") != "" {
			c.Header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
			c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Request-ID")
			c.Header("Access-Control-Max-Age", "600")
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}
