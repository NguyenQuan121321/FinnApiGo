package middleware

import (
	"fmt"

	"github.com/gin-gonic/gin"
)

// SecurityHeaders sets the baseline browser-facing response headers (A3):
//
//   - X-Content-Type-Options: nosniff — stops MIME-type sniffing of API
//     responses rendered in a browser context.
//   - Referrer-Policy: no-referrer — credential-bearing URLs must not leak
//     via the Referer header.
//   - Cache-Control: no-store — applied to EVERY response rather than only
//     token-bearing ones: every endpoint on this service is
//     authentication-related (tokens, profile, sessions), so the safe
//     default wins over per-route opt-ins. Shared/proxy caches and the
//     browser back-button must never replay an auth response.
//   - Strict-Transport-Security — only when the request arrived over TLS
//     (directly or via a trusted proxy's X-Forwarded-Proto) and hstsSeconds
//     > 0; sending HSTS over plaintext is ignored at best and can break
//     plain-HTTP dev setups at worst.
//
// Routes should install this once, before any handler.
func SecurityHeaders(hstsSeconds int) gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		if hstsSeconds > 0 && isTLS(c) {
			h.Set("Strict-Transport-Security", fmt.Sprintf("max-age=%d", hstsSeconds))
		}
		c.Next()
	}
}

// isTLS reports whether the request reached this instance over HTTPS — either
// a direct TLS connection or an X-Forwarded-Proto header, which Gin only
// honors from trusted proxies (see routes.SetTrustedProxies wiring).
func isTLS(c *gin.Context) bool {
	return c.Request.TLS != nil || c.Request.Header.Get("X-Forwarded-Proto") == "https"
}
