// Package middleware contains Gin middlewares: JWT auth + role checks +
// rate limiting + request logging.
package middleware

import (
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/finnapigo/finnapigo/internal/jwt"
	"github.com/finnapigo/finnapigo/internal/response"
)

// MFAPendingMiddleware verifies the Bearer JWT from the Authorization header
// and accepts ONLY tokens with type "mfa_pending". Regular access tokens are
// rejected so a fully-authenticated session cannot call the MFA completion
// endpoint (prevents one session from bypassing a pending login for a different
// session). On success it stores user_id into the Gin context.
func MFAPendingMiddleware(jwtMgr *jwt.JWTManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		if header == "" {
			response.Respond(c, 401, "missing authorization header", nil)
			c.Abort()
			return
		}
		parts := strings.SplitN(header, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
			response.Respond(c, 401, "invalid authorization header format", nil)
			c.Abort()
			return
		}
		claims, err := jwtMgr.Verify(parts[1])
		if err != nil {
			response.Respond(c, 401, "invalid or expired token", nil)
			c.Abort()
			return
		}
		// Accept ONLY mfa_pending tokens — access/reset/verify-email are rejected.
		if claims.Type != jwt.TokenTypeMFAPending {
			response.Respond(c, 401, "invalid token type", nil)
			c.Abort()
			return
		}
		c.Set(CtxUserID, claims.UserID)
		c.Next()
	}
}
