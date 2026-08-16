// Package middleware contains Gin middlewares: JWT auth + role checks +
// rate limiting + request logging.
package middleware

import (
	"log/slog"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/finnapigo/finnapigo/internal/jwt"
	"github.com/finnapigo/finnapigo/internal/response"
)

// Context keys for values set by AuthMiddleware.
const (
	CtxUserID = "user_id"
	CtxRole   = "role"
	CtxEmail  = "email"
	// CtxSudoUntil holds the expiry time.Time of the verified sudo token —
	// set by SudoMiddleware, which must run after AuthMiddleware.
	CtxSudoUntil = "sudo_until"
	// CtxRequestID is the request identifier set by the routes request
	// logger; AuthMiddleware copies it onto its denial log lines.
	CtxRequestID = "request_id"
)

// denyAuth answers 401 and makes the denial observable: one slog.Warn per
// rejection carrying the client IP and request id (A4) — before, middleware
// 401s were invisible to operators triaging credential-stuffing incidents.
func denyAuth(c *gin.Context, msg string) {
	rid, _ := c.Get(CtxRequestID)
	ridStr, _ := rid.(string)
	slog.Warn("auth denied",
		"reason", msg,
		"client_ip", c.ClientIP(),
		"rid", ridStr,
		"path", c.Request.URL.Path,
	)
	response.Respond(c, 401, msg, nil)
	c.Abort()
}

// AuthMiddleware verifies the Bearer JWT from the Authorization header.
// On success it stores user_id / role / email into the Gin context for
// downstream handlers. On failure it short-circuits with 401.
func AuthMiddleware(jwtMgr *jwt.JWTManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		if header == "" {
			denyAuth(c, "missing authorization header")
			return
		}
		parts := strings.SplitN(header, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
			denyAuth(c, "invalid authorization header format")
			return
		}
		claims, err := jwtMgr.Verify(parts[1])
		if err != nil {
			denyAuth(c, "invalid or expired token")
			return
		}
		// Only genuine access tokens are accepted on protected endpoints.
		if claims.Type != jwt.TokenTypeAccess {
			denyAuth(c, "invalid token type")
			return
		}
		c.Set(CtxUserID, claims.UserID)
		c.Set(CtxRole, claims.Role)
		c.Set(CtxEmail, claims.Email)
		c.Next()
	}
}

// RequireRole returns a middleware that allows only the listed roles.
// Must be installed AFTER AuthMiddleware so the role is already in context.
func RequireRole(roles ...string) gin.HandlerFunc {
	allowed := make(map[string]struct{}, len(roles))
	for _, r := range roles {
		allowed[r] = struct{}{}
	}
	return func(c *gin.Context) {
		role, exists := c.Get(CtxRole)
		if !exists {
			response.Respond(c, 401, "authentication required", nil)
			c.Abort()
			return
		}
		roleStr, _ := role.(string)
		if _, ok := allowed[roleStr]; !ok {
			response.Respond(c, 403, "insufficient permissions", nil)
			c.Abort()
			return
		}
		c.Next()
	}
}

// HasRole is a small helper for handlers that need to branch on role without
// aborting the request.
func HasRole(c *gin.Context, role string) bool {
	v, ok := c.Get(CtxRole)
	if !ok {
		return false
	}
	s, _ := v.(string)
	return s == role
}
