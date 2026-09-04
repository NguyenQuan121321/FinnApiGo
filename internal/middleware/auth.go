// Package middleware contains Gin middlewares: JWT auth + role checks +
// rate limiting + request logging.
package middleware

import (
	"context"
	"log/slog"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/finnapigo/finnapigo/internal/jwt"
	"github.com/finnapigo/finnapigo/internal/response"
	"github.com/finnapigo/finnapigo/internal/tenant"
)

// Context keys for values set by AuthMiddleware.
const (
	CtxUserID = "user_id"
	CtxRole   = "role"
	CtxEmail  = "email"
	// CtxJTI holds the access token's unique jti (P0.2).
	CtxJTI = "jti"
	// CtxSID holds the access token's session UUID (P0.2 / P0.3).
	CtxSID = "sid"
	// CtxPermissions holds the RBAC permission list from the token's perms
	// claim (P2.2), consumed by RequirePermission.
	CtxPermissions = "permissions"
	// CtxSudoUntil holds the expiry time.Time of the verified sudo token —
	// set by SudoMiddleware, which must run after AuthMiddleware.
	CtxSudoUntil = "sudo_until"
	// CtxRequestID is the request identifier set by the routes request
	// logger; AuthMiddleware copies it onto its denial log lines.
	CtxRequestID = "request_id"
)

// DenylistChecker checks whether a token JTI or session UUID is denylisted (P0.2).
type DenylistChecker interface {
	Get(key string) (any, bool)
}

type authOptions struct {
	denylist DenylistChecker
}

// AuthOption configures optional AuthMiddleware capabilities.
type AuthOption func(*authOptions)

// WithDenylist wires a store/cache to check for revoked jti/sid entries (P0.2).
func WithDenylist(d DenylistChecker) AuthOption {
	return func(o *authOptions) { o.denylist = d }
}

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

// VersionSource returns the live password-version counter for a user (A7).
// Wire AuthService.CurrentPwdVersion in production; nil disables the check
// (tests / degraded deployments).
type VersionSource func(ctx context.Context, userID uint) (int64, error)

// AuthMiddleware verifies the Bearer JWT from the Authorization header.
// On success it stores user_id / role / email / jti / sid into the Gin context
// for downstream handlers. On failure it short-circuits with 401.
//
// A7 — when a VersionSource is wired, access tokens whose embedded pwdver
// falls behind the live counter (the credential changed) are rejected. If the
// version cannot be LOADED (store + DB both unreachable) the request is
// allowed through with a warning: the residual exposure is bounded by the
// access TTL, the documented worst case.
func AuthMiddleware(jwtMgr *jwt.JWTManager, pwdVersion VersionSource, opts ...AuthOption) gin.HandlerFunc {
	var opt authOptions
	for _, fn := range opts {
		fn(&opt)
	}
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
		// P0.2 — denylist check: if the token's JTI or SID was revoked, abort 401.
		if opt.denylist != nil {
			if claims.ID != "" {
				if _, revoked := opt.denylist.Get("denylist:jti:" + claims.ID); revoked {
					denyAuth(c, "token revoked")
					return
				}
			}
			if claims.SID != "" {
				if _, revoked := opt.denylist.Get("denylist:sid:" + claims.SID); revoked {
					denyAuth(c, "session revoked")
					return
				}
			}
		}
		if pwdVersion != nil {
			current, err := pwdVersion(c.Request.Context(), claims.UserID)
			if err != nil {
				slog.Warn("auth: password version unavailable — failing open (bounded by access TTL)",
					"user_id", claims.UserID, "err", err)
			} else if claims.PwdVer < current {
				denyAuth(c, "credentials changed, please sign in again")
				return
			}
		}
		c.Set(CtxUserID, claims.UserID)
		c.Set(CtxRole, claims.Role)
		c.Set(CtxEmail, claims.Email)
		c.Set(CtxJTI, claims.ID)
		c.Set(CtxSID, claims.SID)
		if len(claims.Permissions) > 0 {
			c.Set(CtxPermissions, claims.Permissions)
		}
		// P2.1 — tenant binding: a signed tid claim OVERRIDES whatever tenant
		// the request headers/subdomain resolved to. The effective tenant for
		// every authenticated request is therefore the one bound at token
		// issuance — clients cannot cross tenant boundaries by setting
		// X-Tenant-ID. Tokens issued before the tid claim existed carry no
		// tenant and keep the header-derived value (bounded by AccessTTL).
		if claims.TenantID != "" {
			c.Set("tenant_id", claims.TenantID)
			c.Request = c.Request.WithContext(
				tenant.WithTenant(c.Request.Context(), claims.TenantID))
		}
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
