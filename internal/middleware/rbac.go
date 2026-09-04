package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/finnapigo/finnapigo/internal/response"
	"github.com/gin-gonic/gin"
)

// RBACPermissionChecker abstracts permission lookups for RequirePermission middleware.
type RBACPermissionChecker interface {
	UserHasPermission(ctx context.Context, userID uint, permission string) (bool, error)
	GetUserPermissions(ctx context.Context, userID uint) ([]string, error)
}

// RequirePermission enforces fine-grained RBAC permission gating (P2.2).
// Checks JWT claims perms first, then DB/store.
func RequirePermission(permission string, checker RBACPermissionChecker) gin.HandlerFunc {
	return func(c *gin.Context) {
		v, ok := c.Get(CtxUserID)
		uid, isUint := v.(uint)
		if !ok || !isUint || uid == 0 {
			response.Respond(c, http.StatusUnauthorized, "authentication required", nil)
			c.Abort()
			return
		}

		// 1. If user is superadmin / role=admin, allow
		if r, exists := c.Get(CtxRole); exists {
			if roleStr, ok := r.(string); ok && roleStr == "admin" {
				c.Next()
				return
			}
		}

		// 2. Check JWT permissions claim if populated
		if permsVal, exists := c.Get(CtxPermissions); exists {
			if permsList, ok := permsVal.([]string); ok {
				for _, p := range permsList {
					if strings.EqualFold(p, permission) || p == "*" {
						c.Next()
						return
					}
				}
			}
		}

		// 3. Fallback to checker lookup
		if checker != nil {
			has, err := checker.UserHasPermission(c.Request.Context(), uid, permission)
			if err == nil && has {
				c.Next()
				return
			}
		}

		response.Respond(c, http.StatusForbidden, "permission denied: "+permission+" required", nil)
		c.Abort()
	}
}
