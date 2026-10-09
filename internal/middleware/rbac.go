package middleware

import (
	"context"
	"net/http"

	"github.com/finnapigo/finnapigo/internal/response"
	"github.com/gin-gonic/gin"
)

// RBACPermissionChecker abstracts permission lookups for RequirePermission middleware.
type RBACPermissionChecker interface {
	UserHasPermission(ctx context.Context, userID uint, permission string) (bool, error)
	GetUserPermissions(ctx context.Context, userID uint) ([]string, error)
}

// RequirePermission enforces fine-grained RBAC permission gating (P2.2).
// Uses exact signed grants. The checker argument is retained for API compatibility.
func RequirePermission(permission string, _ RBACPermissionChecker) gin.HandlerFunc {
	return func(c *gin.Context) {
		v, ok := c.Get(CtxUserID)
		uid, isUint := v.(uint)
		if !ok || !isUint || uid == 0 {
			response.Respond(c, http.StatusUnauthorized, "authentication required", nil)
			c.Abort()
			return
		}

		// Only exact signed grants authorize access. Roles, wildcards and
		// database fallbacks cannot expand the authenticated token's authority.
		if permsVal, exists := c.Get(CtxPermissions); exists {
			if permsList, ok := permsVal.([]string); ok {
				for _, p := range permsList {
					if p == permission {
						c.Next()
						return
					}
				}
			}
		}

		response.Respond(c, http.StatusForbidden, "permission denied: "+permission+" required", nil)
		c.Abort()
	}
}
