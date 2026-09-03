package middleware_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/finnapigo/finnapigo/internal/middleware"
	"github.com/gin-gonic/gin"
)

type mockRBACChecker struct {
	allowed map[string]bool
}

func (m mockRBACChecker) UserHasPermission(_ context.Context, userID uint, permission string) (bool, error) {
	return m.allowed[permission], nil
}

func (m mockRBACChecker) GetUserPermissions(_ context.Context, userID uint) ([]string, error) {
	var out []string
	for k, v := range m.allowed {
		if v {
			out = append(out, k)
		}
	}
	return out, nil
}

func TestRequirePermission(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name       string
		setAuth    bool
		userID     uint
		role       string
		jwtPerms   []string
		checker    mockRBACChecker
		reqPerm    string
		wantStatus int
	}{
		{
			name:       "unauthenticated returns 401",
			setAuth:    false,
			reqPerm:    "users:read",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "admin role bypasses permission check",
			setAuth:    true,
			userID:     1,
			role:       "admin",
			reqPerm:    "users:write",
			wantStatus: http.StatusOK,
		},
		{
			name:       "allowed via JWT permissions claim",
			setAuth:    true,
			userID:     2,
			role:       "user",
			jwtPerms:   []string{"users:read", "audit:read"},
			reqPerm:    "users:read",
			wantStatus: http.StatusOK,
		},
		{
			name:       "allowed via checker fallback",
			setAuth:    true,
			userID:     3,
			role:       "user",
			checker:    mockRBACChecker{allowed: map[string]bool{"users:write": true}},
			reqPerm:    "users:write",
			wantStatus: http.StatusOK,
		},
		{
			name:       "forbidden when permission missing",
			setAuth:    true,
			userID:     4,
			role:       "user",
			checker:    mockRBACChecker{allowed: map[string]bool{"users:read": true}},
			reqPerm:    "users:write",
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := gin.New()
			r.GET("/protected", func(c *gin.Context) {
				if tt.setAuth {
					c.Set("user_id", tt.userID)
					c.Set("role", tt.role)
					if len(tt.jwtPerms) > 0 {
						c.Set("permissions", tt.jwtPerms)
					}
				}
				c.Next()
			}, middleware.RequirePermission(tt.reqPerm, tt.checker), func(c *gin.Context) {
				c.Status(http.StatusOK)
			})

			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/protected", nil))

			if w.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", w.Code, tt.wantStatus)
			}
		})
	}
}
