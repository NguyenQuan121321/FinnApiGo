package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/finnapigo/finnapigo/internal/middleware"
	"github.com/gin-gonic/gin"
)

func TestTenantMiddleware_Resolution(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name       string
		headers    map[string]string
		host       string
		wantTenant string
	}{
		{
			name:       "default fallback",
			headers:    nil,
			host:       "localhost:8080",
			wantTenant: middleware.DefaultTenantID,
		},
		{
			name:       "via X-Tenant-ID header",
			headers:    map[string]string{"X-Tenant-ID": "acme-corp"},
			host:       "localhost:8080",
			wantTenant: "acme-corp",
		},
		{
			name:       "via X-Tenant-Slug header",
			headers:    map[string]string{"X-Tenant-Slug": "globex"},
			host:       "localhost:8080",
			wantTenant: "globex",
		},
		{
			name:       "via subdomain",
			headers:    nil,
			host:       "initech.example.com",
			wantTenant: "initech",
		},
		{
			name:       "common prefix ignored (api.example.com)",
			headers:    nil,
			host:       "api.example.com",
			wantTenant: middleware.DefaultTenantID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := gin.New()
			r.Use(middleware.TenantMiddleware())

			var gotTenantGin string
			var gotTenantCtx string

			r.GET("/test", func(c *gin.Context) {
				gotTenantGin = middleware.TenantFromGin(c)
				gotTenantCtx = middleware.TenantFromContext(c.Request.Context())
				c.Status(http.StatusOK)
			})

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.Host = tt.host
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if gotTenantGin != tt.wantTenant {
				t.Fatalf("TenantFromGin = %q, want %q", gotTenantGin, tt.wantTenant)
			}
			if gotTenantCtx != tt.wantTenant {
				t.Fatalf("TenantFromContext = %q, want %q", gotTenantCtx, tt.wantTenant)
			}
		})
	}
}
