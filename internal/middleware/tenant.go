package middleware

import (
	"context"
	"net"
	"strings"

	"github.com/finnapigo/finnapigo/internal/tenant"
	"github.com/gin-gonic/gin"
)

const DefaultTenantID = tenant.DefaultTenantID

// TenantFromContext extracts the resolved tenant ID from context.Context.
func TenantFromContext(ctx context.Context) string {
	return tenant.FromContext(ctx)
}

// WithTenant attaches a tenant ID to a context.Context.
func WithTenant(ctx context.Context, tenantID string) context.Context {
	return tenant.WithTenant(ctx, tenantID)
}

// TenantFromGin extracts the resolved tenant ID from gin.Context.
func TenantFromGin(c *gin.Context) string {
	if c == nil {
		return DefaultTenantID
	}
	if v, exists := c.Get("tenant_id"); exists {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return TenantFromContext(c.Request.Context())
}

// TenantMiddleware resolves the tenant partition (P2.1) from:
// 1. X-Tenant-ID header
// 2. X-Tenant-Slug header
// 3. Subdomain (e.g. acme.auth.example.com -> acme)
// 4. Default "default"
//
// The resolution here is UNAUTHENTICATED context only (it drives which
// partition register/login land in). For authenticated requests AuthMiddleware
// overrides it with the signed `tid` JWT claim, so a client cannot switch to
// another tenant's partition by setting headers after login.
func TenantMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantID := resolveTenant(c)
		if tenantID == "" {
			tenantID = DefaultTenantID
		}

		// Inject into gin.Context
		c.Set("tenant_id", tenantID)

		// Inject into underlying request context for repositories and services
		ctx := WithTenant(c.Request.Context(), tenantID)
		c.Request = c.Request.WithContext(ctx)

		c.Next()
	}
}

// resolveTenant extracts tenant identifier from headers, subdomain, or returns default.
func resolveTenant(c *gin.Context) string {
	// 1. Header X-Tenant-ID
	if headerID := strings.TrimSpace(c.GetHeader("X-Tenant-ID")); headerID != "" {
		return headerID
	}

	// 2. Header X-Tenant-Slug
	if headerSlug := strings.TrimSpace(c.GetHeader("X-Tenant-Slug")); headerSlug != "" {
		return headerSlug
	}

	// 3. Subdomain
	host := c.Request.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSpace(host))

	// Check for valid subdomain (e.g. acme.example.com)
	parts := strings.Split(host, ".")
	if len(parts) >= 3 {
		sub := parts[0]
		// Ignore common non-tenant prefixes
		if sub != "www" && sub != "api" && sub != "auth" && sub != "app" && sub != "localhost" {
			return sub
		}
	}

	return DefaultTenantID
}
