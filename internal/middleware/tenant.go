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

	// If host is an IP address (e.g. 127.0.0.1, 192.168.1.1), return default
	if ip := net.ParseIP(host); ip != nil {
		return DefaultTenantID
	}

	// Check for valid subdomain (e.g. acme.example.com)
	parts := strings.Split(host, ".")
	if len(parts) >= 3 {
		// Detect PaaS public domains where <app>.<platform>.<tld> has 3 parts
		// (e.g. finnapigo.onrender.com, myapp.fly.dev, etc.)
		lastTwo := parts[len(parts)-2] + "." + parts[len(parts)-1]
		isPaaS := lastTwo == "onrender.com" || lastTwo == "fly.dev" ||
			lastTwo == "railway.app" || lastTwo == "herokuapp.com" ||
			lastTwo == "vercel.app"

		if isPaaS && len(parts) == 3 {
			// e.g. finnapigo.onrender.com is the base service domain, not a tenant
			return DefaultTenantID
		}

		sub := parts[0]
		// Ignore common non-tenant prefixes and base service names
		if sub != "www" && sub != "api" && sub != "auth" && sub != "app" &&
			sub != "admin" && sub != "staging" && sub != "dev" &&
			sub != "localhost" && sub != "finnapigo" {
			return sub
		}
	}

	return DefaultTenantID
}
