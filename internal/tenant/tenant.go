package tenant

import "context"

type contextKey string

const contextKeyTenantID contextKey = "tenant_id"

// DefaultTenantID is the fallback tenant for single-tenant / backwards-compatible mode.
const DefaultTenantID = "default"

// FromContext extracts the tenant ID from context.Context.
// Returns DefaultTenantID ("default") if none is set.
func FromContext(ctx context.Context) string {
	if ctx == nil {
		return DefaultTenantID
	}
	if v, ok := ctx.Value(contextKeyTenantID).(string); ok && v != "" {
		return v
	}
	return DefaultTenantID
}

// WithTenant attaches a tenant ID to context.Context.
func WithTenant(ctx context.Context, tenantID string) context.Context {
	if tenantID == "" {
		tenantID = DefaultTenantID
	}
	return context.WithValue(ctx, contextKeyTenantID, tenantID)
}
