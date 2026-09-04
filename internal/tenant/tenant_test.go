package tenant

import (
	"context"
	"testing"
)

func TestFromContext(t *testing.T) {
	var nilCtx context.Context
	//nolint:staticcheck // SA1012: deliberate nil context test to verify defensive fallback
	if got := FromContext(nilCtx); got != DefaultTenantID {
		t.Fatalf("FromContext(nil) = %q, want %q", got, DefaultTenantID)
	}
	if got := FromContext(context.Background()); got != DefaultTenantID {
		t.Fatalf("FromContext(empty) = %q, want %q", got, DefaultTenantID)
	}
	ctx := WithTenant(context.Background(), "acme")
	if got := FromContext(ctx); got != "acme" {
		t.Fatalf("FromContext(set) = %q, want acme", got)
	}
}

func TestWithTenant_EmptyNormalizesToDefault(t *testing.T) {
	ctx := WithTenant(context.Background(), "")
	if got := FromContext(ctx); got != DefaultTenantID {
		t.Fatalf("WithTenant(\"\") = %q, want %q", got, DefaultTenantID)
	}
}

func TestDefaultTenantIDValue(t *testing.T) {
	if DefaultTenantID != "default" {
		t.Fatalf("DefaultTenantID = %q, want default", DefaultTenantID)
	}
}
