package geo

import (
	"context"
	"testing"
)

func TestNoOpResolver(t *testing.T) {
	r := NewNoOpResolver()
	if got := r.Resolve(context.Background(), "8.8.8.8"); got != UnknownLocation {
		t.Errorf("NoOpResolver.Resolve = %q, want %q", got, UnknownLocation)
	}
	// nil IP must also return UnknownLocation without panicking.
	if got := r.Resolve(context.Background(), ""); got != UnknownLocation {
		t.Errorf("NoOpResolver.Resolve(empty) = %q, want %q", got, UnknownLocation)
	}
}

// mockResolver is a test geo.Resolver that returns a fixed label.
type mockResolver struct{ label string }

func (m mockResolver) Resolve(_ context.Context, _ string) string { return m.label }

func TestMockResolver(t *testing.T) {
	r := mockResolver{label: "Frankfurt, DE"}
	if got := r.Resolve(context.Background(), "1.2.3.4"); got != "Frankfurt, DE" {
		t.Errorf("mockResolver.Resolve = %q, want %q", got, "Frankfurt, DE")
	}
}
