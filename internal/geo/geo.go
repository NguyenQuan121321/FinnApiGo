// Package geo provides a mockable IP -> location resolver for the session/
// device-management feature. The default implementation returns "Unknown"
// (so the service works fully offline); production can inject a real
// GeoIP-backed resolver without touching the service layer.
package geo

import "context"

// UnknownLocation is the placeholder returned when a location cannot be
// resolved (no resolver configured, offline, private IP, lookup miss).
const UnknownLocation = "Unknown"

// Resolver maps a client IP to a short human-readable location label
// (e.g. "Frankfurt, DE"). Implementations MUST be safe for concurrent use.
// A nil IP or private/loopback address should resolve to UnknownLocation.
//
// Resolve MUST never block indefinitely: callers pass a context carrying a
// deadline, and a resolver should honor it (return UnknownLocation on
// timeout/error rather than failing the whole request).
type Resolver interface {
	Resolve(ctx context.Context, ip string) string
}

// NoOpResolver always returns UnknownLocation. It is the zero-dependency
// default so the service is fully functional offline; the DB column still
// defaults to "Unknown".
type NoOpResolver struct{}

// NewNoOpResolver returns a Resolver that always reports UnknownLocation.
func NewNoOpResolver() NoOpResolver { return NoOpResolver{} }

// Resolve satisfies Resolver.
func (NoOpResolver) Resolve(_ context.Context, _ string) string { return UnknownLocation }
