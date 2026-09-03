// Package netutil holds small, dependency-free network helpers shared across
// layers (middleware rate limiting and service-layer abuse counters key on
// the same canonical IP form — V4).
package netutil

import "net"

// CanonicalIP normalizes a client IP for use as a state key. IPv6 sources are
// collapsed to their /64 prefix so one host cycling addresses inside its
// subnet cannot mint unbounded counter/limiter keys (V4 — the middleware
// limiter previously keyed raw c.ClientIP(), bypassing the /64 collapse the
// service-layer counters already applied). IPv4 addresses are returned
// verbatim — the /64 mask is meaningless for them. Unparseable input is
// returned unchanged so callers keep their existing key shape.
func CanonicalIP(ip string) string {
	if ip == "" {
		return ip
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip
	}
	if v4 := parsed.To4(); v4 != nil {
		return v4.String()
	}
	if v6 := parsed.To16(); v6 != nil {
		return v6.Mask(net.CIDRMask(64, 128)).String()
	}
	return ip
}
