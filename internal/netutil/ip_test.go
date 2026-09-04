package netutil

import (
	"fmt"
	"testing"
)

func TestCanonicalIP(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty passthrough", "", ""},
		{"ipv4 verbatim", "203.0.113.7", "203.0.113.7"},
		{"ipv4-mapped ipv6 collapsed to ipv4", "::ffff:203.0.113.7", "203.0.113.7"},
		{"ipv6 collapsed to /64", "2001:db8:1:2:3:4:5:6", "2001:db8:1:2::"},
		{"same /64 different host collapses identically", "2001:db8:1:2:aaaa::1", "2001:db8:1:2::"},
		{"different /64 stays distinct", "2001:db8:1:3::1", "2001:db8:1:3::"},
		{"unparseable passthrough", "not-an-ip", "not-an-ip"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CanonicalIP(tc.in); got != tc.want {
				t.Fatalf("CanonicalIP(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestCanonicalIP_SubnetRotationBounded is the V4 property: a host cycling
// addresses inside one /64 must key to a single canonical form, so limiter
// counters and store keys cannot be multiplied by address rotation.
func TestCanonicalIP_SubnetRotationBounded(t *testing.T) {
	seen := map[string]bool{}
	for i := 1; i <= 20; i++ {
		ip := fmt.Sprintf("2001:db8:9:a::%x", i)
		seen[CanonicalIP(ip)] = true
	}
	if len(seen) != 1 {
		t.Fatalf("addresses within one /64 produced %d distinct keys, want 1", len(seen))
	}
}
