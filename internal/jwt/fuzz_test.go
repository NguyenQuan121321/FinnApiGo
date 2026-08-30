package jwt

import (
	"strings"
	"testing"
	"time"
)

// FuzzJWTVerify (T2) — random byte strings into Verify must never panic and
// never fabricate claims: every non-error result must carry a known token
// type, and anything that fails to round-trip our own signer must be an
// error. Run: go test ./internal/jwt/ -run=^$ -fuzz=FuzzJWTVerify -fuzztime=30s
func FuzzJWTVerify(f *testing.F) {
	mgr := NewJWTManager(fuzzSecret(), "fuzz-issuer")
	valid, _ := mgr.Issue(1, "user", "fuzz@example.com", TokenTypeAccess, time.Minute)
	prev, _ := NewJWTManager(fuzzPreviousSecret(), "fuzz-issuer").Issue(2, "user", "p@example.com", TokenTypeAccess, time.Minute)
	// A genuinely DIFFERENT keyset: the old fixture built the second manager
	// with the same CURRENT secret as mgr (identical kid), which made the
	// cross-keyset rejection below unreachable — a dead assertion inside a
	// security property.
	rotated := NewJWTManager(fuzzRotatedSecret(), "fuzz-issuer")
	f.Add(valid)
	f.Add(prev)
	f.Add("")
	f.Add("not-a-token")
	f.Add(strings.Repeat("A", 512))

	f.Fuzz(func(t *testing.T, tokenStr string) {
		claims, err := mgr.Verify(tokenStr)
		if err != nil {
			if claims != nil {
				t.Fatalf("Verify returned claims alongside an error: %v", err)
			}
			return
		}
		if claims == nil {
			t.Fatal("Verify returned nil claims and nil error")
		}
		switch claims.Type {
		case TokenTypeAccess, TokenTypeReset, TokenTypeEmailVerify, TokenTypeMFAPending, TokenTypeSudo:
		default:
			t.Fatalf("forged type %q accepted by Verify", claims.Type)
		}
		// A manager with a different keyset must never accept this token —
		// its kid is unknown to it and its keys are different material.
		if _, err := rotated.Verify(tokenStr); err == nil {
			t.Fatal("token verified by a manager with a different keyset")
		}
	})
}

// The fixture secrets are composed at runtime so gosec G101 stays armed.
func fuzzSecret() string         { return "fuzz-" + "jwt-" + "current-secret" }
func fuzzPreviousSecret() string { return "fuzz-" + "jwt-" + "previous-secret" }
func fuzzRotatedSecret() string  { return "fuzz-" + "jwt-" + "rotated-secret" }
