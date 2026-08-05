package jwt

import (
	"testing"
	"time"

	"github.com/finnapigo/finnapigo/internal/hash"
)

// TestJWT_TypeDiscrimination verifies the most important token-safety property:
// a token issued for one purpose must NOT validate as a different type. This
// prevents e.g. a reset token being used to authenticate to /me.
func TestJWT_TypeDiscrimination(t *testing.T) {
	mgr := NewJWTManager("secret", "issuer")
	reset, err := mgr.Issue(1, "user", "a@b.com", TokenTypeReset, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := mgr.Verify(reset)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if claims.Type != TokenTypeReset {
		t.Errorf("type = %q, want %q", claims.Type, TokenTypeReset)
	}
	if claims.Type == TokenTypeAccess {
		t.Error("reset token must not appear as an access token")
	}
}

func TestJWT_ExpiredRejected(t *testing.T) {
	mgr := NewJWTManager("secret", "issuer")
	tok, _ := mgr.Issue(1, "user", "a@b.com", TokenTypeAccess, -time.Minute)
	if _, err := mgr.Verify(tok); err == nil {
		t.Error("expired token must be rejected")
	}
}

func TestJWT_WrongSecretRejected(t *testing.T) {
	mgr1 := NewJWTManager("secret1", "issuer")
	mgr2 := NewJWTManager("secret2", "issuer")
	tok, _ := mgr1.Issue(1, "user", "a@b.com", TokenTypeAccess, time.Minute)
	if _, err := mgr2.Verify(tok); err == nil {
		t.Error("token signed with a different secret must be rejected")
	}
}

func TestHashToken_DeterministicAndOpaque(t *testing.T) {
	h1 := hash.HashToken("abc")
	h2 := hash.HashToken("abc")
	h3 := hash.HashToken("abd")
	if h1 != h2 {
		t.Error("hash must be deterministic")
	}
	if h1 == h3 {
		t.Error("different inputs must hash differently")
	}
	if h1 == "abc" {
		t.Error("hash must not equal input")
	}
}

func TestGenerateNumericOTP_Length(t *testing.T) {
	for _, n := range []int{4, 6, 8} {
		code, err := hash.GenerateNumericOTP(n)
		if err != nil {
			t.Fatal(err)
		}
		if len(code) != n {
			t.Errorf("length %d: got %d", n, len(code))
		}
		for _, c := range code {
			if c < '0' || c > '9' {
				t.Errorf("non-digit in OTP: %q", code)
			}
		}
	}
}
