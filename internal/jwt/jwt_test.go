package jwt

import (
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"

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

func TestJWT_SudoTokenRoundTrip(t *testing.T) {
	mgr := NewJWTManager("secret", "issuer")
	tok, err := mgr.Issue(42, "user", "a@b.com", TokenTypeSudo, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := mgr.Verify(tok)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if claims.Type != TokenTypeSudo {
		t.Errorf("type = %q, want %q", claims.Type, TokenTypeSudo)
	}
	if claims.UserID != 42 {
		t.Errorf("uid = %d, want 42", claims.UserID)
	}
	if claims.ExpiresAt == nil || claims.ExpiresAt.IsZero() {
		t.Error("sudo token must carry an expiry for SudoMiddleware")
	}
	// A sudo token must never pass as an access token.
	if claims.Type == TokenTypeAccess {
		t.Error("sudo token must not appear as an access token")
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

// TestJWT_Verify_RejectsWrongIssuer_C5 — C5 regression: the configured issuer
// is enforced. A token signed with the same secret but a different iss must be
// rejected (prevents cross-environment token confusion).
func TestJWT_Verify_RejectsWrongIssuer_C5(t *testing.T) {
	signer := NewJWTManager("secret", "issuer-a")
	verifier := NewJWTManager("secret", "issuer-b")
	tok, err := signer.Issue(1, "user", "a@b.com", TokenTypeAccess, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(tok); err == nil {
		t.Error("token with wrong iss must be rejected")
	}
}

// TestJWT_Verify_RejectsMissingExp_C5 — C5 regression: exp is required. A
// structurally valid, correctly signed token without an expiry claim must be
// rejected instead of living forever.
func TestJWT_Verify_RejectsMissingExp_C5(t *testing.T) {
	mgr := NewJWTManager("secret", "issuer")
	claims := Claims{UserID: 1, Type: TokenTypeAccess, RegisteredClaims: jwtv5.RegisteredClaims{Issuer: "issuer"}}
	tok, err := jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, claims).SignedString([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Verify(tok); err == nil {
		t.Error("token without exp must be rejected")
	}
}

// TestJWT_Verify_RejectsNonHS256Alg_C5 — C5 regression: only HS256 is
// accepted. The old keyfunc accepted the whole HMAC family, so an HS384 token
// signed with the same secret verified successfully.
func TestJWT_Verify_RejectsNonHS256Alg_C5(t *testing.T) {
	mgr := NewJWTManager("secret", "issuer")
	claims := Claims{UserID: 1, Type: TokenTypeAccess, RegisteredClaims: jwtv5.RegisteredClaims{
		Issuer: "issuer", ExpiresAt: jwtv5.NewNumericDate(time.Now().Add(time.Minute)),
	}}
	tok, err := jwtv5.NewWithClaims(jwtv5.SigningMethodHS384, claims).SignedString([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Verify(tok); err == nil {
		t.Error("HS384-signed token must be rejected (only HS256 allowed)")
	}
	tokNone, err := jwtv5.NewWithClaims(jwtv5.SigningMethodNone, claims).SignedString(jwtv5.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Verify(tokNone); err == nil {
		t.Error("alg=none token must be rejected")
	}
}
