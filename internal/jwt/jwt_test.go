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

// ----- K2: kid header + versioned key map -----

func TestJWT_IssueSetsKidHeader_K2(t *testing.T) {
	mgr := NewJWTManager("k2-current-secret", "issuer")
	tok1, err := mgr.Issue(1, "user", "a@b.com", TokenTypeAccess, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	tok2, _ := mgr.Issue(2, "user", "c@d.com", TokenTypeAccess, time.Minute)
	kid1 := headerKid(t, tok1)
	kid2 := headerKid(t, tok2)
	if kid1 == "" {
		t.Fatal("issued tokens must carry a kid header")
	}
	if kid1 != kid2 {
		t.Fatal("kid must be stable for the same signing secret")
	}
	other := NewJWTManager("k2-different-secret", "issuer")
	tok3, _ := other.Issue(1, "user", "a@b.com", TokenTypeAccess, time.Minute)
	if headerKid(t, tok3) == kid1 {
		t.Fatal("kid must differ when the signing secret differs")
	}
}

// TestJWT_VerifyAcceptsPreviousKeyVersion_K2 — phase gate: after rotation
// (JWT_SECRET=new, JWT_SECRET_PREVIOUS=old), tokens signed by the previous
// secret still verify, so rotation does not invalidate every session.
func TestJWT_VerifyAcceptsPreviousKeyVersion_K2(t *testing.T) {
	oldMgr := NewJWTManager("k2-previous-secret", "issuer")
	legacy, err := oldMgr.Issue(7, "user", "a@b.com", TokenTypeAccess, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	rotated := NewRotatingJWTManager("k2-current-secret", "k2-previous-secret", "issuer")
	claims, err := rotated.Verify(legacy)
	if err != nil {
		t.Fatalf("previous-key token must verify after rotation: %v", err)
	}
	if claims.UserID != 7 {
		t.Fatalf("uid = %d, want 7", claims.UserID)
	}
	fresh, err := rotated.Issue(8, "user", "a@b.com", TokenTypeAccess, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotated.Verify(fresh); err != nil {
		t.Fatalf("current-key token must verify: %v", err)
	}
	stranger := NewJWTManager("k2-unrelated-secret", "issuer")
	alien, _ := stranger.Issue(9, "user", "a@b.com", TokenTypeAccess, time.Minute)
	if _, err := rotated.Verify(alien); err == nil {
		t.Fatal("token signed by a key outside the keyset must be rejected")
	}
}

// TestJWT_VerifyLegacyTokenWithoutKid_K2 — tokens issued before K2 carry no
// kid header; the verifier must still accept them while the keyset covers
// their signing secret (grace window for the rotation rollout).
func TestJWT_VerifyLegacyTokenWithoutKid_K2(t *testing.T) {
	rotated := NewRotatingJWTManager("k2-current-secret", "k2-previous-secret", "issuer")
	mk := func(secret string) string {
		claims := Claims{UserID: 1, Type: TokenTypeAccess, RegisteredClaims: jwtv5.RegisteredClaims{
			Issuer: "issuer", ExpiresAt: jwtv5.NewNumericDate(time.Now().Add(time.Minute)),
		}}
		tok, err := jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, claims).SignedString([]byte(secret))
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	if _, err := rotated.Verify(mk("k2-current-secret")); err != nil {
		t.Fatalf("kid-less current-key token must verify: %v", err)
	}
	if _, err := rotated.Verify(mk("k2-previous-secret")); err != nil {
		t.Fatalf("kid-less previous-key token must verify: %v", err)
	}
	if _, err := rotated.Verify(mk("k2-unrelated-secret")); err == nil {
		t.Fatal("kid-less token with unknown key must be rejected")
	}
}

// TestJWT_VerifyRejectsUnknownKid_K2 — a kid not in the keyset is rejected
// outright instead of falling through to blind key guessing.
func TestJWT_VerifyRejectsUnknownKid_K2(t *testing.T) {
	mgr := NewJWTManager("k2-current-secret", "issuer")
	stranger := NewJWTManager("k2-unrelated-secret", "issuer")
	tok, err := stranger.Issue(1, "user", "a@b.com", TokenTypeAccess, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Verify(tok); err == nil {
		t.Fatal("token with unknown kid must be rejected")
	}
}

// TestJWT_RotatingManagerDedupesEqualSecrets_K2 — setting
// JWT_SECRET_PREVIOUS to the same value as JWT_SECRET must not error or
// double-register the key.
func TestJWT_RotatingManagerDedupesEqualSecrets_K2(t *testing.T) {
	mgr := NewRotatingJWTManager("k2-same-secret", "k2-same-secret", "issuer")
	tok, err := mgr.Issue(1, "user", "a@b.com", TokenTypeAccess, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Verify(tok); err != nil {
		t.Fatalf("verify with deduped keyset failed: %v", err)
	}
}

// headerKid extracts the kid header without verifying the token (test only).
func headerKid(t *testing.T, tokenStr string) string {
	t.Helper()
	tok, _, err := jwtv5.NewParser().ParseUnverified(tokenStr, &jwtv5.MapClaims{})
	if err != nil {
		t.Fatalf("parse unverified: %v", err)
	}
	kid, _ := tok.Header["kid"].(string)
	return kid
}
