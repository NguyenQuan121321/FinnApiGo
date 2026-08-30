package services

import (
	"context"
	"strconv"

	"google.golang.org/api/idtoken"
)

// productionGoogleVerifier verifies Google ID tokens using the
// google.golang.org/api/idtoken package, which fetches Google's JWKS and
// validates the token's signature, expiry, issuer, and audience claim.
// No hand-rolled JWT verification.
type productionGoogleVerifier struct {
	clientID string
}

// NewProductionGoogleVerifier creates a verifier bound to the given Google
// OAuth client ID. The client ID is used as the expected "aud" claim in the
// ID token, so a token minted for a different application is rejected.
func NewProductionGoogleVerifier(clientID string) *productionGoogleVerifier {
	return &productionGoogleVerifier{clientID: clientID}
}

// Verify validates the ID token cryptographically and returns the verified
// claims. Returns ErrOAuthTokenVerificationFailed on any validation error.
func (v *productionGoogleVerifier) Verify(ctx context.Context, rawIDToken string) (*GoogleIDTokenClaims, error) {
	payload, err := idtoken.Validate(ctx, rawIDToken, v.clientID)
	if err != nil {
		return nil, ErrOAuthTokenVerificationFailed
	}
	return &GoogleIDTokenClaims{
		Sub:           payload.Subject,
		Email:         claimString(payload.Claims, "email"),
		EmailVerified: claimBool(payload.Claims, "email_verified"),
		Name:          claimString(payload.Claims, "name"),
		Picture:       claimString(payload.Claims, "picture"),
		Nonce:         claimString(payload.Claims, "nonce"),
	}, nil
}

// claimString extracts a string claim from the raw claims map.
func claimString(claims map[string]interface{}, key string) string {
	if v, ok := claims[key].(string); ok {
		return v
	}
	return ""
}

// claimBool extracts a boolean claim, tolerating the string-encoded form
// ("true"/"false") some providers emit.
func claimBool(claims map[string]interface{}, key string) bool {
	switch v := claims[key].(type) {
	case bool:
		return v
	case string:
		b, _ := strconv.ParseBool(v)
		return b
	default:
		return false
	}
}
