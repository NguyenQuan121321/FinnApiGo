package jwt

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Token type claim values. Each issued token carries exactly one of these in
// the "type" claim so a token issued for one purpose cannot be replayed for
// another (e.g. a reset token can't be used to call protected endpoints).
const (
	TokenTypeAccess      = "access"
	TokenTypeReset       = "reset"
	TokenTypeEmailVerify = "verify-email"
	TokenTypeMFAPending  = "mfa_pending"
	TokenTypeSudo        = "sudo"
)

// Claims is the custom JWT claims payload shared by every token type.
type Claims struct {
	UserID uint   `json:"uid"`
	Role   string `json:"role,omitempty"`
	Email  string `json:"email,omitempty"`
	Type   string `json:"type"`
	// PwdVer (access tokens only) is the user's password-version counter at
	// issue time; AuthMiddleware rejects the token once the live version is
	// higher (credential changed — A7).
	PwdVer int64 `json:"pwdver,omitempty"`
	jwt.RegisteredClaims
}

// JWTManager signs and parses tokens using a single HMAC-SHA256 secret.
type JWTManager struct {
	secret []byte
	issuer string
}

// NewJWTManager constructs a JWTManager. The secret is captured as bytes so it
// is not accidentally logged via %s formatting of a struct.
func NewJWTManager(secret, issuer string) *JWTManager {
	return &JWTManager{secret: []byte(secret), issuer: issuer}
}

// Issue builds and signs a token of the given type with the requested lifetime.
// For reset and verify-email tokens a jti (UUID) is embedded so single-use
// enforcement can track consumption (§1.8).
func (m *JWTManager) Issue(userID uint, role, email, tokenType string, ttl time.Duration) (string, error) {
	claims := m.baseClaims(userID, role, email, tokenType, ttl)
	// §1.8 — single-use tokens get a unique jti so replay is detectable.
	switch tokenType {
	case TokenTypeReset, TokenTypeEmailVerify:
		claims.ID = uuid.New().String()
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(m.secret)
}

// IssueAccess issues an ACCESS token embedding the user's current password
// version (A7). Callers must pass the live users.pwd_version so the next
// credential change invalidates the token.
func (m *JWTManager) IssueAccess(userID uint, role, email string, ttl time.Duration, pwdVer int64) (string, error) {
	claims := m.baseClaims(userID, role, email, TokenTypeAccess, ttl)
	claims.PwdVer = pwdVer
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(m.secret)
}

// baseClaims assembles the registered + custom claims shared by every token.
func (m *JWTManager) baseClaims(userID uint, role, email, tokenType string, ttl time.Duration) *Claims {
	now := time.Now()
	return &Claims{
		UserID: userID,
		Role:   role,
		Email:  email,
		Type:   tokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Subject:   fmt.Sprintf("%d", userID),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			NotBefore: jwt.NewNumericDate(now),
		},
	}
}

// Verify validates the signature, expiry, and issuer. exp is REQUIRED (a
// token without one never verifies) and the only accepted algorithm is
// HS256 — the keyfunc additionally rejects the non-HMAC families. On success
// it returns the typed claims. Callers must additionally check claims.Type
// matches the expected purpose (Verify does not assume a single type).
func (m *JWTManager) Verify(tokenStr string) (*Claims, error) {
	claims := &Claims{}
	tok, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrUnexpectedSigningMethod
		}
		return m.secret, nil
	},
		jwt.WithIssuer(m.issuer),
		jwt.WithExpirationRequired(),
		jwt.WithValidMethods([]string{"HS256"}),
	)
	if err != nil {
		return nil, fmt.Errorf("verify token: %w", err)
	}
	if !tok.Valid {
		return nil, ErrInvalidToken
	}
	return claims, nil
}

// Sentinel errors for JWT operations.
var (
	ErrUnexpectedSigningMethod = errors.New("unexpected jwt signing method")
	ErrInvalidToken            = errors.New("invalid token")
)
