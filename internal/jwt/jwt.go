package jwt

import (
	"crypto/sha256"
	"encoding/hex"
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
	// SID (access tokens only) is the server-side session UUID the token was
	// issued for (P0.2). Revoking a session denylists this value so every
	// outstanding access token of that session dies before its exp.
	SID string `json:"sid,omitempty"`
	// TenantID identifies the tenant isolation partition (P2.1).
	TenantID string `json:"tid,omitempty"`
	// Permissions list the fine-grained RBAC capabilities granted (P2.2).
	Permissions []string `json:"perms,omitempty"`
	jwt.RegisteredClaims
}

// JWTManager signs and parses tokens with HMAC-SHA256 over a versioned keyset
// (K2). Signing always uses the current key and stamps its kid (a short
// SHA-256 fingerprint of the key material) into the header; verification
// resolves the key by kid so the previous secret stays valid during a
// rotation (JWT_SECRET + JWT_SECRET_PREVIOUS). HS256-only enforcement (C5)
// is unchanged.
type JWTManager struct {
	issuer     string
	current    []byte
	currentKid string
	keys       map[string][]byte // kid -> secret
	// tryOrder lists kids current-first; it drives the fallback path for
	// legacy tokens issued before kid headers existed.
	tryOrder []string
}

// NewJWTManager constructs a single-key JWTManager. The secret is captured as
// bytes so it is not accidentally logged via %s formatting of a struct.
func NewJWTManager(secret, issuer string) *JWTManager {
	return newJWTManager([]byte(secret), nil, issuer)
}

// NewRotatingJWTManager constructs a manager that signs with current and
// verifies tokens signed by current OR previous (K2). An empty or identical
// previous secret degrades to a single-key keyset.
func NewRotatingJWTManager(current, previous, issuer string) *JWTManager {
	var prev []byte
	if previous != "" && previous != current {
		prev = []byte(previous)
	}
	return newJWTManager([]byte(current), prev, issuer)
}

func newJWTManager(current, previous []byte, issuer string) *JWTManager {
	m := &JWTManager{
		issuer:     issuer,
		current:    current,
		currentKid: kidFor(current),
		keys:       make(map[string][]byte, 2),
	}
	m.keys[m.currentKid] = current
	m.tryOrder = append(m.tryOrder, m.currentKid)
	if len(previous) > 0 {
		kid := kidFor(previous)
		if _, dup := m.keys[kid]; !dup {
			m.keys[kid] = previous
			m.tryOrder = append(m.tryOrder, kid)
		}
	}
	return m
}

// kidFor derives a stable, non-secret key identifier: the first 8 hex chars
// of SHA-256(key). It fingerprints the key without exposing any key material
// and needs no extra configuration.
func kidFor(secret []byte) string {
	sum := sha256.Sum256(secret)
	return hex.EncodeToString(sum[:4])
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
	return m.sign(claims)
}

// IssueAccess issues an ACCESS token embedding the user's current password
// version (A7) and the server-side session UUID it belongs to (P0.2). Every
// access token gets a unique jti so Logout can denylist it for its remaining
// lifetime, plus the session id (sid) so revoking a session kills all of that
// session's outstanding access tokens at once. Callers must pass the live
// users.pwd_version so the next credential change invalidates the token.
func (m *JWTManager) IssueAccess(userID uint, role, email string, ttl time.Duration, pwdVer int64, sessionID string) (string, error) {
	claims := m.baseClaims(userID, role, email, TokenTypeAccess, ttl)
	claims.PwdVer = pwdVer
	claims.ID = uuid.New().String()
	claims.SID = sessionID
	return m.sign(claims)
}

// IssueAccessEnterprise issues an access token carrying tenant isolation (P2.1) and RBAC permissions (P2.2).
func (m *JWTManager) IssueAccessEnterprise(userID uint, role, email string, ttl time.Duration, pwdVer int64, sessionID, tenantID string, perms []string) (string, error) {
	claims := m.baseClaims(userID, role, email, TokenTypeAccess, ttl)
	claims.PwdVer = pwdVer
	claims.ID = uuid.New().String()
	claims.SID = sessionID
	claims.TenantID = tenantID
	claims.Permissions = perms
	return m.sign(claims)
}

// sign stamps the current kid and signs with the current key only.
func (m *JWTManager) sign(claims *Claims) (string, error) {
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tok.Header["kid"] = m.currentKid
	return tok.SignedString(m.current)
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
// HS256 — the keyfunc additionally rejects the non-HMAC families. Key
// resolution (K2): a kid header selects exactly one key from the versioned
// keyset (unknown kid ⇒ reject); kid-less legacy tokens are tried against
// each keyset key, current first, for the rotation grace window. On success
// it returns the typed claims. Callers must additionally check claims.Type
// matches the expected purpose (Verify does not assume a single type).
func (m *JWTManager) Verify(tokenStr string) (*Claims, error) {
	if kid := peekKid(tokenStr); kid != "" {
		key, ok := m.keys[kid]
		if !ok {
			return nil, fmt.Errorf("verify token: %w: %q", ErrUnknownKeyID, kid)
		}
		return m.parse(tokenStr, key)
	}
	var firstErr error
	for i, kid := range m.tryOrder {
		claims, err := m.parse(tokenStr, m.keys[kid])
		if err == nil {
			return claims, nil
		}
		if i == 0 {
			firstErr = err
		}
	}
	return nil, firstErr
}

// parse runs the full golang-jwt validation against one specific key.
func (m *JWTManager) parse(tokenStr string, key []byte) (*Claims, error) {
	claims := &Claims{}
	tok, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrUnexpectedSigningMethod
		}
		return key, nil
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

// peekKid reads the kid header WITHOUT verifying anything. The value is never
// trusted for auth — Verify uses it only to pick a candidate key and then
// validates the full signature against it.
func peekKid(tokenStr string) string {
	tok, _, err := jwt.NewParser().ParseUnverified(tokenStr, &jwt.MapClaims{})
	if err != nil {
		return ""
	}
	kid, _ := tok.Header["kid"].(string)
	return kid
}

// Sentinel errors for JWT operations.
var (
	ErrUnexpectedSigningMethod = errors.New("unexpected jwt signing method")
	ErrInvalidToken            = errors.New("invalid token")
	ErrUnknownKeyID            = errors.New("unknown jwt key id (kid)")
)
