package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	Issuer       = "finnapigo"
	FinnAudience = "finnapigo-api"
	JakeAudience = "jakeai-service"
	MaxAccessTTL = 900 * time.Second
	MaxSkew      = 30 * time.Second
	KeyDrain     = MaxAccessTTL + MaxSkew
)

// KeyConfig is deployment policy, never populated from token headers.
type KeyConfig struct {
	Algorithm, CurrentID, CurrentSecret, PreviousID, PreviousSecret string
	PreviousLastIssued                                              time.Time
}

// DecodeStrongKey requires base64 random key material; entropy provenance remains
// an operator responsibility. Reject obvious low-entropy/default material.
func DecodeStrongKey(value string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(b) < 32 || base64.StdEncoding.EncodeToString(b) != value {
		return nil, fmt.Errorf("key must encode at least 32 random bytes as base64")
	}
	seen := map[byte]bool{}
	for _, c := range b {
		seen[c] = true
	}
	if len(seen) < 16 {
		return nil, fmt.Errorf("key material has insufficient diversity")
	}
	return b, nil
}

func NewConfiguredJWTManager(c KeyConfig) (*JWTManager, error) {
	if c.Algorithm != "HS256" || !validKeyID(c.CurrentID) {
		return nil, fmt.Errorf("HS256 and explicit current key ID required")
	}
	current, err := DecodeStrongKey(c.CurrentSecret)
	if err != nil {
		return nil, err
	}
	m := &JWTManager{issuer: Issuer, current: current, currentKid: c.CurrentID,
		keys: map[string][]byte{c.CurrentID: current}, strict: true, now: time.Now}
	if c.PreviousSecret == "" {
		if c.PreviousID != "" || !c.PreviousLastIssued.IsZero() {
			return nil, fmt.Errorf("incomplete previous key configuration")
		}
		return m, nil
	}
	previous, err := DecodeStrongKey(c.PreviousSecret)
	if err != nil {
		return nil, err
	}
	if !validKeyID(c.PreviousID) || c.PreviousID == c.CurrentID || c.PreviousSecret == c.CurrentSecret || c.PreviousLastIssued.IsZero() || c.PreviousLastIssued.After(time.Now()) {
		return nil, fmt.Errorf("distinct previous key and past last-issuance timestamp required")
	}
	m.keys[c.PreviousID] = previous
	m.previousID = c.PreviousID
	m.previousRetires = c.PreviousLastIssued.Add(KeyDrain)
	return m, nil
}

func validKeyID(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_", c) {
			return false
		}
	}
	return true
}

// IssueAccessV1 takes only authoritative issuer state; there is no audience or
// arbitrary scope parameter. Roles and wildcards never select Jake authority.
func (m *JWTManager) IssueAccessV1(userID uint, role, email string, ttl time.Duration, pwdVer, authEpoch int64, sid, tid string, perms []string) (string, error) {
	if userID == 0 || sid == "" || tid == "" || pwdVer < 0 || authEpoch < 0 || ttl <= 0 || ttl > MaxAccessTTL {
		return "", ErrInvalidToken
	}
	c := m.baseClaims(userID, role, email, TokenTypeAccess, ttl)
	c.ContractVersion, c.PwdVer, c.AuthEpoch = 1, pwdVer, authEpoch
	c.ID, c.SID, c.TenantID = uuid.NewString(), sid, tid
	c.Permissions = append([]string{}, perms...)
	c.Audience = jwtlib.ClaimStrings{FinnAudience}
	for _, p := range perms {
		if p == "chat:read" || p == "chat:write" {
			c.Audience = jwtlib.ClaimStrings{FinnAudience, JakeAudience}
			break
		}
	}
	return m.sign(c)
}

// VerifyAccessV1 validates raw presence/types before converting to typed claims.
// This prevents omitted zero-valued pwdver/epoch and conflicting aliases.
func (m *JWTManager) VerifyAccessV1(token, audience string) (*Claims, error) {
	if audience != FinnAudience && audience != JakeAudience {
		return nil, ErrInvalidToken
	}
	c, err := m.Verify(token)
	if err != nil {
		return nil, err
	}
	if err := m.validateAccess(token, c, audience); err != nil {
		return nil, err
	}
	return c, nil
}

func (m *JWTManager) validateAccess(token string, c *Claims, audience string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ErrInvalidToken
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ErrInvalidToken
	}
	raw, err := uniqueObject(b)
	if err != nil {
		return ErrInvalidToken
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return ErrInvalidToken
	}
	if _, err := uniqueObject(hb); err != nil {
		return ErrInvalidToken
	}
	for _, name := range []string{"contract_ver", "iss", "aud", "sub", "uid", "type", "tid", "exp", "iat", "nbf", "jti", "sid", "pwdver", "auth_epoch", "perms"} {
		if v, ok := raw[name]; !ok || string(v) == "null" {
			return ErrInvalidToken
		}
	}
	for _, name := range []string{"tenant_id", "permissions", "roles", "scopes", "id"} {
		if _, ok := raw[name]; ok {
			return ErrInvalidToken
		}
	}
	for _, name := range []string{"contract_ver", "uid", "pwdver", "auth_epoch", "exp", "iat", "nbf"} {
		var n int64
		if err := json.Unmarshal(raw[name], &n); err != nil || n < 0 {
			return ErrInvalidToken
		}
	}
	var permissions []any
	if err := json.Unmarshal(raw["perms"], &permissions); err != nil || permissions == nil {
		return ErrInvalidToken
	}
	for _, permission := range permissions {
		if _, ok := permission.(string); !ok {
			return ErrInvalidToken
		}
	}
	if c.ContractVersion != 1 || c.Issuer != Issuer || c.Type != TokenTypeAccess || c.UserID == 0 || c.Subject != strconv.FormatUint(uint64(c.UserID), 10) || strings.TrimSpace(c.TenantID) == "" || c.ID == "" || c.SID == "" || c.Permissions == nil || c.PwdVer < 0 || c.AuthEpoch < 0 {
		return ErrInvalidToken
	}
	if c.ExpiresAt == nil || c.IssuedAt == nil || c.NotBefore == nil || c.ExpiresAt.Sub(c.IssuedAt.Time) <= 0 || c.ExpiresAt.Sub(c.IssuedAt.Time) > MaxAccessTTL || c.NotBefore.Before(c.IssuedAt.Time) || c.NotBefore.After(c.ExpiresAt.Time) {
		return ErrInvalidToken
	}
	now := time.Now()
	if m.now != nil {
		now = m.now()
	}
	if c.IssuedAt.After(now.Add(MaxSkew)) || c.NotBefore.After(now.Add(MaxSkew)) || !now.Before(c.ExpiresAt.Add(MaxSkew)) {
		return ErrInvalidToken
	}
	if len(c.Audience) != 1 && len(c.Audience) != 2 {
		return ErrInvalidToken
	}
	hasAudience, hasFinn, hasJake := false, false, false
	for _, a := range c.Audience {
		if a == audience {
			hasAudience = true
		}
		switch a {
		case FinnAudience:
			if hasFinn {
				return ErrInvalidToken
			}
			hasFinn = true
		case JakeAudience:
			if hasJake {
				return ErrInvalidToken
			}
			hasJake = true
		default:
			return ErrInvalidToken
		}
	}
	if !hasAudience || !hasFinn {
		return ErrInvalidToken
	}
	return nil
}

func (m *JWTManager) Strict() bool { return m.strict }

// Validate before Go's typed decoder can fold JSON names (including Unicode
// equivalents such as long s). Extensions remain case-sensitive and may coexist;
// names interpreted as claims or JOSE parameters must use their exact spelling.
func validateTokenNames(token string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ErrInvalidToken
	}
	protected := [][]string{
		{"alg", "kid", "typ", "cty", "crit", "jku", "jwk", "x5u", "x5c", "x5t", "x5t#S256", "b64"},
		{"contract_ver", "iss", "aud", "sub", "uid", "type", "tid", "exp", "iat", "nbf", "jti", "sid", "pwdver", "auth_epoch", "perms", "role", "email", "tenant_id", "permissions", "roles", "scopes", "id"},
	}
	for i, names := range protected {
		b, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil {
			return ErrInvalidToken
		}
		obj, err := uniqueObject(b)
		if err != nil {
			return ErrInvalidToken
		}
		for key := range obj {
			for _, canonical := range names {
				if key != canonical && strings.EqualFold(key, canonical) {
					return ErrInvalidToken
				}
			}
		}
	}
	return nil
}

func uniqueObject(b []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return nil, ErrInvalidToken
	}
	out := map[string]json.RawMessage{}
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return nil, ErrInvalidToken
		}
		s, ok := key.(string)
		if !ok {
			return nil, ErrInvalidToken
		}
		if _, exists := out[s]; exists {
			return nil, ErrInvalidToken
		}
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return nil, ErrInvalidToken
		}
		out[s] = value
	}
	if _, err := d.Token(); err != nil {
		return nil, ErrInvalidToken
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return nil, ErrInvalidToken
	}
	return out, nil
}
