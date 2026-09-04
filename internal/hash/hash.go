package hash

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/bcrypt"
)

// MaxPasswordBytes is bcrypt's maximum accepted password size. Enforcing it
// prevents silent truncation, which could otherwise let distinct passwords
// authenticate as the same credential.
const MaxPasswordBytes = 72

// Bcrypt work factor constants mirrored from golang.org/x/crypto/bcrypt.
const (
	MinCost     = bcrypt.MinCost
	DefaultCost = bcrypt.DefaultCost
	MaxCost     = bcrypt.MaxCost
)

// HashPassword returns a bcrypt hash of the plaintext password using bcrypt.DefaultCost,
// or the optional cost if supplied and positive.
// Use this at registration / password change / reset.
func HashPassword(plain string, optCost ...int) (string, error) {
	cost := DefaultCost
	if len(optCost) > 0 && optCost[0] > 0 {
		cost = optCost[0]
	}
	return HashPasswordWithCost(plain, cost)
}

// HashPasswordWithCost returns a bcrypt hash using the specified cost work factor.
// If cost is outside [MinCost, MaxCost], it falls back to DefaultCost.
func HashPasswordWithCost(plain string, cost int) (string, error) {
	if len(plain) > MaxPasswordBytes {
		return "", fmt.Errorf("hash password: exceeds bcrypt limit of %d bytes", MaxPasswordBytes)
	}
	if cost < MinCost || cost > MaxCost {
		cost = DefaultCost
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(plain), cost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(hashed), nil
}

// CheckPassword reports whether plain matches the stored bcrypt hash.
func CheckPassword(hash, plain string) bool {
	if len(plain) > MaxPasswordBytes {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil
}

// HashToken returns the SHA-256 hex digest of an arbitrary secret token.
// Used for refresh tokens — we store only the hash so the DB
// never holds a usable credential.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// HashRecoveryCode returns the SHA-256 hex digest of a high-entropy recovery
// code. Random codes are not subject to dictionary attacks, so they need NOT
// be run through bcrypt's expensive key derivation; SHA-256 is sufficient and,
// crucially, O(1) — preventing a CPU DoS where an attacker spams invalid
// recovery codes to peg 100% CPU on bcrypt. Verification must use
// hash.ConstantTimeCompare (timing-safe).
func HashRecoveryCode(code string) string {
	return HashToken(code)
}

// randReader allows injecting a failing reader during unit tests.
var randReader io.Reader = rand.Reader

// GenerateRandomBytes returns n cryptographically secure random bytes.
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(randReader, b); err != nil {
		return nil, err
	}
	return b, nil
}

// GenerateOpaqueToken returns a 32-byte (256-bit) hex random string used as
// the plaintext refresh/reset token returned to clients.
func GenerateOpaqueToken() (string, error) {
	b, err := GenerateRandomBytes(32)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ConstantTimeCompare reports whether two strings are equal in constant time.
// It is a thin wrapper over crypto/subtle so callers don't import it directly.
// The inputs need not be the same length; mismatched lengths return false
// without short-circuiting beyond a single length comparison.
func ConstantTimeCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// MatchRecoveryCode hashes the candidate and returns the index of the stored
// code hash it matches, or -1. This IS the acceptance logic the TOTP recovery
// path uses (SHA-256 + constant-time compare) — extracted so the service and
// its fuzz target exercise the same function and can never drift apart.
func MatchRecoveryCode(candidate string, codeHashes []string) int {
	want := HashRecoveryCode(candidate)
	for i := range codeHashes {
		if ConstantTimeCompare(codeHashes[i], want) {
			return i
		}
	}
	return -1
}
