package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"

	"golang.org/x/crypto/bcrypt"
)

// HashPassword returns a bcrypt hash of the plaintext password.
// Use this at registration / password change / reset.
func HashPassword(plain string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(hashed), nil
}

// CheckPassword reports whether plain matches the stored bcrypt hash.
func CheckPassword(hash, plain string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil
}

// HashToken returns the SHA-256 hex digest of an arbitrary secret token.
// Used for refresh tokens and OTP codes — we store only the hash so the DB
// never holds a usable credential.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// GenerateRandomBytes returns n cryptographically secure random bytes.
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// GenerateNumericOTP returns a zero-padded numeric one-time code of the given
// length using crypto/rand (NOT math/rand — must be unpredictable).
func GenerateNumericOTP(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("otp length must be positive")
	}
	const digits = "0123456789"
	out := make([]byte, length)
	for i := range out {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(digits))))
		if err != nil {
			return "", err
		}
		out[i] = digits[idx.Int64()]
	}
	return string(out), nil
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
