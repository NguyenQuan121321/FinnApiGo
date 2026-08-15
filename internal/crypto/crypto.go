// Package crypto provides reversible encryption for secrets that must be
// displayed again later (e.g. GitHub-style re-viewable MFA recovery codes).
// It is deliberately separate from internal/hash, which is one-way only:
// anything encrypted here can be recovered with the server-side key, so it
// must never hold a credential that only needs verification.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/finnapigo/finnapigo/internal/hash"
)

// KeyLen is the required AES-256 key length in bytes.
const KeyLen = 32

// nonceLen is the standard 12-byte GCM nonce. A fresh random nonce is prepended
// to every ciphertext so encrypting the same plaintext twice yields different
// output without leaking equality.
const nonceLen = 12

// ErrInvalidKey is returned when the key is not exactly KeyLen bytes.
var ErrInvalidKey = errors.New("crypto: key must be 32 bytes (AES-256)")

// Encrypt seals plaintext with AES-256-GCM under key and returns
// base64(nonce ‖ ciphertext+tag). Use hash.GenerateRandomBytes-derived keys;
// never a user-supplied password.
func Encrypt(key []byte, plaintext string) (string, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	nonce, err := hash.GenerateRandomBytes(nonceLen)
	if err != nil {
		return "", fmt.Errorf("crypto: generate nonce: %w", err)
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Decrypt opens a value produced by Encrypt. GCM authentication means any
// tampering (wrong key, truncated/corrupted payload) fails here.
func Decrypt(key []byte, encoded string) (string, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("crypto: decode payload: %w", err)
	}
	if len(raw) < nonceLen+gcm.Overhead() {
		return "", errors.New("crypto: payload too short")
	}
	plain, err := gcm.Open(nil, raw[:nonceLen], raw[nonceLen:], nil)
	if err != nil {
		return "", fmt.Errorf("crypto: decrypt: %w", err)
	}
	return string(plain), nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != KeyLen {
		return nil, ErrInvalidKey
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: init cipher: %w", err)
	}
	return cipher.NewGCM(block)
}
