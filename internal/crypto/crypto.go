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

// Encryptor seals and opens payloads with AES-256-GCM under one fixed key.
// The key schedule (aes.NewCipher + cipher.NewGCM) is computed once in
// NewEncryptor and reused by every call — the app's key never changes at
// runtime, so re-deriving it per Encrypt/Decrypt call is pure waste. Construct
// one Encryptor at startup and inject it wherever sealing is needed.
type Encryptor struct {
	gcm cipher.AEAD
}

// NewEncryptor validates the key and pre-computes the GCM cipher block.
func NewEncryptor(key []byte) (*Encryptor, error) {
	if len(key) != KeyLen {
		return nil, ErrInvalidKey
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: init cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: init gcm: %w", err)
	}
	return &Encryptor{gcm: gcm}, nil
}

// Encrypt seals plaintext and returns base64(nonce ‖ ciphertext+tag). Use
// hash.GenerateRandomBytes-derived keys; never a user-supplied password.
func (e *Encryptor) Encrypt(plaintext string) (string, error) {
	nonce, err := hash.GenerateRandomBytes(nonceLen)
	if err != nil {
		return "", fmt.Errorf("crypto: generate nonce: %w", err)
	}
	sealed := e.gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Decrypt opens a value produced by Encrypt. GCM authentication means any
// tampering (wrong key, truncated/corrupted payload) fails here.
func (e *Encryptor) Decrypt(encoded string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("crypto: decode payload: %w", err)
	}
	if len(raw) < nonceLen+e.gcm.Overhead() {
		return "", errors.New("crypto: payload too short")
	}
	plain, err := e.gcm.Open(nil, raw[:nonceLen], raw[nonceLen:], nil)
	if err != nil {
		return "", fmt.Errorf("crypto: decrypt: %w", err)
	}
	return string(plain), nil
}

// Encrypt seals plaintext with AES-256-GCM under key and returns
// base64(nonce ‖ ciphertext+tag). It is a convenience wrapper for callers
// without a long-lived Encryptor; the hot path should use NewEncryptor once
// and reuse the instance to avoid the per-call key schedule.
func Encrypt(key []byte, plaintext string) (string, error) {
	e, err := NewEncryptor(key)
	if err != nil {
		return "", err
	}
	return e.Encrypt(plaintext)
}

// Decrypt opens a value produced by Encrypt. GCM authentication means any
// tampering (wrong key, truncated/corrupted payload) fails here.
func Decrypt(key []byte, encoded string) (string, error) {
	e, err := NewEncryptor(key)
	if err != nil {
		return "", err
	}
	return e.Decrypt(encoded)
}
