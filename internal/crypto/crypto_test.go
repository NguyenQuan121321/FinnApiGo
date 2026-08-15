package crypto

import (
	"strings"
	"testing"
)

func testKey() []byte {
	// Deterministic 32-byte key — value is irrelevant, only length matters.
	return []byte("0123456789abcdef0123456789abcdef")
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	key := testKey()
	enc, err := Encrypt(key, "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if enc == "" || strings.Contains(enc, "a1b2c3") {
		t.Fatalf("ciphertext leaked plaintext: %q", enc)
	}
	dec, err := Decrypt(key, enc)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if dec != "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6" {
		t.Fatalf("round trip mismatch: %q", dec)
	}
}

func TestEncrypt_FreshNoncePerCall(t *testing.T) {
	key := testKey()
	a, _ := Encrypt(key, "same-plaintext")
	b, _ := Encrypt(key, "same-plaintext")
	if a == b {
		t.Fatal("identical ciphertexts — nonce reuse would leak plaintext equality")
	}
}

func TestDecrypt_WrongKeyFails(t *testing.T) {
	enc, err := Encrypt(testKey(), "secret-code")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	wrong := []byte("ffffffffffffffffffffffffffffffff")
	if _, err = Decrypt(wrong, enc); err == nil {
		t.Fatal("decrypt with wrong key should fail")
	}
}

func TestDecrypt_TamperedCiphertextFails(t *testing.T) {
	enc, _ := Encrypt(testKey(), "secret-code")
	tampered := enc[:len(enc)-4] + "AAAA"
	if _, err := Decrypt(testKey(), tampered); err == nil {
		t.Fatal("tampered ciphertext should fail GCM authentication")
	}
}

func TestEncrypt_InvalidKeyLength(t *testing.T) {
	if _, err := Encrypt([]byte("short"), "x"); err == nil {
		t.Fatal("short key should be rejected")
	}
	if _, err := Decrypt([]byte("short"), "x"); err == nil {
		t.Fatal("short key should be rejected")
	}
}

func TestDecrypt_MalformedPayload(t *testing.T) {
	if _, err := Decrypt(testKey(), "not-base64!!!"); err == nil {
		t.Fatal("malformed base64 should be rejected")
	}
	if _, err := Decrypt(testKey(), "AAAA"); err == nil {
		t.Fatal("too-short payload should be rejected")
	}
}
