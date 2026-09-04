package crypto

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnvKeyProvider_Retrieve_K3(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i) + 1 // start at 1 so zeroing is detectable below
	}
	p := NewEnvKeyProvider(map[string][]byte{KeyNameRecoveryCodes: key})
	got, err := p.Retrieve(KeyNameRecoveryCodes)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != hex.EncodeToString(key) {
		t.Fatal("retrieved key must match the supplied key")
	}
	// Returned bytes must be a copy — callers zeroing their slice must not
	// corrupt the provider's copy.
	for i := range got {
		got[i] = 0
	}
	again, _ := p.Retrieve(KeyNameRecoveryCodes)
	if again[0] == 0 {
		t.Fatal("Retrieve must return a defensive copy")
	}
}

func TestEnvKeyProvider_UnknownNameRejected_K3(t *testing.T) {
	p := NewEnvKeyProvider(map[string][]byte{})
	if _, err := p.Retrieve("nope"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("want ErrKeyNotFound, got %v", err)
	}
}

func writeFileKey(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name+".key"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestFileKeyProvider_RetrieveHexKey_K3(t *testing.T) {
	dir := t.TempDir()
	raw := strings.Repeat("ab", 32) // 64 hex chars → 32 bytes
	writeFileKey(t, dir, KeyNameRecoveryCodes, raw+"\n")
	p := NewFileKeyProvider(dir)
	got, err := p.Retrieve(KeyNameRecoveryCodes)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != KeyLen {
		t.Fatalf("key must decode to %d bytes, got %d", KeyLen, len(got))
	}
}

func TestFileKeyProvider_MissingFileIsKeyNotFound_K3(t *testing.T) {
	p := NewFileKeyProvider(t.TempDir())
	if _, err := p.Retrieve(KeyNameJWT); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("want ErrKeyNotFound, got %v", err)
	}
}

func TestFileKeyProvider_RejectsBadHex_K3(t *testing.T) {
	dir := t.TempDir()
	writeFileKey(t, dir, KeyNameJWT, "not-hex!!")
	p := NewFileKeyProvider(dir)
	if _, err := p.Retrieve(KeyNameJWT); err == nil {
		t.Fatal("non-hex key file must be rejected")
	}
}

func TestFileKeyProvider_RejectsWrongLength_K3(t *testing.T) {
	dir := t.TempDir()
	writeFileKey(t, dir, KeyNameJWT, "abcd") // 2 bytes
	p := NewFileKeyProvider(dir)
	if _, err := p.Retrieve(KeyNameJWT); err == nil {
		t.Fatal("short key file must be rejected")
	}
}

func TestEnvKeyProvider_EmptyKeyRejected(t *testing.T) {
	p := NewEnvKeyProvider(map[string][]byte{"empty": {}})
	if _, err := p.Retrieve("empty"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("empty key slice must yield ErrKeyNotFound, got %v", err)
	}
}

func TestFileKeyProvider_ReadError(t *testing.T) {
	dir := t.TempDir()
	// Create a directory named anything.key so os.ReadFile fails with a read error, not NotExist
	if err := os.Mkdir(filepath.Join(dir, "anything.key"), 0o700); err != nil {
		t.Fatal(err)
	}
	p := NewFileKeyProvider(dir)
	if _, err := p.Retrieve("anything"); err == nil || errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected non-NotFound file read error, got %v", err)
	}
}
