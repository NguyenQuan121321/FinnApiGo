package hash

import (
	"errors"
	"strings"
	"testing"
)

func TestHashPasswordAndCheckPassword(t *testing.T) {
	passwords := []string{"", "Password1!", strings.Repeat("a", 72), "mật-khẩu🔐"}
	for _, password := range passwords {
		t.Run("password", func(t *testing.T) {
			hash, err := HashPassword(password)
			if err != nil {
				t.Fatalf("HashPassword: %v", err)
			}
			if !CheckPassword(hash, password) {
				t.Fatal("correct password did not verify")
			}
			if CheckPassword(hash, password+"x") {
				t.Fatal("incorrect password verified")
			}
		})
	}
}

func TestHashPasswordUsesUniqueSalts(t *testing.T) {
	first, err := HashPassword("Password1!")
	if err != nil {
		t.Fatal(err)
	}
	second, err := HashPassword("Password1!")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("bcrypt hashes must use unique salts")
	}
}

func TestHashTokenDeterministic(t *testing.T) {
	first := HashToken("token-a")
	second := HashToken("token-a")
	if first != second {
		t.Fatal("same token must hash identically")
	}
	if first == HashToken("token-b") {
		t.Fatal("distinct tokens must not hash identically")
	}
}

func TestPasswordOverBcryptLimitIsRejected(t *testing.T) {
	tooLong := strings.Repeat("a", MaxPasswordBytes+1)
	if _, err := HashPassword(tooLong); err == nil {
		t.Fatal("expected overlong password to be rejected")
	}
	hash, err := HashPassword(strings.Repeat("a", MaxPasswordBytes))
	if err != nil {
		t.Fatal(err)
	}
	if CheckPassword(hash, tooLong) {
		t.Fatal("overlong password must not authenticate via bcrypt truncation")
	}
}

func TestGenerateRandomBytesAndOpaqueToken(t *testing.T) {
	b, err := GenerateRandomBytes(16)
	if err != nil || len(b) != 16 {
		t.Fatalf("GenerateRandomBytes(16) failed: len=%d, err=%v", len(b), err)
	}

	tok, err := GenerateOpaqueToken()
	if err != nil || len(tok) != 64 { // 32 bytes hex encoded = 64 hex characters
		t.Fatalf("GenerateOpaqueToken() failed: len=%d, err=%v", len(tok), err)
	}

	tok2, _ := GenerateOpaqueToken()
	if tok == tok2 {
		t.Fatal("consecutive opaque tokens must be distinct")
	}
}

func TestConstantTimeCompare(t *testing.T) {
	if !ConstantTimeCompare("exact-match", "exact-match") {
		t.Fatal("identical strings must match")
	}
	if ConstantTimeCompare("string-a", "string-b") {
		t.Fatal("distinct strings of equal length must not match")
	}
	if ConstantTimeCompare("short", "much-longer-string") {
		t.Fatal("strings of different length must not match")
	}
}

func TestHashAndMatchRecoveryCode(t *testing.T) {
	code1 := "abcd-1234-wxyz"
	code2 := "5678-efgh-9012"
	h1 := HashRecoveryCode(code1)
	h2 := HashRecoveryCode(code2)

	hashes := []string{h1, h2}

	idx := MatchRecoveryCode(code1, hashes)
	if idx != 0 {
		t.Fatalf("MatchRecoveryCode expected idx 0, got %d", idx)
	}

	idx = MatchRecoveryCode(code2, hashes)
	if idx != 1 {
		t.Fatalf("MatchRecoveryCode expected idx 1, got %d", idx)
	}

	idx = MatchRecoveryCode("invalid-code", hashes)
	if idx != -1 {
		t.Fatalf("MatchRecoveryCode expected idx -1 for invalid, got %d", idx)
	}
}

type failReader struct{}

func (failReader) Read(_ []byte) (int, error) { return 0, errors.New("entropy source failed") }

func TestGenerateRandomBytesError(t *testing.T) {
	orig := randReader
	randReader = failReader{}
	defer func() { randReader = orig }()

	if _, err := GenerateRandomBytes(16); err == nil {
		t.Fatal("expected error on failing entropy reader")
	}
	if _, err := GenerateOpaqueToken(); err == nil {
		t.Fatal("expected error on failing entropy reader")
	}
}
