package hash

import (
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
