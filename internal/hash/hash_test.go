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
	if HashToken("token-a") != HashToken("token-a") {
		t.Fatal("same token must hash identically")
	}
	if HashToken("token-a") == HashToken("token-b") {
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

func TestGenerateNumericOTP(t *testing.T) {
	for _, tc := range []struct {
		length  int
		wantErr bool
	}{{6, false}, {0, true}, {-1, true}} {
		t.Run("length", func(t *testing.T) {
			otp, err := GenerateNumericOTP(tc.length)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
			if !tc.wantErr && (len(otp) != tc.length || strings.Trim(otp, "0123456789") != "") {
				t.Fatalf("invalid OTP %q", otp)
			}
		})
	}
}
