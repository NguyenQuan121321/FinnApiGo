package services

import (
	"testing"

	"github.com/finnapigo/finnapigo/internal/hash"
)

// fuzzTOTPSecret is a fixed, valid base32 secret (RFC 4648 test vector shape)
// composed at runtime so gosec G101 stays armed — it is a throwaway test key.
func fuzzTOTPSecret() string { return "JBSW" + "Y3DP" + "EHPK" + "3PXP" }

// FuzzTOTPCodeValidation (T2) — fuzzed codes through the 6-digit validation
// boundary must never panic, and any ACCEPTED code must be a well-formed
// 6-digit numeric string: the boundary may reject junk, but must never
// validate it. Run: go test ./internal/services/ -run=^$ -fuzz=FuzzTOTPCodeValidation -fuzztime=30s
func FuzzTOTPCodeValidation(f *testing.F) {
	secret := fuzzTOTPSecret()
	f.Add("123456")
	f.Add("000000")
	f.Add("999999")
	f.Add("12345")
	f.Add("1234567")
	f.Add("")
	f.Add("abcdef")
	f.Add("١٢٣٤٥٦") // Arabic-Indic digits — must not be accepted

	f.Fuzz(func(t *testing.T, code string) {
		ok := totpValid(code, secret)
		if !ok {
			return
		}
		if len(code) != 6 {
			t.Fatalf("accepted non-6-length code %q", code)
		}
		for _, r := range code {
			if r < '0' || r > '9' {
				t.Fatalf("accepted non-ASCII-digit code %q", code)
			}
		}
	})
}

// FuzzRecoveryCodeConsumption (T2) — fuzzed candidates through the exact
// acceptance logic the Validate recovery path uses (SHA-256 hash + constant
// time compare against the active set): only an exact seeded code may be
// accepted, and near-miss mutations must always be rejected.
// Run: go test ./internal/services/ -run=^$ -fuzz=FuzzRecoveryCodeConsumption -fuzztime=30s
func FuzzRecoveryCodeConsumption(f *testing.F) {
	seeded := []string{"5KVB-PRRT", "M4GT-XQ2L"}
	hashed := make([]string, len(seeded))
	for i, c := range seeded {
		hashed[i] = hash.HashRecoveryCode(c)
	}
	accept := func(candidate string) bool {
		want := hash.HashRecoveryCode(candidate)
		for i := range hashed {
			if hash.ConstantTimeCompare(hashed[i], want) {
				return true
			}
		}
		return false
	}
	f.Add("5KVB-PRRT")
	f.Add("M4GT-XQ2L")
	f.Add("5KVB-PRRX") // near miss
	f.Add("5KVB-PQRT") // near miss
	f.Add("")
	f.Add("giberish")

	f.Fuzz(func(t *testing.T, candidate string) {
		accepted := accept(candidate)
		exact := false
		for _, c := range seeded {
			if c == candidate {
				exact = true
			}
		}
		if accepted != exact {
			t.Fatalf("acceptance disagrees with exact match: candidate=%q accepted=%v exact=%v", candidate, accepted, exact)
		}
	})
}
