package services

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/finnapigo/finnapigo/internal/config"
	"github.com/finnapigo/finnapigo/internal/crypto"
	"github.com/finnapigo/finnapigo/internal/hash"
	"github.com/finnapigo/finnapigo/internal/models"
)

// testEncKey is a fixed 32-byte AES-256 key for sealing recovery codes in
// tests. The value is public test data — only its length matters.
func testEncKey() []byte {
	return []byte("test-recovery-encryption-key-32b")
}

// newTestTOTPService builds a TOTPService with sensible test defaults. Pass
// nil for store/audits to disable those subsystems.
func newTestTOTPService(repo TOTPRepo, store StoreProvider, audits AuditRepo, cfgOverrides ...config.AuthConfig) *TOTPService {
	cfg := config.AuthConfig{
		TOTPMaxAttempts:   5,
		TOTPAttemptWindow: 5 * time.Minute,
		RecoveryCodeCount: 3, // small for fast tests
		RecoveryCodeBytes: 16,
	}
	if len(cfgOverrides) > 0 {
		cfg = cfgOverrides[0]
	}
	return NewTOTPService(repo, store, audits, "TestIssuer", cfg, testEncKey())
}

// enableAndVerify is a test helper that runs Enable then VerifyEnable, returning
// the secret and recovery codes. Panics on failure (test-only).
func enableAndVerify(t *testing.T, svc *TOTPService, userID uint) (string, []string) {
	t.Helper()
	secret, _, err := svc.Enable(context.Background(), userID, "user@example.com")
	if err != nil {
		t.Fatalf("Enable: %v", err)
	}
	codes, err := svc.VerifyEnable(context.Background(), userID, totpCode(t, secret))
	if err != nil {
		t.Fatalf("VerifyEnable: %v", err)
	}
	return secret, codes
}

// ---------- Enable ----------

func TestTOTPService_Enable_CreatesDevice(t *testing.T) {
	repo := newMockTOTPRepo()
	svc := newTestTOTPService(repo, nil, nil)

	secret, uri, err := svc.Enable(context.Background(), 1, "user@example.com")
	if err != nil {
		t.Fatalf("Enable failed: %v", err)
	}
	if secret == "" {
		t.Fatal("expected non-empty secret")
	}
	if uri == "" {
		t.Fatal("expected non-empty provisioning URI")
	}
	d, _ := repo.FindByUserID(context.Background(), 1)
	if d == nil {
		t.Fatal("expected device row to exist")
	}
	if d.Enabled {
		t.Fatal("device should be disabled until VerifyEnable confirms")
	}
	if d.Secret != secret {
		t.Fatal("stored secret should match returned secret")
	}
}

func TestTOTPService_Enable_RotatesExistingSecret(t *testing.T) {
	repo := newMockTOTPRepo()
	svc := newTestTOTPService(repo, nil, nil)

	secret1, _, _ := svc.Enable(context.Background(), 1, "a@b.com")
	secret2, _, err := svc.Enable(context.Background(), 1, "a@b.com")
	if err != nil {
		t.Fatalf("second Enable failed: %v", err)
	}
	if secret1 == secret2 {
		t.Fatal("second Enable should produce a fresh secret")
	}
	d, _ := repo.FindByUserID(context.Background(), 1)
	if d.Enabled {
		t.Fatal("device should still be disabled after re-enable")
	}
}

// ---------- VerifyEnable ----------

func TestTOTPService_VerifyEnable_ValidCode(t *testing.T) {
	repo := newMockTOTPRepo()
	audit := &mockAuditRepo{}
	svc := newTestTOTPService(repo, nil, audit)

	secret, _, _ := svc.Enable(context.Background(), 1, "user@example.com")
	codes, err := svc.VerifyEnable(context.Background(), 1, totpCode(t, secret))
	if err != nil {
		t.Fatalf("VerifyEnable failed: %v", err)
	}
	if len(codes) != 3 {
		t.Fatalf("expected 3 recovery codes, got %d", len(codes))
	}
	for _, c := range codes {
		if len(c) < 16 {
			t.Fatalf("recovery code too short: %q", c)
		}
	}
	d, _ := repo.FindByUserID(context.Background(), 1)
	if !d.Enabled {
		t.Fatal("device should be enabled after successful verify")
	}
	if audit.count() == 0 {
		t.Fatal("expected audit entry for totp_enabled")
	}
	_ = secret
}

func TestTOTPService_VerifyEnable_BadCode(t *testing.T) {
	repo := newMockTOTPRepo()
	svc := newTestTOTPService(repo, nil, nil)

	_, _, _ = svc.Enable(context.Background(), 1, "user@example.com")
	_, err := svc.VerifyEnable(context.Background(), 1, "000000")
	if !errors.Is(err, ErrInvalidOTP) {
		t.Fatalf("expected ErrInvalidOTP, got %v", err)
	}
}

func TestTOTPService_VerifyEnable_AlreadyEnabled(t *testing.T) {
	repo := newMockTOTPRepo()
	svc := newTestTOTPService(repo, nil, nil)

	secret, _, _ := svc.Enable(context.Background(), 1, "user@example.com")
	_, _ = svc.VerifyEnable(context.Background(), 1, totpCode(t, secret))
	_, err := svc.VerifyEnable(context.Background(), 1, totpCode(t, secret))
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
	_ = secret
}

func TestTOTPService_VerifyEnable_NoDevice(t *testing.T) {
	repo := newMockTOTPRepo()
	svc := newTestTOTPService(repo, nil, nil)

	_, err := svc.VerifyEnable(context.Background(), 99, "000000")
	if !errors.Is(err, ErrInvalidOTP) {
		t.Fatalf("expected ErrInvalidOTP, got %v", err)
	}
}

// ---------- Recovery codes are SHA-256 (not bcrypt) ----------

func TestRecoveryCodes_SHA256_NotBcrypt(t *testing.T) {
	repo := newMockTOTPRepo()
	svc := newTestTOTPService(repo, nil, nil)

	_, codes := enableAndVerify(t, svc, 1)

	// All stored hashes must be exactly 64 hex chars (SHA-256), NOT bcrypt
	// format ($2a$04$...).
	active, _ := repo.ActiveRecoveryCodes(context.Background(), 1)
	for i, c := range active {
		if len(c.CodeHash) != 64 {
			t.Errorf("code[%d] hash length=%d (want 64 for SHA-256): %q", i, len(c.CodeHash), c.CodeHash)
		}
		want := hash.HashRecoveryCode(codes[i])
		if c.CodeHash != want {
			t.Errorf("code[%d] hash mismatch: stored=%q want=%q", i, c.CodeHash, want)
		}
	}
}

// ---------- Validate — TOTP code ----------

func TestTOTPService_Validate_ValidTOTPCode(t *testing.T) {
	repo := newMockTOTPRepo()
	store := newMockStore()
	audit := &mockAuditRepo{}
	svc := newTestTOTPService(repo, store, audit)

	secret, _ := enableAndVerify(t, svc, 1)

	code := totpCode(t, secret)
	if err := svc.Validate(context.Background(), 1, code); err != nil {
		t.Fatalf("Validate with valid TOTP code failed: %v", err)
	}
}

func TestTOTPService_Validate_ReplayPrevention(t *testing.T) {
	repo := newMockTOTPRepo()
	store := newMockStore()
	svc := newTestTOTPService(repo, store, nil)

	secret, _ := enableAndVerify(t, svc, 1)

	code := totpCode(t, secret)
	if err := svc.Validate(context.Background(), 1, code); err != nil {
		t.Fatalf("first use should succeed: %v", err)
	}
	replayErr := svc.Validate(context.Background(), 1, code)
	if replayErr == nil {
		t.Fatal("replayed code should be rejected")
	}
	if !errors.Is(replayErr, ErrInvalidOTP) {
		t.Fatalf("expected ErrInvalidOTP for replay, got %v", replayErr)
	}
}

func TestTOTPService_Validate_BadTOTPCode(t *testing.T) {
	repo := newMockTOTPRepo()
	svc := newTestTOTPService(repo, nil, nil)

	_, _ = enableAndVerify(t, svc, 1)

	if err := svc.Validate(context.Background(), 1, "000000"); err == nil {
		t.Fatal("wrong code should be rejected")
	}
}

func TestTOTPService_Validate_NoDevice(t *testing.T) {
	repo := newMockTOTPRepo()
	svc := newTestTOTPService(repo, nil, nil)

	if err := svc.Validate(context.Background(), 99, "123456"); err == nil {
		t.Fatal("should fail when no device exists")
	}
}

func TestTOTPService_Validate_DeviceDisabled(t *testing.T) {
	repo := newMockTOTPRepo()
	svc := newTestTOTPService(repo, nil, nil)

	_, _, _ = svc.Enable(context.Background(), 1, "user@example.com")
	// Device is disabled (never verified).

	if err := svc.Validate(context.Background(), 1, "123456"); err == nil {
		t.Fatal("should fail when device is disabled")
	}
}

// ---------- Validate — recovery code ----------

func TestTOTPService_Validate_ValidRecoveryCode(t *testing.T) {
	repo := newMockTOTPRepo()
	svc := newTestTOTPService(repo, nil, nil)

	_, codes := enableAndVerify(t, svc, 1)
	if len(codes) == 0 {
		t.Fatal("no recovery codes issued")
	}

	if err := svc.Validate(context.Background(), 1, codes[0]); err != nil {
		t.Fatalf("valid recovery code should succeed: %v", err)
	}
	// The code should now be marked used.
	active, _ := repo.ActiveRecoveryCodes(context.Background(), 1)
	for _, c := range active {
		if c.CodeHash == hash.HashRecoveryCode(codes[0]) {
			t.Fatal("used recovery code should not appear in active codes")
		}
	}
}

func TestTOTPService_Validate_UsedRecoveryCode(t *testing.T) {
	repo := newMockTOTPRepo()
	svc := newTestTOTPService(repo, nil, nil)

	_, codes := enableAndVerify(t, svc, 1)

	// Use the code once.
	_ = svc.Validate(context.Background(), 1, codes[0])
	// Second use should fail.
	if err := svc.Validate(context.Background(), 1, codes[0]); err == nil {
		t.Fatal("reused recovery code should be rejected")
	}
}

func TestTOTPService_Validate_InvalidRecoveryCode(t *testing.T) {
	repo := newMockTOTPRepo()
	svc := newTestTOTPService(repo, nil, nil)

	_, _ = enableAndVerify(t, svc, 1)

	if err := svc.Validate(context.Background(), 1, "aabbccddeeff00112233aabbccddeeff"); err == nil {
		t.Fatal("invalid recovery code should be rejected")
	}
}

// ---------- Brute-force guard ----------

func TestTOTPService_BruteForce_RateLimits(t *testing.T) {
	repo := newMockTOTPRepo()
	store := newMockStore()
	cfg := config.AuthConfig{
		TOTPMaxAttempts:   3,
		TOTPAttemptWindow: 10 * time.Second,
		RecoveryCodeCount: 1,
		RecoveryCodeBytes: 16,
	}
	svc := newTestTOTPService(repo, store, nil, cfg)

	secret, _ := enableAndVerify(t, svc, 1)

	// Burn the attempt budget: 3 attempts, 3rd should be ErrRateLimited.
	for i := 0; i < 3; i++ {
		err := svc.Validate(context.Background(), 1, "000000")
		if i < 2 {
			if err == nil {
				t.Fatalf("wrong code should fail (attempt %d)", i+1)
			}
			if errors.Is(err, ErrRateLimited) {
				t.Fatalf("attempt %d should not be rate-limited yet", i+1)
			}
		}
		if i == 2 && !errors.Is(err, ErrRateLimited) {
			t.Fatalf("attempt %d should be rate-limited, got %v", i+1, err)
		}
	}
	// Even a valid code should be rejected (account is locked out).
	validCode := totpCode(t, secret)
	if err := svc.Validate(context.Background(), 1, validCode); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("rate-limited user should still get 429 even with valid code, got %v", err)
	}
}

func TestTOTPService_BruteForce_NoStore_NoOp(t *testing.T) {
	repo := newMockTOTPRepo()
	svc := newTestTOTPService(repo, nil, nil)

	_, _ = enableAndVerify(t, svc, 1)

	// Many wrong codes should still return ErrInvalidOTP, not ErrRateLimited.
	for i := 0; i < 20; i++ {
		err := svc.Validate(context.Background(), 1, "000000")
		if err == nil {
			t.Fatalf("wrong code should fail (attempt %d)", i+1)
		}
		if errors.Is(err, ErrRateLimited) {
			t.Fatal("should NOT rate-limit when store is nil")
		}
	}
}

// ---------- IsTOTPError ----------

func TestIsTOTPError(t *testing.T) {
	if !IsTOTPError(ErrInvalidOTP) {
		t.Fatal("should match ErrInvalidOTP")
	}
	if !IsTOTPError(ErrRateLimited) {
		t.Fatal("should match ErrRateLimited")
	}
	if IsTOTPError(ErrInvalidInput) {
		t.Fatal("should not match unrelated errors")
	}
}

// ---------- View recovery codes ----------

func TestTOTPService_ViewRecoveryCodes_ValidTOTP(t *testing.T) {
	repo := newMockTOTPRepo()
	audit := &mockAuditRepo{}
	svc := newTestTOTPService(repo, nil, audit)

	secret, issued := enableAndVerify(t, svc, 1)

	viewed, err := svc.ViewRecoveryCodes(context.Background(), 1, totpCode(t, secret))
	if err != nil {
		t.Fatalf("ViewRecoveryCodes failed: %v", err)
	}
	if len(viewed) != len(issued) {
		t.Fatalf("viewed %d codes, want %d", len(viewed), len(issued))
	}
	for i := range issued {
		if viewed[i] != issued[i] {
			t.Fatalf("code[%d] mismatch: viewed=%q issued=%q", i, viewed[i], issued[i])
		}
	}
	if len(audit.byEvent(models.AuditEventRecoveryCodesViewed)) == 0 {
		t.Fatal("expected recovery_codes_viewed audit entry")
	}
}

func TestTOTPService_ViewRecoveryCodes_BadCode(t *testing.T) {
	repo := newMockTOTPRepo()
	svc := newTestTOTPService(repo, nil, nil)

	_, _ = enableAndVerify(t, svc, 1)

	_, err := svc.ViewRecoveryCodes(context.Background(), 1, "000000")
	if !errors.Is(err, ErrInvalidOTP) {
		t.Fatalf("expected ErrInvalidOTP, got %v", err)
	}
}

func TestTOTPService_ViewRecoveryCodes_RecoveryCodeNotAllowed(t *testing.T) {
	repo := newMockTOTPRepo()
	svc := newTestTOTPService(repo, nil, nil)

	_, codes := enableAndVerify(t, svc, 1)

	// A recovery code must NOT unlock viewing the saved codes.
	_, err := svc.ViewRecoveryCodes(context.Background(), 1, codes[0])
	if !errors.Is(err, ErrInvalidOTP) {
		t.Fatalf("expected ErrInvalidOTP for recovery code, got %v", err)
	}
}

func TestTOTPService_ViewRecoveryCodes_ReplayRejected(t *testing.T) {
	repo := newMockTOTPRepo()
	store := newMockStore()
	svc := newTestTOTPService(repo, store, nil)

	secret, _ := enableAndVerify(t, svc, 1)

	code := totpCode(t, secret)
	if _, err := svc.ViewRecoveryCodes(context.Background(), 1, code); err != nil {
		t.Fatalf("first view should succeed: %v", err)
	}
	if _, err := svc.ViewRecoveryCodes(context.Background(), 1, code); !errors.Is(err, ErrInvalidOTP) {
		t.Fatalf("replayed TOTP code should be rejected, got %v", err)
	}
}

func TestTOTPService_ViewRecoveryCodes_DeviceNotEnabled(t *testing.T) {
	repo := newMockTOTPRepo()
	svc := newTestTOTPService(repo, nil, nil)

	_, _, _ = svc.Enable(context.Background(), 1, "user@example.com")

	if _, err := svc.ViewRecoveryCodes(context.Background(), 1, "123456"); !errors.Is(err, ErrInvalidOTP) {
		t.Fatalf("expected ErrInvalidOTP for unverified device, got %v", err)
	}
}

func TestTOTPService_ViewRecoveryCodes_ExcludesUsedCodes(t *testing.T) {
	repo := newMockTOTPRepo()
	store := newMockStore()
	svc := newTestTOTPService(repo, store, nil)

	secret, codes := enableAndVerify(t, svc, 1)
	// Burn one recovery code at login.
	if err := svc.Validate(context.Background(), 1, codes[0]); err != nil {
		t.Fatalf("Validate with recovery code failed: %v", err)
	}

	viewed, err := svc.ViewRecoveryCodes(context.Background(), 1, totpCode(t, secret))
	if err != nil {
		t.Fatalf("ViewRecoveryCodes failed: %v", err)
	}
	if len(viewed) != len(codes)-1 {
		t.Fatalf("viewed %d codes, want %d (used code excluded)", len(viewed), len(codes)-1)
	}
	for _, v := range viewed {
		if v == codes[0] {
			t.Fatal("used recovery code must not be re-displayed")
		}
	}
}

func TestTOTPService_ViewRecoveryCodes_SkipsLegacyUnencryptedRows(t *testing.T) {
	repo := newMockTOTPRepo()
	svc := newTestTOTPService(repo, nil, nil)

	secret, _ := enableAndVerify(t, svc, 1)
	// Simulate rows written before the encrypted column existed: hashes only.
	if err := repo.ReplaceRecoveryCodes(context.Background(), 1, []*models.RecoveryCode{
		{UserID: 1, CodeHash: hash.HashRecoveryCode("legacy-code-1")},
	}); err != nil {
		t.Fatalf("seed legacy rows: %v", err)
	}

	viewed, err := svc.ViewRecoveryCodes(context.Background(), 1, totpCode(t, secret))
	if err != nil {
		t.Fatalf("ViewRecoveryCodes should succeed, got %v", err)
	}
	if len(viewed) != 0 {
		t.Fatalf("legacy rows must be skipped, got %d codes", len(viewed))
	}
}

// ---------- Regenerate recovery codes ----------

func TestTOTPService_RegenerateRecoveryCodes_ReplacesSet(t *testing.T) {
	repo := newMockTOTPRepo()
	store := newMockStore()
	svc := newTestTOTPService(repo, store, nil)

	_, oldCodes := enableAndVerify(t, svc, 1)

	newCodes, err := svc.RegenerateRecoveryCodes(context.Background(), 1)
	if err != nil {
		t.Fatalf("RegenerateRecoveryCodes failed: %v", err)
	}
	if len(newCodes) != 3 {
		t.Fatalf("expected 3 new codes (test cfg), got %d", len(newCodes))
	}
	for _, oc := range oldCodes {
		if err := svc.Validate(context.Background(), 1, oc); err == nil {
			t.Fatal("old recovery code must be invalid after regenerate")
		}
	}
	if err := svc.Validate(context.Background(), 1, newCodes[0]); err != nil {
		t.Fatalf("new recovery code should validate: %v", err)
	}
	// The old rows must be gone entirely (used or not).
	active, _ := repo.ActiveRecoveryCodes(context.Background(), 1)
	if len(active) != len(newCodes)-1 { // one was just consumed above
		t.Fatalf("expected %d active rows after regenerate+use, got %d", len(newCodes)-1, len(active))
	}
}

func TestTOTPService_RegenerateRecoveryCodes_EncryptedAtRest(t *testing.T) {
	repo := newMockTOTPRepo()
	audit := &mockAuditRepo{}
	svc := newTestTOTPService(repo, nil, audit)

	_, _ = enableAndVerify(t, svc, 1)
	newCodes, err := svc.RegenerateRecoveryCodes(context.Background(), 1)
	if err != nil {
		t.Fatalf("RegenerateRecoveryCodes failed: %v", err)
	}

	active, _ := repo.ActiveRecoveryCodes(context.Background(), 1)
	if len(active) != len(newCodes) {
		t.Fatalf("stored %d rows, want %d", len(active), len(newCodes))
	}
	for i, row := range active {
		if row.CodeEncrypted == "" {
			t.Fatalf("row[%d] has no encrypted copy", i)
		}
		if row.CodeEncrypted == newCodes[i] {
			t.Fatalf("row[%d] stores plaintext!", i)
		}
		plain, err := crypto.Decrypt(testEncKey(), row.CodeEncrypted)
		if err != nil {
			t.Fatalf("row[%d] decrypt: %v", i, err)
		}
		if plain != newCodes[i] {
			t.Fatalf("row[%d] decrypts to %q, want %q", i, plain, newCodes[i])
		}
	}
	if len(audit.byEvent(models.AuditEventRecoveryCodesRegenerated)) == 0 {
		t.Fatal("expected recovery_codes_regenerated audit entry")
	}
}

func TestTOTPService_RegenerateRecoveryCodes_DeviceNotEnabled(t *testing.T) {
	repo := newMockTOTPRepo()
	svc := newTestTOTPService(repo, nil, nil)

	_, _, _ = svc.Enable(context.Background(), 1, "user@example.com")

	if _, err := svc.RegenerateRecoveryCodes(context.Background(), 1); !errors.Is(err, ErrInvalidOTP) {
		t.Fatalf("expected ErrInvalidOTP for unverified device, got %v", err)
	}
}

func TestTOTPService_RegenerateRecoveryCodes_NewSetViewable(t *testing.T) {
	repo := newMockTOTPRepo()
	svc := newTestTOTPService(repo, nil, nil)

	secret, _ := enableAndVerify(t, svc, 1)
	newCodes, err := svc.RegenerateRecoveryCodes(context.Background(), 1)
	if err != nil {
		t.Fatalf("RegenerateRecoveryCodes failed: %v", err)
	}

	viewed, err := svc.ViewRecoveryCodes(context.Background(), 1, totpCode(t, secret))
	if err != nil {
		t.Fatalf("viewing the regenerated set failed: %v", err)
	}
	if len(viewed) != len(newCodes) {
		t.Fatalf("viewed %d codes, want %d", len(viewed), len(newCodes))
	}
	for i := range newCodes {
		if viewed[i] != newCodes[i] {
			t.Fatalf("code[%d] mismatch: viewed=%q regenerated=%q", i, viewed[i], newCodes[i])
		}
	}
}

// ---------- Audit recording ----------

func TestTOTPService_Audit_OnFailure(t *testing.T) {
	repo := newMockTOTPRepo()
	audit := &mockAuditRepo{}
	svc := newTestTOTPService(repo, nil, audit)

	_, _, _ = svc.Enable(context.Background(), 1, "user@example.com")
	_ = svc.Validate(context.Background(), 1, "000000")

	if audit.count() == 0 {
		t.Fatal("expected audit entries for failed attempts")
	}
}

// ---------- Concurrency / race safety ----------

func TestTOTPService_ConcurrentValidates_NoRace(t *testing.T) {
	repo := newMockTOTPRepo()
	store := newMockStore()
	svc := newTestTOTPService(repo, store, nil)

	secret, _ := enableAndVerify(t, svc, 1)

	code := totpCode(t, secret)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = svc.Validate(context.Background(), 1, code)
		}()
	}
	wg.Wait()
}

// ---------- helpers ----------

// totpCode generates a valid TOTP code for the given secret at the current
// time. The service uses ValidateCustom with Skew=1, so this code (generated
// for "now") will always validate successfully.
func totpCode(t *testing.T, secret string) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("failed to generate test TOTP code: %v", err)
	}
	return code
}
