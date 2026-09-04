package services

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/go-sql-driver/mysql"
	"github.com/pquerna/otp/totp"
	"gorm.io/gorm"

	"github.com/finnapigo/finnapigo/internal/config"
	"github.com/finnapigo/finnapigo/internal/crypto"
	"github.com/finnapigo/finnapigo/internal/geo"
	"github.com/finnapigo/finnapigo/internal/hash"
	"github.com/finnapigo/finnapigo/internal/jwt"
	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/repositories"
	"github.com/finnapigo/finnapigo/internal/store"
	"github.com/go-webauthn/webauthn/protocol"
)

func TestTOTPService_ComprehensiveBranches(t *testing.T) {
	ctx := context.Background()

	db, err := gorm.Open(sqlite.Open("file:totp_branches?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	_ = db.AutoMigrate(
		&models.User{},
		&models.TOTPDevice{},
		&models.RecoveryCode{},
		&models.PasskeyCredential{},
		&models.AuditLog{},
	)

	userRepo := repositories.NewUserRepository(db)
	totpRepo := repositories.NewTOTPRepository(db)
	passkeyRepo := repositories.NewPasskeyRepository(db)
	auditRepo := repositories.NewAuditRepository(db)
	memStore := store.NewInMemoryStore(0)
	jwtMgr := jwt.NewJWTManager("test-secret-long-enough-32-chars-!!", "test")
	enc, err := crypto.NewEncryptor([]byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal(err)
	}

	totpCfg := config.AuthConfig{
		TOTPMaxAttempts:   3,
		TOTPAttemptWindow: time.Minute,
		RecoveryCodeCount: 4,
		RecoveryCodeBytes: 8,
	}

	notify := &mockNotifier{}
	svc := NewTOTPService(
		totpRepo, memStore, auditRepo, "TestApp", totpCfg, enc, jwtMgr,
		WithTOTPUserRepo(userRepo),
		WithTOTPNotifier(notify),
		WithTOTPPasskeys(passkeyRepo),
	)

	u := &models.User{
		Username: "totpuser",
		Email:    "totpuser@example.com",
		Password: "hashedpassword",
		IsActive: true,
	}
	hp, _ := hash.HashPassword("CorrectPassword123!")
	u.Password = hp
	_ = userRepo.Create(ctx, u)

	// 1. Lock contention on Enable
	memStore.SetNX(fmt.Sprintf("totp:rotatelock:%d", u.ID), "1", time.Minute)
	if _, _, err := svc.Enable(ctx, u.ID, u.Email, ""); err != ErrRateLimited {
		t.Fatalf("expected ErrRateLimited when rotation lock held, got %v", err)
	}
	memStore.Delete(fmt.Sprintf("totp:rotatelock:%d", u.ID))

	// 2. Abandoned enrollment (old device exists but Enabled == false)
	_ = totpRepo.Upsert(ctx, &models.TOTPDevice{
		UserID:          u.ID,
		Secret:          "abandoned_secret",
		SecretEncrypted: "enc_abandoned",
		Enabled:         false,
	})
	secret1, url1, err := svc.Enable(ctx, u.ID, u.Email, "")
	if err != nil || secret1 == "" || url1 == "" {
		t.Fatalf("abandoned enrollment enable failed: %v", err)
	}
	d, _ := totpRepo.FindByUserID(ctx, u.ID)
	if d.Secret != "" {
		t.Fatal("expected plaintext secret to be wiped on re-enrollment")
	}

	// 3. Enable on already enabled device requires sudo token
	d.Enabled = true
	_ = totpRepo.Upsert(ctx, d)

	// No sudo token
	if _, _, err := svc.Enable(ctx, u.ID, u.Email, ""); err != ErrSudoRequired {
		t.Fatalf("expected ErrSudoRequired with no token, got %v", err)
	}
	// Bad token string
	if _, _, err := svc.Enable(ctx, u.ID, u.Email, "invalid.token"); err != ErrSudoRequired {
		t.Fatalf("expected ErrSudoRequired with invalid token, got %v", err)
	}
	// Wrong token type (e.g. Access token)
	accTok, _ := jwtMgr.Issue(u.ID, "user", u.Email, jwt.TokenTypeAccess, time.Hour)
	if _, _, err := svc.Enable(ctx, u.ID, u.Email, accTok); err != ErrSudoRequired {
		t.Fatalf("expected ErrSudoRequired with access token, got %v", err)
	}
	// Wrong user sudo token
	wrongSudo, _ := jwtMgr.Issue(u.ID+99, "user", "other@ex.com", jwt.TokenTypeSudo, time.Hour)
	if _, _, err := svc.Enable(ctx, u.ID, u.Email, wrongSudo); err != ErrSudoRequired {
		t.Fatalf("expected ErrSudoRequired with wrong user sudo, got %v", err)
	}
	// Valid sudo token
	validSudo, _ := jwtMgr.Issue(u.ID, "user", u.Email, jwt.TokenTypeSudo, time.Hour)
	newSec, _, err := svc.Enable(ctx, u.ID, u.Email, validSudo)
	if err != nil {
		t.Fatalf("enable with valid sudo failed: %v", err)
	}

	// 4. VerifyEnable branches
	// Brute-force lockout
	memStore.IncrBy(fmt.Sprintf("totp:fail:%d", u.ID), 5, time.Minute)
	if _, err := svc.VerifyEnable(ctx, u.ID, "123456"); err != ErrRateLimited {
		t.Fatalf("expected ErrRateLimited when brute-force exceeded, got %v", err)
	}
	memStore.Delete(fmt.Sprintf("totp:fail:%d", u.ID))

	// Lock contention on VerifyEnable
	memStore.SetNX(fmt.Sprintf("totp:rotatelock:%d", u.ID), "1", time.Minute)
	if _, err := svc.VerifyEnable(ctx, u.ID, "123456"); err != ErrRateLimited {
		t.Fatalf("expected ErrRateLimited when rotation lock held, got %v", err)
	}
	memStore.Delete(fmt.Sprintf("totp:rotatelock:%d", u.ID))

	// Missing device
	if _, err := svc.VerifyEnable(ctx, 99999, "123456"); err != ErrInvalidCode {
		t.Fatalf("expected ErrInvalidCode for missing device, got %v", err)
	}

	// Device enabled but not confirming
	dConfirming, _ := totpRepo.FindByUserID(ctx, u.ID)
	dConfirming.Enabled = true
	dConfirming.PendingSecretEncrypted = ""
	_ = totpRepo.Upsert(ctx, dConfirming)
	if _, err := svc.VerifyEnable(ctx, u.ID, "123456"); err != ErrInvalidInput {
		t.Fatalf("expected ErrInvalidInput for enabled device without pending secret, got %v", err)
	}

	// Corrupted pending secret
	dConfirming.PendingSecretEncrypted = "bad-encrypted-data"
	_ = totpRepo.Upsert(ctx, dConfirming)
	if _, err := svc.VerifyEnable(ctx, u.ID, "123456"); err == nil {
		t.Fatal("expected error for corrupted pending secret")
	}

	// Bad code on pending secret
	sealedNew, _ := enc.Encrypt(newSec)
	dConfirming.PendingSecretEncrypted = sealedNew
	_ = totpRepo.Upsert(ctx, dConfirming)
	if _, err := svc.VerifyEnable(ctx, u.ID, "000000"); err != ErrInvalidCode {
		t.Fatalf("expected ErrInvalidCode for bad code, got %v", err)
	}

	// Successful VerifyEnable on pending secret
	validCode, _ := totp.GenerateCode(newSec, time.Now())
	codes, err := svc.VerifyEnable(ctx, u.ID, validCode)
	if err != nil || len(codes) != 4 {
		t.Fatalf("VerifyEnable success failed: len=%d, err=%v", len(codes), err)
	}

	// 5. ViewRecoveryCodes branches
	// Bad TOTP code
	if _, err := svc.ViewRecoveryCodes(ctx, u.ID, "000000"); err != ErrInvalidCode {
		t.Fatalf("expected ErrInvalidCode on wrong totp code, got %v", err)
	}
	// Valid code views recovery codes
	vCode, _ := totp.GenerateCode(newSec, time.Now())
	viewedCodes, err := svc.ViewRecoveryCodes(ctx, u.ID, vCode)
	if err != nil || len(viewedCodes) != 4 {
		t.Fatalf("ViewRecoveryCodes failed: %v", err)
	}
	// Replay guard prevents immediate reuse of same code
	if _, err := svc.ViewRecoveryCodes(ctx, u.ID, vCode); err != ErrInvalidCode {
		t.Fatalf("expected replay guard rejection for same code, got %v", err)
	}

	// Corrupted recovery code in DB is gracefully skipped
	_ = totpRepo.ReplaceRecoveryCodes(ctx, u.ID, []*models.RecoveryCode{
		{UserID: u.ID, CodeHash: "h1", CodeEncrypted: ""},                 // legacy unencrypted row
		{UserID: u.ID, CodeHash: "h2", CodeEncrypted: "corrupted-secret"}, // bad encryption
		{UserID: u.ID, CodeHash: "h3", CodeEncrypted: func() string { s, _ := enc.Encrypt("good-code"); return s }()},
	})
	vCode2, _ := totp.GenerateCode(newSec, time.Now().Add(30*time.Second))
	skippedList, err := svc.ViewRecoveryCodes(ctx, u.ID, vCode2)
	if err != nil || len(skippedList) != 1 || skippedList[0] != "good-code" {
		t.Fatalf("expected 1 valid code after skipping legacy/corrupt, got %v, err=%v", skippedList, err)
	}

	// 6. RegenerateRecoveryCodes
	newRegenCodes, err := svc.RegenerateRecoveryCodes(ctx, u.ID)
	if err != nil || len(newRegenCodes) != 4 {
		t.Fatalf("RegenerateRecoveryCodes failed: len=%d, err=%v", len(newRegenCodes), err)
	}

	// 7. openActiveSecret branches
	// A: SecretEncrypted empty falls back to plaintext Secret
	plainRow := &models.TOTPDevice{UserID: u.ID, Secret: "PLAINSECRET", SecretEncrypted: ""}
	sPlain, err := svc.openActiveSecret(ctx, plainRow)
	if err != nil || sPlain != "PLAINSECRET" {
		t.Fatalf("expected plaintext fallback, got %s, err=%v", sPlain, err)
	}
	// B: SecretEncrypted unreadable and Secret empty -> ErrTOTPUnrecoverable
	badRow := &models.TOTPDevice{UserID: u.ID, Secret: "", SecretEncrypted: "bad-cipher"}
	if _, err := svc.openActiveSecret(ctx, badRow); !errors.Is(err, ErrTOTPUnrecoverable) {
		t.Fatalf("expected ErrTOTPUnrecoverable, got %v", err)
	}
	// C: SecretEncrypted unreadable and Secret present -> re-encrypts and returns Secret
	healRow := &models.TOTPDevice{UserID: 8888, Secret: "HEALME", SecretEncrypted: "bad-cipher"}
	sHealed, err := svc.openActiveSecret(ctx, healRow)
	if err != nil || sHealed != "HEALME" || healRow.SecretEncrypted == "bad-cipher" {
		t.Fatalf("expected healRow to re-seal, got %s, enc=%s, err=%v", sHealed, healRow.SecretEncrypted, err)
	}

	// 8. GetMFAMethods branches
	// User with TOTP only
	methods, err := svc.GetMFAMethods(ctx, u.ID)
	if err != nil || methods.DefaultMethod != "totp" || !methods.TOTPEnabled {
		t.Fatalf("expected TOTP as default method, got %+v", methods)
	}
	// User with Passkey attached
	_ = passkeyRepo.Create(ctx, &models.PasskeyCredential{
		UserID:       u.ID,
		CredentialID: []byte("cred-1"),
		PublicKey:    []byte("pub-1"),
	})
	methodsPk, err := svc.GetMFAMethods(ctx, u.ID)
	if err != nil || methodsPk.DefaultMethod != "passkey" || methodsPk.PasskeysCount != 1 {
		t.Fatalf("expected Passkey as default method, got %+v", methodsPk)
	}

	// 9. Disable branches
	// Create dummy device for 99999 so user not found check can run
	_ = totpRepo.Upsert(ctx, &models.TOTPDevice{UserID: 99999, Enabled: true})

	// Fallback password + code:
	// A. User not found
	if err := svc.Disable(ctx, 99999, "", "pass", "123456", "1.1.1.1"); err != ErrUserNotFound {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
	// B. Invalid password
	if err := svc.Disable(ctx, u.ID, "", "WrongPassword!", "123456", "1.1.1.1"); err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
	// C. Empty code
	if err := svc.Disable(ctx, u.ID, "", "CorrectPassword123!", "", "1.1.1.1"); err != ErrInvalidCode {
		t.Fatalf("expected ErrInvalidCode for empty code, got %v", err)
	}
	// D. Bad code
	if err := svc.Disable(ctx, u.ID, "", "CorrectPassword123!", "000000", "1.1.1.1"); err != ErrInvalidCode {
		t.Fatalf("expected ErrInvalidCode for wrong code, got %v", err)
	}
	// E. Valid password + valid recovery code disables device
	memStore.Delete(fmt.Sprintf("totp:fail:%d", u.ID))
	if err := svc.Disable(ctx, u.ID, "", "CorrectPassword123!", newRegenCodes[0], "1.1.1.1"); err != nil {
		t.Fatalf("Disable with password + recovery code failed: %v", err)
	}
	// Calling Disable again when already disabled returns nil (idempotent)
	if err := svc.Disable(ctx, u.ID, validSudo, "", "", "1.1.1.1"); err != nil {
		t.Fatalf("idempotent Disable should succeed, got %v", err)
	}

	// 10. openActiveSecret healing & unrecoverable branches
	secHealed, err := svc.openActiveSecret(ctx, &models.TOTPDevice{
		UserID:          u.ID,
		SecretEncrypted: "corrupted-ciphertext-that-fails-aes-gcm",
		Secret:          "JBSWY3DPEHPK3PXP",
	})
	if err != nil || secHealed != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("openActiveSecret healing failed: %s, err=%v", secHealed, err)
	}
	_, err = svc.openActiveSecret(ctx, &models.TOTPDevice{
		UserID:          u.ID,
		SecretEncrypted: "corrupted-ciphertext-that-fails-aes-gcm",
		Secret:          "",
	})
	if !errors.Is(err, ErrTOTPUnrecoverable) {
		t.Fatalf("expected ErrTOTPUnrecoverable, got %v", err)
	}
}

type mockFailingUserRepo struct {
	mockUserRepo
	updatePasswordErr          error
	resetFailedErr             error
	findByEmailErr             error
	incrementFailedAttemptsErr error
	createErr                  error
}

func (m *mockFailingUserRepo) Create(ctx context.Context, u *models.User) error {
	if m.createErr != nil {
		return m.createErr
	}
	return m.mockUserRepo.Create(ctx, u)
}

func (m *mockFailingUserRepo) IncrementFailedAttempts(ctx context.Context, u *models.User, lockUntil *time.Time) error {
	if m.incrementFailedAttemptsErr != nil {
		return m.incrementFailedAttemptsErr
	}
	return m.mockUserRepo.IncrementFailedAttempts(ctx, u, lockUntil)
}

func (m *mockFailingUserRepo) UpdatePassword(ctx context.Context, u *models.User, pwd string) error {
	if m.updatePasswordErr != nil {
		return m.updatePasswordErr
	}
	return m.mockUserRepo.UpdatePassword(ctx, u, pwd)
}

func (m *mockFailingUserRepo) ResetFailedAttempts(ctx context.Context, u *models.User) error {
	if m.resetFailedErr != nil {
		return m.resetFailedErr
	}
	return m.mockUserRepo.ResetFailedAttempts(ctx, u)
}

func (m *mockFailingUserRepo) FindByEmail(ctx context.Context, email string) (*models.User, error) {
	if m.findByEmailErr != nil {
		return nil, m.findByEmailErr
	}
	return m.mockUserRepo.FindByEmail(ctx, email)
}

type mockFailingTokenRepo struct {
	mockTokenRepo
	revokeAllErr    error
	revokeByIDErr   error
	revokeBySessErr error
}

func (m *mockFailingTokenRepo) RevokeAllForUser(ctx context.Context, userID uint) error {
	if m.revokeAllErr != nil {
		return m.revokeAllErr
	}
	return m.mockTokenRepo.RevokeAllForUser(ctx, userID)
}

func (m *mockFailingTokenRepo) RevokeByID(ctx context.Context, id, userID uint) error {
	if m.revokeByIDErr != nil {
		return m.revokeByIDErr
	}
	return m.mockTokenRepo.RevokeByID(ctx, id, userID)
}

func (m *mockFailingTokenRepo) RevokeBySession(ctx context.Context, sessionID string) error {
	if m.revokeBySessErr != nil {
		return m.revokeBySessErr
	}
	return m.mockTokenRepo.RevokeBySession(ctx, sessionID)
}

type mockFailingSessionRepo struct {
	mockSessionRepo
	revokeAllErr  error
	revokeByIDErr error
}

func (m *mockFailingSessionRepo) RevokeAllForUser(ctx context.Context, userID uint) error {
	if m.revokeAllErr != nil {
		return m.revokeAllErr
	}
	return m.mockSessionRepo.RevokeAllForUser(ctx, userID)
}

func (m *mockFailingSessionRepo) RevokeByID(ctx context.Context, id string, userID uint) error {
	if m.revokeByIDErr != nil {
		return m.revokeByIDErr
	}
	return m.mockSessionRepo.RevokeByID(ctx, id, userID)
}

func TestAuthService_EdgeAndFallbackBranches(t *testing.T) {
	ctx := context.Background()

	users := &mockFailingUserRepo{mockUserRepo: *newMockUserRepo()}
	tokens := &mockFailingTokenRepo{mockTokenRepo: *newMockTokenRepo()}
	sessions := &mockFailingSessionRepo{mockSessionRepo: *newMockSessionRepo()}
	audit := &mockAuditRepo{}
	memStore := store.NewInMemoryStore(0)
	jwtMgr := jwt.NewJWTManager("test-secret-long-enough-32-chars-!!", "test")
	notify := &mockNotifier{}

	authCfg := config.AuthConfig{MaxLoginAttempts: 3}
	rlCfg := config.RateLimitConfig{}
	jwtCfg := config.JWTConfig{AccessTTL: time.Hour, RefreshTTL: 24 * time.Hour, ResetTTL: time.Hour}

	svc := NewAuthService(
		users, tokens, nil, audit, memStore, jwtMgr,
		authCfg, rlCfg, jwtCfg, notify, NoOpCaptchaVerifier{}, geo.NewNoOpResolver(),
		nil, nil,
		WithSessionRepo(sessions),
	)

	u := &models.User{
		ID:       1,
		Email:    "fallback@example.com",
		Username: "fallbackuser",
		Password: "hashedpassword",
		IsActive: true,
	}
	_ = users.Create(ctx, u)

	// 1. applyCredentialChange sequential fallback error branches
	users.updatePasswordErr = errors.New("update pwd failed")
	if err := svc.applyCredentialChange(ctx, u, "newhash"); err == nil {
		t.Fatal("expected error on updatePasswordErr")
	}
	users.updatePasswordErr = nil

	users.resetFailedErr = errors.New("reset failed")
	if err := svc.applyCredentialChange(ctx, u, "newhash"); err == nil {
		t.Fatal("expected error on resetFailedErr")
	}
	users.resetFailedErr = nil

	tokens.revokeAllErr = errors.New("revoke tokens failed")
	if err := svc.applyCredentialChange(ctx, u, "newhash"); err == nil {
		t.Fatal("expected error on revokeAllErr")
	}
	tokens.revokeAllErr = nil

	sessions.revokeAllErr = errors.New("revoke sessions failed")
	if err := svc.applyCredentialChange(ctx, u, "newhash"); err == nil {
		t.Fatal("expected error on sessions.revokeAllErr")
	}
	sessions.revokeAllErr = nil

	// Successful sequential fallback
	if err := svc.applyCredentialChange(ctx, u, "newhash"); err != nil {
		t.Fatalf("sequential fallback failed: %v", err)
	}

	// 2. LogoutAll error branches
	tokens.revokeAllErr = errors.New("logoutall tokens err")
	if err := svc.LogoutAll(ctx, u.ID, "1.1.1.1"); err == nil {
		t.Fatal("expected error on LogoutAll token fail")
	}
	tokens.revokeAllErr = nil

	sessions.revokeAllErr = errors.New("logoutall sessions err")
	if err := svc.LogoutAll(ctx, u.ID, "1.1.1.1"); err == nil {
		t.Fatal("expected error on LogoutAll session fail")
	}
	sessions.revokeAllErr = nil

	// 3. ForgotPassword branches
	users.findByEmailErr = errors.New("db find failed")
	if err := svc.ForgotPassword(ctx, u.Email, "1.1.1.1"); err == nil {
		t.Fatal("expected error on ForgotPassword db failure")
	}
	users.findByEmailErr = nil

	// Unknown email returns nil (timing equalization)
	if err := svc.ForgotPassword(ctx, "nonexistent@ex.com", "1.1.1.1"); err != nil {
		t.Fatalf("expected nil for nonexistent email, got %v", err)
	}

	// 4. RevokeSession legacy mode (s.sessions == nil)
	svcLegacy := NewAuthService(
		users, tokens, nil, audit, memStore, jwtMgr,
		authCfg, rlCfg, jwtCfg, notify, NoOpCaptchaVerifier{}, geo.NewNoOpResolver(),
		nil, nil,
	)
	if err := svcLegacy.RevokeSession(ctx, "not-a-number", u.ID, "1.1.1.1"); err != ErrSessionNotFound {
		t.Fatalf("expected ErrSessionNotFound for non-numeric sessionID, got %v", err)
	}
	tokens.revokeByIDErr = gorm.ErrRecordNotFound
	if err := svcLegacy.RevokeSession(ctx, "123", u.ID, "1.1.1.1"); err != ErrSessionNotFound {
		t.Fatalf("expected ErrSessionNotFound for gorm.ErrRecordNotFound, got %v", err)
	}
	tokens.revokeByIDErr = errors.New("db error")
	if err := svcLegacy.RevokeSession(ctx, "123", u.ID, "1.1.1.1"); err == nil {
		t.Fatal("expected error on general db error in RevokeSession legacy")
	}
	tokens.revokeByIDErr = nil

	// 5. RevokeSession modern mode (s.sessions != nil)
	// Missing session
	if err := svc.RevokeSession(ctx, "nonexistent-sess", u.ID, "1.1.1.1"); err != ErrSessionNotFound {
		t.Fatalf("expected ErrSessionNotFound for missing session, got %v", err)
	}
	// Session exists but wrong user ID
	_ = sessions.Create(ctx, &models.Session{ID: "sess-user-2", UserID: 999})
	if err := svc.RevokeSession(ctx, "sess-user-2", u.ID, "1.1.1.1"); err != ErrSessionNotFound {
		t.Fatalf("expected ErrSessionNotFound for wrong user ID, got %v", err)
	}
	// sessions.RevokeByID returns gorm.ErrRecordNotFound
	_ = sessions.Create(ctx, &models.Session{ID: "sess-err-1", UserID: u.ID})
	sessions.revokeByIDErr = gorm.ErrRecordNotFound
	if err := svc.RevokeSession(ctx, "sess-err-1", u.ID, "1.1.1.1"); err != ErrSessionNotFound {
		t.Fatalf("expected ErrSessionNotFound on gorm.ErrRecordNotFound, got %v", err)
	}
	sessions.revokeByIDErr = errors.New("fail revoke")
	if err := svc.RevokeSession(ctx, "sess-err-1", u.ID, "1.1.1.1"); err == nil {
		t.Fatal("expected error on sessions.RevokeByID failure")
	}
	sessions.revokeByIDErr = nil

	// tokens.RevokeBySession fails
	tokens.revokeBySessErr = errors.New("fail tok revoke")
	if err := svc.RevokeSession(ctx, "sess-err-1", u.ID, "1.1.1.1"); err == nil {
		t.Fatal("expected error on tokens.RevokeBySession failure")
	}
	tokens.revokeBySessErr = nil

	// Success modern RevokeSession
	if err := svc.RevokeSession(ctx, "sess-err-1", u.ID, "1.1.1.1"); err != nil {
		t.Fatalf("modern RevokeSession success failed: %v", err)
	}

	// 6. SetPassword branches
	// User not found
	if err := svc.SetPassword(ctx, 99999, "NewPassword123!", "1.1.1.1"); err != ErrUserNotFound {
		t.Fatalf("expected ErrUserNotFound on SetPassword, got %v", err)
	}
	// User already has password
	if err := svc.SetPassword(ctx, u.ID, "NewPassword123!", "1.1.1.1"); err != ErrPasswordAlreadySet {
		t.Fatalf("expected ErrPasswordAlreadySet, got %v", err)
	}
	// User without password, but weak password provided
	uNoPwd := &models.User{ID: 2, Email: "nopwd@ex.com", Username: "nopwd", Password: "", IsActive: true}
	_ = users.Create(ctx, uNoPwd)
	if err := svc.SetPassword(ctx, uNoPwd.ID, "short", "1.1.1.1"); err == nil {
		t.Fatal("expected validation error on short password")
	}
}

func TestTrustedDeviceService_AllBranches(t *testing.T) {
	ctx := context.Background()

	// 1. Service with nil repo (safe fallbacks)
	nilSvc := NewTrustedDeviceService(nil)
	tok, exp, err := nilSvc.Issue(ctx, 1, "laptop", "1.1.1.1")
	if err != nil || tok == "" || exp.IsZero() {
		t.Fatalf("nil repo Issue failed: tok=%s, err=%v", tok, err)
	}
	if ok, err := nilSvc.Validate(ctx, 1, tok); ok || err != nil {
		t.Fatalf("nil repo Validate should return false, nil; got %v, %v", ok, err)
	}
	if list, err := nilSvc.ListByUser(ctx, 1); list != nil || err != nil {
		t.Fatalf("nil repo ListByUser should return nil, nil; got %v, %v", list, err)
	}
	if err := nilSvc.Revoke(ctx, 1, 1); err != nil {
		t.Fatalf("nil repo Revoke should return nil, got %v", err)
	}

	// 2. Service with SQLite repo
	db, err := gorm.Open(sqlite.Open("file:trusted_dev?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	_ = db.AutoMigrate(&models.TrustedDevice{})
	repo := repositories.NewTrustedDeviceRepository(db)
	svc := NewTrustedDeviceService(repo)

	// Issue token
	devTok, _, err := svc.Issue(ctx, 10, "MacBook Pro", "10.0.0.1")
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}

	// Validate empty token
	if ok, err := svc.Validate(ctx, 10, ""); ok || err != nil {
		t.Fatalf("Validate empty token should be false, got %v, %v", ok, err)
	}
	// Validate nonexistent token
	if ok, err := svc.Validate(ctx, 10, "nonexistent"); ok || err != nil {
		t.Fatalf("Validate nonexistent token should be false, got %v, %v", ok, err)
	}
	// Validate wrong user ID
	if ok, err := svc.Validate(ctx, 999, devTok); ok || err != nil {
		t.Fatalf("Validate wrong user should be false, got %v, %v", ok, err)
	}
	// Validate valid token
	if ok, err := svc.Validate(ctx, 10, devTok); !ok || err != nil {
		t.Fatalf("Validate valid token should be true, got %v, %v", ok, err)
	}

	// Validate expired token
	h := hashDeviceToken("expired-tok")
	_ = repo.Create(ctx, &models.TrustedDevice{
		UserID:     10,
		DeviceHash: h,
		ExpiresAt:  time.Now().Add(-time.Hour),
		Revoked:    false,
	})
	if ok, err := svc.Validate(ctx, 10, "expired-tok"); ok || err != nil {
		t.Fatalf("Validate expired token should be false, got %v, %v", ok, err)
	}

	// Validate revoked token
	hRev := hashDeviceToken("revoked-tok")
	_ = repo.Create(ctx, &models.TrustedDevice{
		UserID:     10,
		DeviceHash: hRev,
		ExpiresAt:  time.Now().Add(time.Hour),
		Revoked:    true,
	})
	if ok, err := svc.Validate(ctx, 10, "revoked-tok"); ok || err != nil {
		t.Fatalf("Validate revoked token should be false, got %v, %v", ok, err)
	}

	// ListByUser
	devices, err := svc.ListByUser(ctx, 10)
	if err != nil || len(devices) < 1 {
		t.Fatalf("ListByUser failed: len=%d, err=%v", len(devices), err)
	}

	// Revoke
	if err := svc.Revoke(ctx, devices[0].ID, 10); err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}
}

func TestWebhookService_AntiSSRFAndBranches(t *testing.T) {
	ctx := context.Background()

	svc := NewWebhookService(nil)

	// ValidateURL edge cases
	if err := svc.ValidateURL("bad-url"); err != ErrInvalidWebhookURL {
		t.Fatalf("expected ErrInvalidWebhookURL, got %v", err)
	}
	if err := svc.ValidateURL("ftp://example.com/hook"); err != ErrInvalidWebhookURL {
		t.Fatalf("expected ErrInvalidWebhookURL for ftp, got %v", err)
	}
	if err := svc.ValidateURL("http:///no-host"); err != ErrInvalidWebhookURL {
		t.Fatalf("expected ErrInvalidWebhookURL for empty host, got %v", err)
	}
	// Loopback blocked by default
	if err := svc.ValidateURL("http://127.0.0.1:8080/hook"); err != ErrWebhookSSRFBlocked {
		t.Fatalf("expected ErrWebhookSSRFBlocked for loopback, got %v", err)
	}
	// SetAllowLocalhost
	svc.SetAllowLocalhost(true)
	if err := svc.ValidateURL("http://127.0.0.1:8080/hook"); err != nil {
		t.Fatalf("expected nil when allowLocalhost is true, got %v", err)
	}
	svc.SetAllowLocalhost(false)

	// blockedIP helper directly
	if !blockedIP(net.ParseIP("127.0.0.1")) {
		t.Fatal("expected 127.0.0.1 to be blocked")
	}
	if !blockedIP(net.ParseIP("10.0.0.1")) {
		t.Fatal("expected 10.0.0.1 to be blocked")
	}
	if !blockedIP(net.ParseIP("192.168.1.1")) {
		t.Fatal("expected 192.168.1.1 to be blocked")
	}
	if !blockedIP(net.ParseIP("::1")) {
		t.Fatal("expected ::1 to be blocked")
	}
	if blockedIP(net.ParseIP("93.184.216.34")) {
		t.Fatal("expected public IP not to be blocked")
	}

	// RegisterEndpoint invalid URL
	if _, err := svc.RegisterEndpoint(ctx, "t1", "http://127.0.0.1/bad", "ev"); err == nil {
		t.Fatal("expected error on RegisterEndpoint with blocked IP")
	}

	// EnqueueEvent with nil repo
	if err := svc.EnqueueEvent(ctx, "t1", "test.event", nil); err != nil {
		t.Fatalf("expected nil from EnqueueEvent with nil repo, got %v", err)
	}

	whRepo := &mockFinalWebhookRepo{}
	svcWired := NewWebhookService(whRepo)
	svcWired.SetAllowLocalhost(true)

	// Mock server returning 200
	srv200 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv200.Close()

	// Mock server returning 500
	srv500 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv500.Close()

	ep, err := svcWired.RegisterEndpoint(ctx, "t1", srv200.URL, "user.created")
	if err != nil || ep == nil {
		t.Fatalf("RegisterEndpoint failed: %v", err)
	}

	if err := svcWired.EnqueueEvent(ctx, "t1", "user.created", map[string]string{"foo": "bar"}); err != nil {
		t.Fatalf("EnqueueEvent failed: %v", err)
	}

	// DeliverOne 200 OK
	d200 := &models.WebhookDelivery{
		ID:       "d-200",
		Payload:  `{"foo":"bar"}`,
		Event:    "user.created",
		Attempts: 0,
	}
	if err := svcWired.DeliverOne(ctx, d200, "test-secret", srv200.URL); err != nil {
		t.Fatalf("DeliverOne 200 failed: %v", err)
	}

	// DeliverOne 500 status code with retry (attempts < 5)
	d500 := &models.WebhookDelivery{
		ID:       "d-500",
		Payload:  `{"foo":"bar"}`,
		Event:    "user.created",
		Attempts: 1,
	}
	if err := svcWired.DeliverOne(ctx, d500, "test-secret", srv500.URL); err == nil {
		t.Fatal("expected error from DeliverOne 500")
	}

	// DeliverOne 500 status code with max attempts reached (attempts >= 5)
	d500Max := &models.WebhookDelivery{
		ID:       "d-500-max",
		Payload:  `{"foo":"bar"}`,
		Event:    "user.created",
		Attempts: 4, // incremented to 5 -> status "failed"
	}
	if err := svcWired.DeliverOne(ctx, d500Max, "test-secret", srv500.URL); err == nil {
		t.Fatal("expected error from DeliverOne 500 max")
	}

	// DeliverOne blocked by SSRF
	svcWired.SetAllowLocalhost(false)
	if err := svcWired.DeliverOne(ctx, d200, "test-secret", "http://127.0.0.1:8080/hook"); err != ErrWebhookSSRFBlocked {
		t.Fatalf("expected ErrWebhookSSRFBlocked, got %v", err)
	}

	// SignPayload
	sig := SignPayload("secret", "payload")
	if !strings.HasPrefix(sig, "sha256=") {
		t.Fatalf("expected sha256= prefix, got %s", sig)
	}
}

type mockFinalWebhookRepo struct {
	endpoints     []models.WebhookEndpoint
	deliveries    []*models.WebhookDelivery
	statusUpdates []string
}

func (m *mockFinalWebhookRepo) CreateEndpoint(ctx context.Context, ep *models.WebhookEndpoint) error {
	m.endpoints = append(m.endpoints, *ep)
	return nil
}

func (m *mockFinalWebhookRepo) FindActiveEndpointsByEvent(ctx context.Context, tenantID, event string) ([]models.WebhookEndpoint, error) {
	return m.endpoints, nil
}

func (m *mockFinalWebhookRepo) CreateDelivery(ctx context.Context, d *models.WebhookDelivery) error {
	m.deliveries = append(m.deliveries, d)
	return nil
}

func (m *mockFinalWebhookRepo) GetPendingDeliveries(ctx context.Context, limit int) ([]models.WebhookDelivery, error) {
	return nil, nil
}

func (m *mockFinalWebhookRepo) UpdateDeliveryStatus(ctx context.Context, id string, status string, attempts int, nextRetry *time.Time, respStatus *int, errMsg string) error {
	m.statusUpdates = append(m.statusUpdates, status)
	return nil
}

func TestAsyncAuditWriter_DrainAndSyncMode(t *testing.T) {
	ctx := context.Background()

	// 1. SyncMode writer
	syncWriter := NewAsyncAuditWriter(&mockAuditRepo{}, nil, config.AuditConfig{BufferSize: 0})
	syncWriter.Record(ctx, &models.AuditLog{Event: "sync-event"})
	syncWriter.Close()

	// 2. Nil repo methods
	nilRepoWriter := NewAsyncAuditWriter(nil, nil, config.AuditConfig{BufferSize: 0})
	if rows, count, err := nilRepoWriter.FindByUserIDPaginated(ctx, 1, 1, 10); rows != nil || count != 0 || err != nil {
		t.Fatalf("expected nil from FindByUserIDPaginated with nil repo")
	}
	if err := nilRepoWriter.AnonymizeUser(ctx, 1); err != nil {
		t.Fatalf("expected nil from AnonymizeUser with nil repo")
	}
	if rows, err := nilRepoWriter.StreamAll(ctx, "default"); rows != nil || err != nil {
		t.Fatalf("expected nil from StreamAll with nil repo")
	}

	// 3. Truncate detail with multibyte boundary
	entry := &models.AuditLog{
		Detail: strings.Repeat("a", 1023) + "€€€",
	}
	truncateDetail(entry)
	if len(entry.Detail) > maxAuditDetail {
		t.Fatalf("expected len <= %d, got %d", maxAuditDetail, len(entry.Detail))
	}

	// 4. Record after Close writes direct without panic
	asyncWriter := NewAsyncAuditWriter(&mockAuditRepo{}, nil, config.AuditConfig{
		BufferSize: 10,
		FlushBatch: 2,
	})
	asyncWriter.Close()
	asyncWriter.Record(ctx, &models.AuditLog{Event: "after-close"})
}

func TestAdminService_ExportAuditLogs_Branches(t *testing.T) {
	ctx := context.Background()

	// Nil audits
	adminSvc := NewAdminService(nil, nil, nil, nil, nil)
	data, mime, err := adminSvc.ExportAuditLogs(ctx, "csv")
	if data != nil || mime != "" || err != nil {
		t.Fatalf("expected nil data for nil audits, got data=%v, err=%v", data, err)
	}
}

func TestMiscHelpers_EdgeCases(t *testing.T) {
	ctx := context.Background()

	// 1. isDisposableEmail edge cases
	if isDisposableEmail("user@") {
		t.Fatal("user@ should not be disposable")
	}
	if isDisposableEmail("no-at-sign") {
		t.Fatal("no-at-sign should not be disposable")
	}
	if !isDisposableEmail("attacker@mailinator.com") {
		t.Fatal("mailinator.com should be disposable")
	}
	if isDisposableEmail("alice@gmail.com") {
		t.Fatal("gmail.com should not be disposable")
	}

	// 2. generateUsernameFromEmail
	if u := generateUsernameFromEmail("testuser@domain.com"); u != "testuser" {
		t.Fatalf("expected testuser, got %s", u)
	}
	if u := generateUsernameFromEmail("standalone"); u != "standalone" {
		t.Fatalf("expected standalone, got %s", u)
	}

	// 3. claimBool and claimString
	claims := map[string]interface{}{
		"str":  "hello",
		"num":  12345,
		"b1":   true,
		"b2":   "true",
		"b3":   "false",
		"b4":   "invalid-bool",
		"bnum": 999,
	}
	if claimString(claims, "str") != "hello" || claimString(claims, "num") != "" {
		t.Fatal("claimString failed")
	}
	if !claimBool(claims, "b1") || !claimBool(claims, "b2") || claimBool(claims, "b3") || claimBool(claims, "b4") || claimBool(claims, "bnum") {
		t.Fatal("claimBool failed")
	}

	// 4. BreachedPasswordChecker edge cases
	if (&BreachedPasswordChecker{}).Breached(ctx, "") {
		t.Fatal("empty password should return false")
	}
	var nilChecker *BreachedPasswordChecker
	if nilChecker.Breached(ctx, "pass") {
		t.Fatal("nil checker should return false")
	}
	badUrlChecker := NewBreachedPasswordChecker("://invalid-url", time.Second)
	if badUrlChecker.Breached(ctx, "password") {
		t.Fatal("invalid url checker should return false")
	}

	// 5. TurnstileVerifier edge cases
	tv := NewTurnstileVerifier("secret").WithEndpoint("://bad-endpoint")
	if err := tv.Verify(ctx, "tok"); err == nil {
		t.Fatal("expected error on invalid endpoint")
	}
	// Server returns non-JSON body
	srvNonJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html>bad gateway</html>"))
	}))
	defer srvNonJSON.Close()
	tvJSON := NewTurnstileVerifier("secret").WithEndpoint(srvNonJSON.URL)
	if err := tvJSON.Verify(ctx, "tok"); err == nil {
		t.Fatal("expected json decode error from non-JSON response")
	}

	// 6. mapDuplicateKey branches
	if err := mapDuplicateKey("a@b.com", "u", &mysql.MySQLError{Number: 1062, Message: "Duplicate entry for key 'users.email'"}); err != ErrEmailExists {
		t.Fatalf("expected ErrEmailExists, got %v", err)
	}
	if err := mapDuplicateKey("a@b.com", "u", &mysql.MySQLError{Number: 1062, Message: "Duplicate entry for key 'users.username'"}); err != ErrUsernameExists {
		t.Fatalf("expected ErrUsernameExists, got %v", err)
	}
	if err := mapDuplicateKey("a@b.com", "u", &mysql.MySQLError{Number: 1062, Message: "Duplicate entry for key 'PRIMARY'"}); err != ErrEmailExists {
		t.Fatalf("expected ErrEmailExists for default mysql dup, got %v", err)
	}
	if err := mapDuplicateKey("a@b.com", "u", errors.New("non-mysql")); err == nil || !strings.Contains(err.Error(), "non-mysql") {
		t.Fatalf("expected non-mysql error, got %v", err)
	}

	// 7. validatePassword edge cases
	if err := validatePassword(strings.Repeat("a", 1000), 0); err != ErrPasswordTooWeak {
		t.Fatalf("expected ErrPasswordTooWeak for password exceeding max length, got %v", err)
	}
	if err := validatePassword("ValidPass123!", 0, "", "   "); err != nil {
		t.Fatalf("validatePassword failed with empty sanitized inputs: %v", err)
	}
}

func TestAuthService_PasswordBranches(t *testing.T) {
	ctx := context.Background()

	users := newMockUserRepo()
	tokens := newMockTokenRepo()
	audit := &mockAuditRepo{}
	memStore := store.NewInMemoryStore(0)
	jwtMgr := jwt.NewJWTManager("test-secret-long-enough-32-chars-!!", "test")
	notify := &mockNotifier{}

	authCfg := config.AuthConfig{MaxLoginAttempts: 3}
	rlCfg := config.RateLimitConfig{}
	jwtCfg := config.JWTConfig{
		AccessTTL:     time.Hour,
		RefreshTTL:    24 * time.Hour,
		ResetTTL:      time.Hour,
		MFAPendingTTL: 5 * time.Minute,
	}

	// Breached checker mock
	srvBreached := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return breached hash suffix for "BreachedPwd123!"
		prefix, suffix := calculateHIBPSHA1Prefix("BreachedPwd123!")
		if strings.HasSuffix(r.URL.Path, prefix) {
			_, _ = w.Write([]byte(suffix + ":5\r\n"))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srvBreached.Close()
	breachedChecker := NewBreachedPasswordChecker(srvBreached.URL+"/", time.Second)

	totpRepo := newMockTOTPRepo()
	svc := NewAuthService(
		users, tokens, nil, audit, memStore, jwtMgr,
		authCfg, rlCfg, jwtCfg, notify, NoOpCaptchaVerifier{}, geo.NewNoOpResolver(),
		totpRepo, nil,
		WithBreachedPasswordChecker(breachedChecker),
	)

	u := &models.User{
		Username: "pwduser",
		Email:    "pwduser@example.com",
		Password: "hashed",
		IsActive: true,
	}
	h, _ := hash.HashPassword("OldValidPwd123!")
	u.Password = h
	_ = users.Create(ctx, u)

	// 1. ResetPassword
	// Invalid token
	if err := svc.ResetPassword(ctx, ResetPasswordInput{Token: "bad-token", NewPassword: "NewValidPwd123!"}, "1.1.1.1"); err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
	// Wrong token type (e.g. Access token)
	accTok, _ := jwtMgr.Issue(u.ID, u.Role, u.Email, jwt.TokenTypeAccess, time.Hour)
	if err := svc.ResetPassword(ctx, ResetPasswordInput{Token: accTok, NewPassword: "NewValidPwd123!"}, "1.1.1.1"); err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for access token, got %v", err)
	}
	// User not found
	resetTokMissingUser, _ := jwtMgr.Issue(99999, "user", "ghost@ex.com", jwt.TokenTypeReset, time.Hour)
	if err := svc.ResetPassword(ctx, ResetPasswordInput{Token: resetTokMissingUser, NewPassword: "NewValidPwd123!"}, "1.1.1.1"); err != ErrUserNotFound {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
	// Weak password
	resetTok, _ := jwtMgr.Issue(u.ID, u.Role, u.Email, jwt.TokenTypeReset, time.Hour)
	if err := svc.ResetPassword(ctx, ResetPasswordInput{Token: resetTok, NewPassword: "short"}, "1.1.1.1"); err == nil {
		t.Fatal("expected validation error on weak reset password")
	}
	// Breached password
	if err := svc.ResetPassword(ctx, ResetPasswordInput{Token: resetTok, NewPassword: "BreachedPwd123!"}, "1.1.1.1"); err != ErrPasswordBreached {
		t.Fatalf("expected ErrPasswordBreached, got %v", err)
	}
	// Successful reset
	if err := svc.ResetPassword(ctx, ResetPasswordInput{Token: resetTok, NewPassword: "NewValidPwd123!"}, "1.1.1.1"); err != nil {
		t.Fatalf("ResetPassword failed: %v", err)
	}
	// Replay of same token returns ErrInvalidToken
	if err := svc.ResetPassword(ctx, ResetPasswordInput{Token: resetTok, NewPassword: "NewValidPwd123!"}, "1.1.1.1"); err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken on replayed reset token, got %v", err)
	}

	// 2. ChangePassword
	// User not found
	if err := svc.ChangePassword(ctx, ChangePasswordInput{UserID: 99999, OldPassword: "pwd", NewPassword: "new"}, "1.1.1.1"); err != ErrUserNotFound {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
	// Wrong old password
	if err := svc.ChangePassword(ctx, ChangePasswordInput{UserID: u.ID, OldPassword: "WrongOldPassword!", NewPassword: "BrandNewPwd123!"}, "1.1.1.1"); err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
	// Weak new password
	if err := svc.ChangePassword(ctx, ChangePasswordInput{UserID: u.ID, OldPassword: "NewValidPwd123!", NewPassword: "short"}, "1.1.1.1"); err == nil {
		t.Fatal("expected validation error on short new password")
	}
	// Breached new password
	if err := svc.ChangePassword(ctx, ChangePasswordInput{UserID: u.ID, OldPassword: "NewValidPwd123!", NewPassword: "BreachedPwd123!"}, "1.1.1.1"); err != ErrPasswordBreached {
		t.Fatalf("expected ErrPasswordBreached, got %v", err)
	}
	// Successful change
	if err := svc.ChangePassword(ctx, ChangePasswordInput{UserID: u.ID, OldPassword: "NewValidPwd123!", NewPassword: "BrandNewPwd123!"}, "1.1.1.1"); err != nil {
		t.Fatalf("ChangePassword failed: %v", err)
	}

	// 3. CheckMFAOrIssueTokens branches
	pair, prof, pending, err := svc.CheckMFAOrIssueTokens(ctx, u, "1.1.1.1", "agent", "custom-detail")
	if err != nil || pair.AccessToken == "" || prof.Email != u.Email || pending != nil {
		t.Fatalf("CheckMFAOrIssueTokens direct issue failed: %v", err)
	}

	// 3B. With TOTP enabled
	_ = totpRepo.Upsert(ctx, &models.TOTPDevice{
		UserID:  u.ID,
		Secret:  "JBSWY3DPEHPK3PXP",
		Enabled: true,
	})
	pairMFA, profMFA, pendingMFA, err := svc.CheckMFAOrIssueTokens(ctx, u, "1.1.1.1", "agent", "custom-detail")
	if err != nil || pairMFA.AccessToken != "" || profMFA.Email != "" || pendingMFA == nil || !pendingMFA.MFARequired || pendingMFA.MFAToken == "" {
		t.Fatalf("expected MFA pending result, got %v, %v, %v, %v", pairMFA, profMFA, pendingMFA, err)
	}

	// 4. handleTokenReuse legacy branch
	rtLegacy := &models.RefreshToken{
		UserID:    u.ID,
		TokenHash: "tok-reuse-leg",
		SessionID: "",
	}
	svc.handleTokenReuse(ctx, rtLegacy, "1.1.1.1", "legacy reuse")

	// 5. consumeSingleUseToken branches
	memStore.Set("jti:already-used", "used", time.Hour)
	if ok := svc.consumeSingleUseToken(ctx, "already-used", time.Hour); ok {
		t.Fatal("expected false for already-used token in store")
	}
	if ok := svc.consumeSingleUseToken(ctx, "fresh-fresh-fresh", time.Hour); !ok {
		t.Fatal("expected true for fresh token")
	}

	// 6. CurrentPwdVersion int and string cache types
	memStore.Set("pwdver:101", 42, time.Minute)
	vInt, err := svc.CurrentPwdVersion(ctx, 101)
	if err != nil || vInt != 42 {
		t.Fatalf("expected 42, got %d, err=%v", vInt, err)
	}
	memStore.Set("pwdver:102", "99", time.Minute)
	vStr, err := svc.CurrentPwdVersion(ctx, 102)
	if err != nil || vStr != 99 {
		t.Fatalf("expected 99, got %d, err=%v", vStr, err)
	}

	_ = totpRepo
}

func TestOAuthService_UnlinkAndLink(t *testing.T) {
	ctx := context.Background()

	db, err := gorm.Open(sqlite.Open("file:oauth_unlink?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	_ = db.AutoMigrate(
		&models.User{},
		&models.OAuthIdentity{},
		&models.PasskeyCredential{},
		&models.AuditLog{},
	)

	userRepo := repositories.NewUserRepository(db)
	oauthRepo := repositories.NewOAuthIdentityRepository(db)
	passkeyRepo := repositories.NewPasskeyRepository(db)
	auditRepo := repositories.NewAuditRepository(db)
	memStore := store.NewInMemoryStore(0)
	notify := &mockNotifier{}

	svc := NewOAuthService(
		userRepo, oauthRepo, memStore, nil, nil, nil,
		WithOAuthAudits(auditRepo),
		WithOAuthNotifier(notify),
		WithOAuthPasskeys(passkeyRepo),
	)

	// User without password and without passkey
	uOAuthOnly := &models.User{
		Username: "oauthonly",
		Email:    "oauthonly@example.com",
		Password: "", // No password
		IsActive: true,
	}
	_ = userRepo.Create(ctx, uOAuthOnly)
	_ = oauthRepo.Create(ctx, &models.OAuthIdentity{
		UserID:         uOAuthOnly.ID,
		Provider:       "google",
		ProviderUserID: "sub-oauth-1",
	})

	// 1. Unlink nonexistent identity
	if err := svc.Unlink(ctx, 99999, "google", "1.1.1.1"); err != ErrUserNotFound {
		t.Fatalf("expected ErrUserNotFound for missing identity, got %v", err)
	}

	// 2. Unlink user's only login method (no password, no passkey) -> ErrCannotUnlinkOnlyMethod
	if err := svc.Unlink(ctx, uOAuthOnly.ID, "google", "1.1.1.1"); err != ErrCannotUnlinkOnlyMethod {
		t.Fatalf("expected ErrCannotUnlinkOnlyMethod, got %v", err)
	}

	// 3. User adds passkey -> now allowed to unlink OAuth!
	_ = passkeyRepo.Create(ctx, &models.PasskeyCredential{
		UserID:       uOAuthOnly.ID,
		CredentialID: []byte("passkey-cred-id"),
		PublicKey:    []byte("pubkey-bytes"),
	})
	if err := svc.Unlink(ctx, uOAuthOnly.ID, "google", "1.1.1.1"); err != nil {
		t.Fatalf("Unlink with passkey should succeed, got %v", err)
	}

	// 4. User with password -> allowed to unlink
	uPwd := &models.User{
		Username: "pwduser_unlink",
		Email:    "pwduser_unlink@example.com",
		Password: "hashedpassword",
		IsActive: true,
	}
	_ = userRepo.Create(ctx, uPwd)
	_ = oauthRepo.Create(ctx, &models.OAuthIdentity{
		UserID:         uPwd.ID,
		Provider:       "google",
		ProviderUserID: "sub-oauth-2",
	})
	if err := svc.Unlink(ctx, uPwd.ID, "google", "1.1.1.1"); err != nil {
		t.Fatalf("Unlink with password should succeed, got %v", err)
	}

	// 5. OAuth helper and ConsumeState branches
	if un := generateUsernameFromEmail("noatsign"); un != "noatsign" {
		t.Fatalf("expected noatsign, got %s", un)
	}
	suf, err := randomSuffix()
	if err != nil || len(suf) == 0 {
		t.Fatalf("randomSuffix failed: %v", err)
	}
	ver, err := pkceVerifier()
	if err != nil || len(ver) == 0 {
		t.Fatalf("pkceVerifier failed: %v", err)
	}
	if chal := s256Challenge(ver); len(chal) == 0 {
		t.Fatal("s256Challenge failed")
	}

	// ConsumeState branches
	if _, err := svc.ConsumeState(ctx, ""); err != ErrOAuthStateInvalid {
		t.Fatalf("expected ErrOAuthStateInvalid for empty state, got %v", err)
	}
	if _, err := svc.ConsumeState(ctx, "missing-state"); err != ErrOAuthStateInvalid {
		t.Fatalf("expected ErrOAuthStateInvalid for missing state, got %v", err)
	}
	memStore.Set(oauthChallengeKey("raw-int"), 12345, time.Minute)
	if _, err := svc.ConsumeState(ctx, "raw-int"); err != ErrOAuthStateInvalid {
		t.Fatalf("expected ErrOAuthStateInvalid for non-string, got %v", err)
	}
	memStore.Set(oauthChallengeKey("bad-json"), "{invalid", time.Minute)
	if _, err := svc.ConsumeState(ctx, "bad-json"); err != ErrOAuthStateInvalid {
		t.Fatalf("expected ErrOAuthStateInvalid for bad json, got %v", err)
	}
	memStore.Set(oauthChallengeKey("empty-ver"), `{"Verifier":""}`, time.Minute)
	if _, err := svc.ConsumeState(ctx, "empty-ver"); err != ErrOAuthStateInvalid {
		t.Fatalf("expected ErrOAuthStateInvalid for empty verifier, got %v", err)
	}

	// 6. findOrCreateUser branches: dangling identity, already linked, and username collision
	_ = oauthRepo.Create(ctx, &models.OAuthIdentity{
		UserID:         88888,
		Provider:       "google",
		ProviderUserID: "dangling-sub",
	})
	if _, err := svc.findOrCreateUser(ctx, &GoogleIDTokenClaims{Sub: "dangling-sub"}, "dangling@example.com", "1.1.1.1"); err != ErrUserNotFound {
		t.Fatalf("expected ErrUserNotFound for dangling identity, got %v", err)
	}

	_ = oauthRepo.Create(ctx, &models.OAuthIdentity{
		UserID:         uPwd.ID,
		Provider:       "google",
		ProviderUserID: "sub-already-linked-test",
	})
	if uFound, err := svc.findOrCreateUser(ctx, &GoogleIDTokenClaims{Sub: "sub-already-linked-test"}, "anything@example.com", "1.1.1.1"); err != nil || uFound.ID != uPwd.ID {
		t.Fatalf("expected existing linked user, got %v, err=%v", uFound, err)
	}

	uCol := &models.User{
		Username: "collisionuser",
		Email:    "collisionuser@example.com",
		Password: "hashedpassword",
		IsActive: true,
	}
	_ = userRepo.Create(ctx, uCol)
	uCreated, err := svc.findOrCreateUser(ctx, &GoogleIDTokenClaims{Sub: "new-sub-col", Name: "Collided"}, "collisionuser@another.com", "1.1.1.1")
	if err != nil || !strings.HasPrefix(uCreated.Username, "collisionuser") {
		t.Fatalf("expected username collision resolution, got %v, err=%v", uCreated, err)
	}
}

func TestAdminService_UnlockAndForceLogout(t *testing.T) {
	ctx := context.Background()

	db, err := gorm.Open(sqlite.Open("file:admin_test?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	_ = db.AutoMigrate(&models.User{}, &models.Session{}, &models.RefreshToken{}, &models.AuditLog{})
	users := repositories.NewUserRepository(db)
	sessions := repositories.NewSessionRepository(db)
	tokens := repositories.NewRefreshTokenRepository(db)
	audit := repositories.NewAuditRepository(db)
	memStore := store.NewInMemoryStore(0)

	adminSvc := NewAdminService(users, sessions, tokens, audit, memStore)

	u := &models.User{
		Username: "targetuser",
		Email:    "target@example.com",
		IsActive: true,
	}
	_ = users.Create(ctx, u)

	// 1. UnlockUser
	// Target user not found
	if err := adminSvc.UnlockUser(ctx, 1, 99999, "1.1.1.1"); err != ErrUserNotFound {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
	// Success
	if err := adminSvc.UnlockUser(ctx, 1, u.ID, "1.1.1.1"); err != nil {
		t.Fatalf("UnlockUser failed: %v", err)
	}

	// 2. ForceLogout
	// Target user not found
	if err := adminSvc.ForceLogout(ctx, 1, 99999, "1.1.1.1"); err != ErrUserNotFound {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
	// Success
	if err := adminSvc.ForceLogout(ctx, 1, u.ID, "1.1.1.1"); err != nil {
		t.Fatalf("ForceLogout failed: %v", err)
	}

	// 3. ListTenantSessions
	_ = sessions.Create(ctx, &models.Session{
		ID:        "sess-admin-1",
		TenantID:  "default",
		UserID:    u.ID,
		IPAddress: "1.2.3.4",
		UserAgent: "Mozilla",
		ExpiresAt: time.Now().Add(time.Hour),
		Revoked:   false,
	})
	sessList, err := adminSvc.ListTenantSessions(ctx)
	if err != nil || len(sessList) == 0 {
		t.Fatalf("ListTenantSessions failed: len=%d, err=%v", len(sessList), err)
	}

	// 4. LockUser branches
	if err := adminSvc.LockUser(ctx, u.ID, u.ID, time.Hour, "1.1.1.1"); err != ErrCannotLockSelf {
		t.Fatalf("expected ErrCannotLockSelf, got %v", err)
	}
	if err := adminSvc.LockUser(ctx, 999, 99999, time.Hour, "1.1.1.1"); err != ErrUserNotFound {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
	// lockDuration <= 0
	if err := adminSvc.LockUser(ctx, 999, u.ID, 0, "1.1.1.1"); err != nil {
		t.Fatalf("LockUser with duration<=0 failed: %v", err)
	}

	// 5. AdminService nil repos fallback
	adminSvcNil := NewAdminService(users, nil, nil, nil, nil)
	nilSess, err := adminSvcNil.ListTenantSessions(ctx)
	if err != nil || nilSess != nil {
		t.Fatalf("expected nil sessions, got %v, err=%v", nilSess, err)
	}
	nilBytes, nilMime, err := adminSvcNil.ExportAuditLogs(ctx, "csv")
	if err != nil || nilBytes != nil || nilMime != "" {
		t.Fatalf("expected nil export, got %v, %v, %v", nilBytes, nilMime, err)
	}

	// 6. ListUsers
	userList, total, err := adminSvc.ListUsers(ctx, 1, 10, "")
	if err != nil || total == 0 || len(userList) == 0 {
		t.Fatalf("ListUsers failed: total=%d, len=%d, err=%v", total, len(userList), err)
	}

	// 7. ExportAuditLogs ndjson and csv with nil UserID
	audit.Record(ctx, &models.AuditLog{
		TenantID:  "default",
		UserID:    nil,
		Email:     "system@internal",
		Event:     models.AuditEventAdminAction,
		IPAddress: "127.0.0.1",
		Success:   true,
	})
	ndjsonBytes, ndjsonMime, err := adminSvc.ExportAuditLogs(ctx, "ndjson")
	if err != nil || len(ndjsonBytes) == 0 || ndjsonMime != "application/x-ndjson" {
		t.Fatalf("ExportAuditLogs ndjson failed: len=%d, mime=%s, err=%v", len(ndjsonBytes), ndjsonMime, err)
	}
	csvBytes, csvMime, err := adminSvc.ExportAuditLogs(ctx, "csv")
	if err != nil || len(csvBytes) == 0 || csvMime != "text/csv" {
		t.Fatalf("ExportAuditLogs csv failed: len=%d, mime=%s, err=%v", len(csvBytes), csvMime, err)
	}
}

func TestSMTPNotifier_ProtocolNegotiation(t *testing.T) {
	ctx := context.Background()

	// 1. Header and address validation helpers
	if err := validHeaderValue("Clean Subject"); err != nil {
		t.Fatal(err)
	}
	if err := validHeaderValue("Header\r\nInjection"); err == nil {
		t.Fatal("expected error for header injection")
	}

	disp := safeMailDisplayValue("line1\r\nline2   extra  \t space")
	if disp != "line1 line2 extra space" {
		t.Fatalf("unexpected display value: %q", disp)
	}

	if ip := safeMailIP("192.168.1.1"); ip != "192.168.1.1" {
		t.Fatalf("expected 192.168.1.1, got %s", ip)
	}
	if ip := safeMailIP("not-an-ip"); ip != "Unknown" {
		t.Fatalf("expected Unknown, got %s", ip)
	}

	// 2. Disabled notifier
	disabled := NewSMTPNotifier("", "", "", "", "")
	if err := disabled.SendPasswordReset(ctx, "u@ex.com", "tok"); err == nil {
		t.Fatal("expected error from disabled notifier")
	}
	if err := disabled.SendEmailVerification(ctx, "u@ex.com", "tok"); err == nil {
		t.Fatal("expected error from disabled notifier")
	}
	if err := disabled.SendNewLoginAlert(ctx, "u@ex.com", "1.1.1.1", "Chrome"); err == nil {
		t.Fatal("expected error from disabled notifier")
	}
	if err := disabled.SendDuplicateRegisterAlert(ctx, "u@ex.com"); err == nil {
		t.Fatal("expected error from disabled notifier")
	}
	if err := disabled.SendSecurityAlert(ctx, "u@ex.com", "ev", "det"); err == nil {
		t.Fatal("expected error from disabled notifier")
	}

	// 3. Address injection / validation failures
	configured := NewSMTPNotifier("localhost", "25", "user", "pass", "valid@example.com")
	if err := configured.SendPasswordReset(ctx, "invalid\r\nrecipient@ex.com", "tok"); err == nil {
		t.Fatal("expected error on invalid to address")
	}
	badFrom := NewSMTPNotifier("localhost", "25", "user", "pass", "invalid\r\nsender@ex.com")
	if err := badFrom.SendPasswordReset(ctx, "recipient@example.com", "tok"); err == nil {
		t.Fatal("expected error on invalid from address")
	}

	// 4. Mock SMTP TCP listener that advertises EHLO without STARTTLS
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	host, port, _ := net.SplitHostPort(l.Addr().String())

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Send greeting
				_, _ = c.Write([]byte("220 mock-smtp ESMTP\r\n"))
				buf := make([]byte, 1024)
				n, _ := c.Read(buf)
				cmd := string(buf[:n])
				if strings.HasPrefix(cmd, "EHLO") || strings.HasPrefix(cmd, "HELO") {
					// Respond without STARTTLS extension
					_, _ = c.Write([]byte("250-mock-smtp\r\n250 HELP\r\n"))
				}
				time.Sleep(50 * time.Millisecond)
			}(conn)
		}
	}()

	notifier := NewSMTPNotifier(host, port, "user", "pass", "noreply@example.com")

	// send should dial, see that STARTTLS is not offered, and safely refuse
	err = notifier.SendPasswordReset(ctx, "recipient@example.com", "reset-token-123")
	if err == nil || !strings.Contains(err.Error(), "offers no STARTTLS") {
		t.Fatalf("expected 'offers no STARTTLS' error, got %v", err)
	}
}

func TestServices_Final_SprintTo90(t *testing.T) {
	ctx := context.Background()

	db, err := gorm.Open(sqlite.Open("file:sprint90?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	_ = db.AutoMigrate(
		&models.User{},
		&models.RefreshToken{},
		&models.AuditLog{},
		&models.Session{},
		&models.OAuthIdentity{},
		&models.PasskeyCredential{},
	)

	users := repositories.NewUserRepository(db)
	tokens := repositories.NewRefreshTokenRepository(db)
	sessions := repositories.NewSessionRepository(db)
	oauthRepo := repositories.NewOAuthIdentityRepository(db)
	passkeyRepo := repositories.NewPasskeyRepository(db)
	audit := repositories.NewAuditRepository(db)
	memStore := store.NewInMemoryStore(0)
	jwtMgr := jwt.NewJWTManager("test-secret-long-enough-32-chars-!!", "test")
	notify := &mockNotifier{}

	authCfg := config.AuthConfig{
		MaxLoginAttempts:     2,
		LoginLockoutDuration: time.Minute,
		MaxLockoutMultiplier: 2,
	}
	rlCfg := config.RateLimitConfig{
		RegisterPerIPMax:         10,
		RegisterWindow:           time.Minute,
		VerifyResendGlobalMax:    1,
		VerifyResendGlobalWindow: time.Minute,
		VerifyResendPerIPMax:     1,
		VerifyResendPerIPWindow:  time.Minute,
		VerifyResendPerEmailMax:  1,
		VerifyResendWindow:       time.Minute,
	}
	jwtCfg := config.JWTConfig{
		AccessTTL:  time.Hour,
		RefreshTTL: 24 * time.Hour,
		ResetTTL:   time.Hour,
		VerifyTTL:  time.Hour,
	}

	// Mock breached password server
	srvBreached := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		prefix, suffix := calculateHIBPSHA1Prefix("BreachedPwd123!")
		if strings.HasSuffix(r.URL.Path, prefix) {
			_, _ = w.Write([]byte(suffix + ":10\r\n"))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srvBreached.Close()
	breachedChecker := NewBreachedPasswordChecker(srvBreached.URL+"/", time.Second)

	svc := NewAuthService(
		users, tokens, nil, audit, memStore, jwtMgr,
		authCfg, rlCfg, jwtCfg, notify, NoOpCaptchaVerifier{}, geo.NewNoOpResolver(),
		nil, nil,
		WithSessionRepo(sessions),
		WithBreachedPasswordChecker(breachedChecker),
	)

	// 1. SetPassword:
	uNoPwd := &models.User{
		Username: "sprint_nopwd",
		Email:    "sprint_nopwd@example.com",
		Password: "",
		IsActive: true,
	}
	_ = users.Create(ctx, uNoPwd)

	// Breached password check in SetPassword
	if err := svc.SetPassword(ctx, uNoPwd.ID, "BreachedPwd123!", "1.1.1.1"); err != ErrPasswordBreached {
		t.Fatalf("expected ErrPasswordBreached, got %v", err)
	}

	// Success path for SetPassword
	if err := svc.SetPassword(ctx, uNoPwd.ID, "ValidNewPassword123!", "1.1.1.1"); err != nil {
		t.Fatalf("SetPassword failed: %v", err)
	}

	// 2. RequestChangeEmail rate limits (per-ip, per-email)
	uEmailUser := &models.User{
		Username: "sprint_email",
		Email:    "sprint_email@example.com",
		Password: "hashed",
		IsActive: true,
	}
	hp, _ := hash.HashPassword("Password123!")
	uEmailUser.Password = hp
	_ = users.Create(ctx, uEmailUser)

	inChg := ChangeEmailRequestInput{
		Password: "Password123!",
		NewEmail: "fresh_email_sprint@example.com",
	}
	// Trip per-ip cap
	memStore.Set(ipCounterKey("chgemail:ip:", "2.2.2.2"), int64(10), time.Minute)
	if err := svc.RequestChangeEmail(ctx, uEmailUser.ID, inChg, "2.2.2.2"); err != ErrRateLimited {
		t.Fatalf("expected ErrRateLimited for per-ip cap, got %v", err)
	}
	// Trip per-email cap
	memStore.Set("chgemail:email:"+uEmailUser.Email, int64(10), time.Minute)
	if err := svc.RequestChangeEmail(ctx, uEmailUser.ID, inChg, "3.3.3.3"); err != ErrRateLimited {
		t.Fatalf("expected ErrRateLimited for per-email cap, got %v", err)
	}

	// 3. recordFailedLogin exponential backoff and error branch
	svc.recordFailedLogin(ctx, uEmailUser, uEmailUser.Email, "1.1.1.1")
	svc.recordFailedLogin(ctx, uEmailUser, uEmailUser.Email, "1.1.1.1")
	svc.recordFailedLogin(ctx, uEmailUser, uEmailUser.Email, "1.1.1.1")

	failingUserRepo := &mockFailingUserRepo{mockUserRepo: *newMockUserRepo()}
	failingUserRepo.incrementFailedAttemptsErr = errors.New("cannot increment")
	svcFailing := NewAuthService(
		failingUserRepo, tokens, nil, audit, memStore, jwtMgr,
		authCfg, rlCfg, jwtCfg, notify, NoOpCaptchaVerifier{}, geo.NewNoOpResolver(),
		nil, nil,
	)
	svcFailing.recordFailedLogin(ctx, uEmailUser, uEmailUser.Email, "1.1.1.1")

	// 4. OAuthService branches
	uUnverified := &models.User{
		Username: "unverified_oauth",
		Email:    "unverified_oauth@example.com",
		Password: "hash",
		IsActive: true,
	}
	_ = users.Create(ctx, uUnverified)
	db.Model(uUnverified).Update("is_email_verified", false)

	oauthSvc := NewOAuthService(users, oauthRepo, memStore, nil, nil, nil)
	if _, err := oauthSvc.findOrCreateUser(ctx, &GoogleIDTokenClaims{Sub: "sub-unverified", Name: "Name"}, uUnverified.Email, "1.1.1.1"); err != ErrOAuthEmailTaken {
		t.Fatalf("expected ErrOAuthEmailTaken, got %v", err)
	}

	// linkIdentity when identity already exists
	_ = oauthRepo.Create(ctx, &models.OAuthIdentity{
		UserID:         uEmailUser.ID,
		Provider:       "google",
		ProviderUserID: "sub-already-linked",
	})
	if err := oauthSvc.linkIdentity(ctx, uEmailUser, &GoogleIDTokenClaims{Sub: "sub-already-linked"}, "1.1.1.1"); err != nil {
		t.Fatalf("expected nil for already linked identity, got %v", err)
	}

	// 5. Register branches
	// Duplicate username collision
	if _, err := svc.Register(ctx, RegisterInput{
		Username: uEmailUser.Username, // collides with existing user
		Email:    "brand_new_unique_email@example.com",
		Password: "ValidPassword123!",
		IP:       "1.1.1.1",
	}); err != nil {
		t.Fatalf("Register on duplicate username should return 201 profile, got %v", err)
	}

	// Notifier SendEmailVerification failure
	notify.verifySendErr = errors.New("smtp down")
	if _, err := svc.Register(ctx, RegisterInput{
		Username: "new_reg_user_sprint",
		Email:    "new_reg_user_sprint@example.com",
		Password: "ValidPassword123!",
		IP:       "1.1.1.1",
	}); err != nil {
		t.Fatalf("Register with failed notifier should succeed, got %v", err)
	}
	notify.verifySendErr = nil

	// shouldThrottleDuplicateRegisterAlert directly
	memStore.Set("reg:dup:global", int64(10), time.Minute)
	if !svc.shouldThrottleDuplicateRegisterAlert("throttled@example.com", "1.1.1.1") {
		t.Fatal("expected true when global cap exceeded")
	}
	memStore.Delete("reg:dup:global")

	memStore.Set(ipCounterKey("reg:dup:ip:", "1.1.1.1"), int64(10), time.Minute)
	if !svc.shouldThrottleDuplicateRegisterAlert("throttled@example.com", "1.1.1.1") {
		t.Fatal("expected true when per-ip cap exceeded")
	}
	memStore.Delete(ipCounterKey("reg:dup:ip:", "1.1.1.1"))

	memStore.Set("reg:dup:email:throttled@example.com", int64(10), time.Minute)
	if !svc.shouldThrottleDuplicateRegisterAlert("throttled@example.com", "1.1.1.1") {
		t.Fatal("expected true when per-email cap exceeded")
	}

	// MySQL duplicate error on users.Create
	failingCreateRepo := &mockFailingUserRepo{mockUserRepo: *newMockUserRepo()}
	failingCreateRepo.createErr = &mysql.MySQLError{Number: 1062, Message: "Duplicate entry 'test' for key 'users.email'"}
	svcMySQLDup := NewAuthService(
		failingCreateRepo, tokens, nil, audit, memStore, jwtMgr,
		authCfg, rlCfg, jwtCfg, notify, NoOpCaptchaVerifier{}, geo.NewNoOpResolver(),
		nil, nil,
	)
	if _, err := svcMySQLDup.Register(ctx, RegisterInput{
		Username: "mysql_dup_user",
		Email:    "mysql_dup@example.com",
		Password: "ValidPassword123!",
		IP:       "1.1.1.1",
	}); err != nil {
		t.Fatalf("Register on MySQL duplicate should return 201 profile, got %v", err)
	}

	// Generic DB error on users.Create
	failingCreateRepo.createErr = errors.New("fatal db error")
	if _, err := svcMySQLDup.Register(ctx, RegisterInput{
		Username: "generic_err_user",
		Email:    "generic_err@example.com",
		Password: "ValidPassword123!",
		IP:       "1.1.1.1",
	}); err == nil {
		t.Fatal("expected error on generic db error in Register")
	}

	// 6. PasskeyService branches
	passCfg := PasskeyConfig{
		RPDisplayName: "TestApp",
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost:8080"},
	}
	passSvc, err := NewPasskeyService(passkeyRepo, users, audit, memStore, nil, passCfg)
	if err != nil {
		t.Fatal(err)
	}
	pImpl := passSvc.(*passkeyService)

	// transportsJSON
	if jsonStr := transportsJSON([]protocol.AuthenticatorTransport{protocol.USB, protocol.NFC}); !strings.Contains(jsonStr, "usb") {
		t.Fatalf("expected usb in transportsJSON, got %s", jsonStr)
	}

	// takeJSON with invalid json in store
	memStore.Set("bad-json-key", "{invalid-json", time.Minute)
	var dummyDst map[string]string
	if err := pImpl.takeJSON(ctx, "bad-json-key", &dummyDst); err == nil {
		t.Fatal("expected error from takeJSON with bad json")
	}

	// loadUser with nonexistent user
	if _, _, err := pImpl.loadUser(ctx, 99999); err != ErrUserNotFound {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}

	// loadUser with disabled user
	uDisabled := &models.User{Username: "disabled_pk", Email: "disabled_pk@example.com", Password: "hash", IsActive: false}
	_ = users.Create(ctx, uDisabled)
	db.Model(uDisabled).Update("is_active", false)
	if _, _, err := pImpl.loadUser(ctx, uDisabled.ID); err != ErrAccountDisabled {
		t.Fatalf("expected ErrAccountDisabled, got %v", err)
	}

	// takeJSON with non-string
	memStore.Set("non-str-pk-key", 12345, time.Minute)
	if err := pImpl.takeJSON(ctx, "non-str-pk-key", &dummyDst); err != ErrPasskeyChallenge {
		t.Fatalf("expected ErrPasskeyChallenge for non-string, got %v", err)
	}

	// FinishAuthentication with nil tokens
	if _, err := pImpl.FinishAuthentication(ctx, 99999, nil); err != ErrPasskeyNotConfigured {
		t.Fatalf("expected ErrPasskeyNotConfigured for nil tokens, got %v", err)
	}

	// FinishRegistration branches
	if _, err := pImpl.FinishRegistration(ctx, 99999, nil); err == nil {
		t.Fatal("expected error on FinishRegistration with missing staged session")
	}
	memStore.Set(regSessionKey(99999), `{"DisplayName":"Key","Session":{}}`, time.Minute)
	if _, err := pImpl.FinishRegistration(ctx, 99999, nil); err != ErrUserNotFound {
		t.Fatalf("expected ErrUserNotFound on FinishRegistration with ghost user, got %v", err)
	}

	// 7. AuthService Login & Register branches
	// Timing attack mitigation: user not found in Login
	if _, _, _, err := svc.Login(ctx, LoginInput{Email: "nonexistent-timing@example.com", Password: "AnyPassword123!"}, "1.1.1.1", "agent"); err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials on timing check, got %v", err)
	}

	// Email unverified when required
	svcReqVerify := NewAuthService(
		users, tokens, nil, audit, memStore, jwtMgr,
		config.AuthConfig{RequireEmailVerified: true}, rlCfg, jwtCfg, notify, NoOpCaptchaVerifier{}, geo.NewNoOpResolver(),
		nil, nil,
	)
	uUnverifiedLogin := &models.User{
		Username:        "unverified_login_user",
		Email:           "unverified_login@example.com",
		Password:        hp,
		IsActive:        true,
		IsEmailVerified: false,
	}
	_ = users.Create(ctx, uUnverifiedLogin)
	db.Model(uUnverifiedLogin).Update("is_email_verified", false)
	if _, _, _, err := svcReqVerify.Login(ctx, LoginInput{Email: uUnverifiedLogin.Email, Password: "Password123!"}, "1.1.1.1", "agent"); err != ErrEmailNotVerified {
		t.Fatalf("expected ErrEmailNotVerified, got %v", err)
	}

	// Account locked
	lockTime := time.Now().Add(time.Hour)
	uLocked := &models.User{
		Username:    "locked_user",
		Email:       "locked_user@example.com",
		Password:    hp,
		IsActive:    true,
		LockedUntil: &lockTime,
	}
	_ = users.Create(ctx, uLocked)
	db.Model(uLocked).Update("locked_until", &lockTime)
	if _, _, _, err := svc.Login(ctx, LoginInput{Email: uLocked.Email, Password: "Password123!"}, "1.1.1.1", "agent"); err != ErrAccountLocked {
		t.Fatalf("expected ErrAccountLocked, got %v", err)
	}

	// Register with disposable email
	if _, err := svc.Register(ctx, RegisterInput{
		Username: "disposableuser",
		Email:    "disposable@mailinator.com",
		Password: "ValidPassword123!",
		IP:       "1.1.1.1",
	}); err != ErrDisposableEmail {
		t.Fatalf("expected ErrDisposableEmail, got %v", err)
	}

	// ConfirmChangeEmail empty payload
	memStore.Set("change_email:empty-payload", "", time.Minute)
	if err := svc.ConfirmChangeEmail(ctx, "empty-payload", "1.1.1.1"); err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for empty payload, got %v", err)
	}

	// resolveLocation with NoOpResolver returns UnknownLocation
	if loc := svc.resolveLocation(ctx, "1.2.3.4"); loc != geo.UnknownLocation {
		t.Fatalf("expected UnknownLocation, got %s", loc)
	}

	// shouldThrottleDuplicateRegisterAlert with nil store returns false
	svcNilStore := NewAuthService(
		users, tokens, nil, audit, nil, jwtMgr,
		authCfg, rlCfg, jwtCfg, notify, NoOpCaptchaVerifier{}, geo.NewNoOpResolver(),
		nil, nil,
	)
	if svcNilStore.shouldThrottleDuplicateRegisterAlert("test@example.com", "1.1.1.1") {
		t.Fatal("expected false with nil store")
	}
}

func TestServices_Final_OverTheTop(t *testing.T) {
	ctx := context.Background()

	db, err := gorm.Open(sqlite.Open("file:overthetop?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	_ = db.AutoMigrate(
		&models.User{},
		&models.RefreshToken{},
		&models.AuditLog{},
		&models.Session{},
		&models.UsedToken{},
		&models.OAuthIdentity{},
		&models.PasskeyCredential{},
		&models.TOTPDevice{},
		&models.RecoveryCode{},
	)

	users := repositories.NewUserRepository(db)
	tokens := repositories.NewRefreshTokenRepository(db)
	sessions := repositories.NewSessionRepository(db)
	audit := repositories.NewAuditRepository(db)
	usedTokens := repositories.NewUsedTokenRepository(db)
	oauthRepo := repositories.NewOAuthIdentityRepository(db)
	passkeyRepo := repositories.NewPasskeyRepository(db)
	totpRepo := repositories.NewTOTPRepository(db)
	memStore := store.NewInMemoryStore(0)
	jwtMgr := jwt.NewJWTManager("test-secret-long-enough-32-chars-!!", "test")
	notify := &mockNotifier{}

	authCfg := config.AuthConfig{MaxLoginAttempts: 3}
	rlCfg := config.RateLimitConfig{}
	jwtCfg := config.JWTConfig{
		AccessTTL:  time.Hour,
		RefreshTTL: 24 * time.Hour,
		ResetTTL:   time.Hour,
		VerifyTTL:  time.Hour,
	}

	svc := NewAuthService(
		users, tokens, usedTokens, audit, memStore, jwtMgr,
		authCfg, rlCfg, jwtCfg, notify, NoOpCaptchaVerifier{}, geo.NewNoOpResolver(),
		totpRepo, &mockFinalTOTPValidator{},
		WithSessionRepo(sessions),
		WithAuthOAuthIdents(oauthRepo),
		WithAuthPasskeys(passkeyRepo),
	)

	u := &models.User{
		Username: "overtopuser",
		Email:    "overtop@example.com",
		Password: "hashed",
		IsActive: true,
	}
	h, _ := hash.HashPassword("ValidPassword123!")
	u.Password = h
	_ = users.Create(ctx, u)

	// 1. Refresh branches with sessions
	// A: sess == nil (SessionID points to nonexistent session)
	rawTokMissing := "raw-missing-sess-token"
	_ = tokens.Create(ctx, &models.RefreshToken{
		UserID:    u.ID,
		TokenHash: hash.HashToken(rawTokMissing),
		SessionID: "nonexistent-sess-uuid",
		ExpiresAt: time.Now().Add(time.Hour),
		Revoked:   false,
	})
	if _, err := svc.Refresh(ctx, rawTokMissing, "1.1.1.1", "agent"); err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for nonexistent session, got %v", err)
	}

	// B: sess.Revoked == true -> triggers handleTokenReuse and returns ErrInvalidToken
	rawTokRev := "raw-revoked-sess-token"
	_ = sessions.Create(ctx, &models.Session{
		ID:        "sess-revoked-fam",
		UserID:    u.ID,
		Revoked:   true,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	_ = tokens.Create(ctx, &models.RefreshToken{
		UserID:    u.ID,
		TokenHash: hash.HashToken(rawTokRev),
		SessionID: "sess-revoked-fam",
		ExpiresAt: time.Now().Add(time.Hour),
		Revoked:   false,
	})
	if _, err := svc.Refresh(ctx, rawTokRev, "1.1.1.1", "agent"); err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for revoked session family, got %v", err)
	}

	// 2. ConfirmChangeEmail branches
	// A: Bad payload format (not 3 parts)
	memStore.Set("change_email:bad-fmt", "only-one-part", time.Minute)
	if err := svc.ConfirmChangeEmail(ctx, "bad-fmt", "1.1.1.1"); err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for malformed payload, got %v", err)
	}

	// B: User ID parse failure
	memStore.Set("change_email:bad-uid", "notanumber:old@ex.com:new@ex.com", time.Minute)
	if err := svc.ConfirmChangeEmail(ctx, "bad-uid", "1.1.1.1"); err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for invalid user ID, got %v", err)
	}

	// C: Target user not found
	memStore.Set("change_email:ghost-user", "99999:old@ex.com:new@ex.com", time.Minute)
	if err := svc.ConfirmChangeEmail(ctx, "ghost-user", "1.1.1.1"); err != ErrUserNotFound {
		t.Fatalf("expected ErrUserNotFound for ghost user, got %v", err)
	}

	// D: Email collision with another existing user
	uExisting := &models.User{
		Username: "existingemailuser",
		Email:    "existingemail@example.com",
		Password: h,
		IsActive: true,
	}
	_ = users.Create(ctx, uExisting)

	memStore.Set("change_email:collision-tok", fmt.Sprintf("%d:%s:%s", u.ID, u.Email, uExisting.Email), time.Minute)
	if err := svc.ConfirmChangeEmail(ctx, "collision-tok", "1.1.1.1"); err != ErrEmailExists {
		t.Fatalf("expected ErrEmailExists on ConfirmChangeEmail collision, got %v", err)
	}

	// E: ConfirmChangeEmail success path
	memStore.Set("change_email:success-tok", fmt.Sprintf("%d:%s:%s", u.ID, u.Email, "newconfirmed@example.com"), time.Minute)
	if err := svc.ConfirmChangeEmail(ctx, "success-tok", "1.1.1.1"); err != nil {
		t.Fatalf("ConfirmChangeEmail failed: %v", err)
	}

	// 3. DeactivateAccount & EraseAccount: user not found, bad credential, and success
	if err := svc.DeactivateAccount(ctx, 99999, "", "pass", "jti", "1.1.1.1"); err != ErrUserNotFound {
		t.Fatalf("expected ErrUserNotFound on DeactivateAccount, got %v", err)
	}
	if err := svc.DeactivateAccount(ctx, u.ID, "", "WrongPassword!", "jti", "1.1.1.1"); err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials on DeactivateAccount, got %v", err)
	}
	if err := svc.EraseAccount(ctx, 99999, "", "pass", "jti", "1.1.1.1"); err != ErrUserNotFound {
		t.Fatalf("expected ErrUserNotFound on EraseAccount, got %v", err)
	}
	if err := svc.EraseAccount(ctx, u.ID, "", "WrongPassword!", "jti", "1.1.1.1"); err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials on EraseAccount, got %v", err)
	}

	// Success DeactivateAccount
	uToDeact := &models.User{
		Username: "deact_user",
		Email:    "deact@example.com",
		Password: h,
		IsActive: true,
	}
	_ = users.Create(ctx, uToDeact)
	if err := svc.DeactivateAccount(ctx, uToDeact.ID, "", "ValidPassword123!", "jti-deact", "1.1.1.1"); err != nil {
		t.Fatalf("DeactivateAccount failed: %v", err)
	}

	// Success EraseAccount (with totp, oauth, passkey attached)
	uToErase := &models.User{
		Username: "erase_user",
		Email:    "erase@example.com",
		Password: h,
		IsActive: true,
	}
	_ = users.Create(ctx, uToErase)
	_ = oauthRepo.Create(ctx, &models.OAuthIdentity{UserID: uToErase.ID, Provider: "google", ProviderUserID: "erase-google-sub"})
	_ = passkeyRepo.Create(ctx, &models.PasskeyCredential{UserID: uToErase.ID, CredentialID: []byte("cred-erase"), PublicKey: []byte("pub-erase")})
	_ = totpRepo.Upsert(ctx, &models.TOTPDevice{UserID: uToErase.ID, Secret: "JBSWY3DPEHPK3PXP", Enabled: true})

	if err := svc.EraseAccount(ctx, uToErase.ID, "", "ValidPassword123!", "jti-erase", "1.1.1.1"); err != nil {
		t.Fatalf("EraseAccount failed: %v", err)
	}

	// 4. Me and GetUserAuditLog
	if _, err := svc.Me(ctx, 99999); err != ErrUserNotFound {
		t.Fatalf("expected ErrUserNotFound on Me, got %v", err)
	}
	svcNoAudit := NewAuthService(
		users, tokens, usedTokens, nil, memStore, jwtMgr,
		authCfg, rlCfg, jwtCfg, notify, NoOpCaptchaVerifier{}, geo.NewNoOpResolver(),
		nil, nil,
	)
	if logs, total, err := svcNoAudit.GetUserAuditLog(ctx, u.ID, 1, 10); len(logs) != 0 || total != 0 || err != nil {
		t.Fatalf("expected empty logs on svcNoAudit, got len=%d, total=%d, err=%v", len(logs), total, err)
	}

	// 5. IssuePasskeyTokenPair
	uInactive := &models.User{Username: "inactive_pk", Email: "inact@ex.com", IsActive: false}
	_ = users.Create(ctx, uInactive)
	db.Model(uInactive).Update("is_active", false)
	if _, _, err := svc.IssuePasskeyTokenPair(ctx, uInactive, "1.1.1.1", "agent"); err != ErrAccountDisabled {
		t.Fatalf("expected ErrAccountDisabled on inactive user passkey token issue, got %v", err)
	}
	pkPair, pkProf, err := svc.IssuePasskeyTokenPair(ctx, u, "1.1.1.1", "agent")
	if err != nil || pkPair.AccessToken == "" || pkProf.Email != u.Email {
		t.Fatalf("IssuePasskeyTokenPair on active user failed: %v", err)
	}

	// 6. VerifyEmail branches
	uUnverified := &models.User{
		Username: "unverified_ve",
		Email:    "unverified_ve@example.com",
		Password: h,
		IsActive: true,
	}
	_ = users.Create(ctx, uUnverified)
	db.Model(uUnverified).Update("is_email_verified", false)

	// Wrong token type (e.g. reset token)
	resetTok, _ := jwtMgr.Issue(uUnverified.ID, "user", uUnverified.Email, jwt.TokenTypeReset, time.Hour)
	if err := svc.VerifyEmail(ctx, EmailVerifyInput{Token: resetTok}); err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for wrong token type, got %v", err)
	}

	// Nonexistent user in token
	ghostTok, _ := jwtMgr.Issue(99999, "user", "ghost@ex.com", jwt.TokenTypeEmailVerify, time.Hour)
	if err := svc.VerifyEmail(ctx, EmailVerifyInput{Token: ghostTok}); err != ErrUserNotFound {
		t.Fatalf("expected ErrUserNotFound for ghost user token, got %v", err)
	}

	// Valid token verifies successfully
	verifyTok, _ := jwtMgr.Issue(uUnverified.ID, "user", uUnverified.Email, jwt.TokenTypeEmailVerify, time.Hour)
	if err := svc.VerifyEmail(ctx, EmailVerifyInput{Token: verifyTok}); err != nil {
		t.Fatalf("VerifyEmail failed: %v", err)
	}
	// Replay token fails
	if err := svc.VerifyEmail(ctx, EmailVerifyInput{Token: verifyTok}); err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken on replayed token, got %v", err)
	}

	// 7. ListSessions & RevokeSession
	_ = sessions.Create(ctx, &models.Session{
		ID:        "sess-curr",
		UserID:    u.ID,
		IPAddress: "1.2.3.4",
		UserAgent: "Mozilla/5.0",
		ExpiresAt: time.Now().Add(time.Hour),
		Revoked:   false,
	})
	_ = sessions.Create(ctx, &models.Session{
		ID:        "sess-other",
		UserID:    u.ID,
		IPAddress: "5.6.7.8",
		UserAgent: "Safari",
		ExpiresAt: time.Now().Add(time.Hour),
		Revoked:   false,
	})
	sessList, err := svc.ListSessions(ctx, u.ID, "sess-curr")
	if err != nil || len(sessList) < 2 {
		t.Fatalf("ListSessions failed: len=%d, err=%v", len(sessList), err)
	}
	// Revoke session unauthorized
	if err := svc.RevokeSession(ctx, "sess-curr", 99999, "1.1.1.1"); err != ErrSessionNotFound {
		t.Fatalf("expected ErrSessionNotFound on wrong user revoking session, got %v", err)
	}
	// Revoke session authorized
	if err := svc.RevokeSession(ctx, "sess-curr", u.ID, "1.1.1.1"); err != nil {
		t.Fatalf("RevokeSession failed: %v", err)
	}

	// 8. CompleteMFALogin
	if _, _, err := svc.CompleteMFALogin(ctx, CompleteMFALoginInput{UserID: 99999, Code: "123456", IP: "1.1.1.1", UA: "agent"}); err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken on ghost user CompleteMFALogin, got %v", err)
	}
	pairMFAComplete, profMFAComplete, err := svc.CompleteMFALogin(ctx, CompleteMFALoginInput{UserID: u.ID, Code: "123456", IP: "1.1.1.1", UA: "agent"})
	if err != nil || pairMFAComplete.AccessToken == "" || profMFAComplete.ID != u.ID {
		t.Fatalf("CompleteMFALogin failed: %v", err)
	}

	// 9. LogoutAll with sessions
	if err := svc.LogoutAll(ctx, u.ID, "1.1.1.1"); err != nil {
		t.Fatalf("LogoutAll failed: %v", err)
	}

	// 10. SetPassword on user who already has a password (ErrPasswordAlreadySet)
	if err := svc.SetPassword(ctx, u.ID, "BrandNewPassword123!", "1.1.1.1"); err != ErrPasswordAlreadySet {
		t.Fatalf("expected ErrPasswordAlreadySet, got %v", err)
	}

	// 11. GetUserAuditLog with existing logs
	audit.Record(ctx, &models.AuditLog{
		TenantID:  "default",
		UserID:    &u.ID,
		Email:     u.Email,
		Event:     models.AuditEventLogin,
		IPAddress: "1.1.1.1",
		Success:   true,
	})
	userLogs, totalLogs, err := svc.GetUserAuditLog(ctx, u.ID, 1, 10)
	if err != nil || totalLogs == 0 || len(userLogs) == 0 {
		t.Fatalf("GetUserAuditLog failed: len=%d, total=%d, err=%v", len(userLogs), totalLogs, err)
	}
}

type mockFinalTOTPValidator struct {
	err error
}

func (m *mockFinalTOTPValidator) Validate(ctx context.Context, userID uint, code string) error {
	return m.err
}

type mockFailingAdminUserRepo struct {
	findUser   *models.User
	findErr    error
	setLockErr error
	listErr    error
	bumpErr    error
}

func (m *mockFailingAdminUserRepo) FindByID(ctx context.Context, id uint) (*models.User, error) {
	return m.findUser, m.findErr
}
func (m *mockFailingAdminUserRepo) ListPaginated(ctx context.Context, tenantID string, page, limit int, search string) ([]models.User, int64, error) {
	return nil, 0, m.listErr
}
func (m *mockFailingAdminUserRepo) SetLock(ctx context.Context, userID uint, lockedUntil *time.Time) error {
	return m.setLockErr
}
func (m *mockFailingAdminUserRepo) BumpPwdVersion(ctx context.Context, userID uint) error {
	return m.bumpErr
}

type mockFailingAdminSessionRepo struct {
	findAllErr error
	revokeErr  error
}

func (m *mockFailingAdminSessionRepo) FindAllActiveByTenant(ctx context.Context, tenantID string) ([]models.Session, error) {
	return nil, m.findAllErr
}
func (m *mockFailingAdminSessionRepo) RevokeAllForUser(ctx context.Context, userID uint) error {
	return m.revokeErr
}

type mockFailingAdminAuditRepo struct {
	streamErr error
}

func (m *mockFailingAdminAuditRepo) Record(ctx context.Context, entry *models.AuditLog) {}
func (m *mockFailingAdminAuditRepo) StreamAll(ctx context.Context, tenantID string) ([]models.AuditLog, error) {
	return nil, m.streamErr
}

type mockErrorTrustedDeviceRepo struct {
	createErr error
	findErr   error
	listErr   error
	device    *models.TrustedDevice
	touchErr  error
	revokeErr error
}

func (m *mockErrorTrustedDeviceRepo) Create(ctx context.Context, d *models.TrustedDevice) error {
	return m.createErr
}
func (m *mockErrorTrustedDeviceRepo) FindByDeviceHash(ctx context.Context, hash string) (*models.TrustedDevice, error) {
	return m.device, m.findErr
}
func (m *mockErrorTrustedDeviceRepo) TouchUsage(ctx context.Context, id uint, at time.Time) error {
	return m.touchErr
}
func (m *mockErrorTrustedDeviceRepo) ListByUser(ctx context.Context, userID uint) ([]models.TrustedDevice, error) {
	return nil, m.listErr
}
func (m *mockErrorTrustedDeviceRepo) Revoke(ctx context.Context, id, userID uint) error {
	return m.revokeErr
}

func TestServices_Final_SprintAcrossTheFinishLine(t *testing.T) {
	ctx := context.Background()

	// --- 1. AdminService Error Branches ---
	adminUserErr := errors.New("admin user db error")
	adminSvcUserFail := NewAdminService(
		&mockFailingAdminUserRepo{findErr: adminUserErr, listErr: adminUserErr, setLockErr: adminUserErr},
		nil, nil, nil, nil,
	)

	// ListUsers failure
	if _, _, err := adminSvcUserFail.ListUsers(ctx, 1, 10, ""); err == nil {
		t.Fatal("expected error on ListUsers")
	}

	// LockUser FindByID failure
	if err := adminSvcUserFail.LockUser(ctx, 1, 2, time.Hour, "1.1.1.1"); err == nil {
		t.Fatal("expected error on LockUser FindByID")
	}

	// LockUser SetLock failure
	adminSvcLockFail := NewAdminService(
		&mockFailingAdminUserRepo{findUser: &models.User{ID: 2, Email: "u2@example.com"}, setLockErr: adminUserErr},
		nil, nil, nil, nil,
	)
	if err := adminSvcLockFail.LockUser(ctx, 1, 2, time.Hour, "1.1.1.1"); err == nil {
		t.Fatal("expected error on LockUser SetLock")
	}

	// UnlockUser FindByID failure
	if err := adminSvcUserFail.UnlockUser(ctx, 1, 2, "1.1.1.1"); err == nil {
		t.Fatal("expected error on UnlockUser FindByID")
	}

	// UnlockUser SetLock failure
	if err := adminSvcLockFail.UnlockUser(ctx, 1, 2, "1.1.1.1"); err == nil {
		t.Fatal("expected error on UnlockUser SetLock")
	}

	// ForceLogout FindByID failure
	if err := adminSvcUserFail.ForceLogout(ctx, 1, 2, "1.1.1.1"); err == nil {
		t.Fatal("expected error on ForceLogout FindByID")
	}

	// ListTenantSessions FindAllActiveByTenant failure
	sessErr := errors.New("session db error")
	adminSvcSessFail := NewAdminService(nil, &mockFailingAdminSessionRepo{findAllErr: sessErr}, nil, nil, nil)
	if _, err := adminSvcSessFail.ListTenantSessions(ctx); err == nil {
		t.Fatal("expected error on ListTenantSessions")
	}

	// ExportAuditLogs StreamAll failure
	auditErr := errors.New("audit db error")
	adminSvcAuditFail := NewAdminService(nil, nil, nil, &mockFailingAdminAuditRepo{streamErr: auditErr}, nil)
	if _, _, err := adminSvcAuditFail.ExportAuditLogs(ctx, "csv"); err == nil {
		t.Fatal("expected error on ExportAuditLogs")
	}

	// --- 2. TrustedDeviceService Branches ---
	devErr := errors.New("device db error")
	tdSvcErr := NewTrustedDeviceService(&mockErrorTrustedDeviceRepo{
		createErr: devErr,
		findErr:   devErr,
		listErr:   devErr,
		revokeErr: devErr,
	})

	// Issue create error
	if _, _, err := tdSvcErr.Issue(ctx, 1, "laptop", "1.1.1.1"); err == nil {
		t.Fatal("expected error on Issue")
	}

	// Validate with repo == nil
	tdSvcNil := NewTrustedDeviceService(nil)
	if ok, err := tdSvcNil.Validate(ctx, 1, "sometoken"); ok || err != nil {
		t.Fatalf("expected false, nil for nil repo Validate, got %v, %v", ok, err)
	}

	// Validate FindByDeviceHash error
	if ok, err := tdSvcErr.Validate(ctx, 1, "sometoken"); ok || err == nil {
		t.Fatal("expected error on Validate FindByDeviceHash")
	}

	// ListByUser with repo == nil
	if res, err := tdSvcNil.ListByUser(ctx, 1); res != nil || err != nil {
		t.Fatalf("expected nil, nil for nil repo ListByUser, got %v, %v", res, err)
	}

	// ListByUser error
	if _, err := tdSvcErr.ListByUser(ctx, 1); err == nil {
		t.Fatal("expected error on ListByUser")
	}

	// Revoke with repo == nil
	if err := tdSvcNil.Revoke(ctx, 1, 1); err != nil {
		t.Fatalf("expected nil for nil repo Revoke, got %v", err)
	}
}
