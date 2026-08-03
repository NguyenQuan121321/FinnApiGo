package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/finnapigo/finnapigo/internal/config"
	"github.com/finnapigo/finnapigo/internal/models"
)

func newTestMFAService() (*MFAService, *mockOtpRepo, *mockUserRepo, *mockNotifier) {
	otps := newMockOtpRepo()
	users := newMockUserRepo()
	audit := &mockAuditRepo{}
	notify := &mockNotifier{}
	store := newMockStore()
	cfg := config.AuthConfig{OTPTTL: 5 * time.Minute, OTPLength: 6, OTPMaxAttempts: 5}
	rateLimitCfg := config.RateLimitConfig{
		OTPSendPerUserMax: 5,
		OTPSendWindow:     time.Minute,
	}
	svc := NewMFAService(otps, users, audit, notify, cfg, rateLimitCfg, store)
	return svc, otps, users, notify
}

func TestSendOTP_DeliversAndStores(t *testing.T) {
	svc, otps, users, notify := newTestMFAService()
	if err := users.Create(context.Background(), &models.User{ID: 1, Email: "a@example.com", IsActive: true}); err != nil {
		t.Fatal(err)
	}
	if err := svc.SendOTP(context.Background(), OTPSendInput{UserID: 1, Purpose: models.OTPPurposeLogin}, "ip"); err != nil {
		t.Fatalf("send failed: %v", err)
	}
	if notify.lastOTPCode == "" || len(notify.lastOTPCode) != 6 {
		t.Errorf("expected 6-digit code delivered, got %q", notify.lastOTPCode)
	}
	if len(otps.rows) != 1 {
		t.Fatalf("expected 1 otp row, got %d", len(otps.rows))
	}
	if otps.rows[0].CodeHash == notify.lastOTPCode {
		t.Error("OTP must be stored hashed, not plaintext")
	}
}

func TestVerifyOTP_SuccessAndSingleUse(t *testing.T) {
	svc, _, users, notify := newTestMFAService()
	if err := users.Create(context.Background(), &models.User{ID: 1, Email: "a@example.com", IsActive: true}); err != nil {
		t.Fatal(err)
	}
	_ = svc.SendOTP(context.Background(), OTPSendInput{UserID: 1, Purpose: models.OTPPurposeLogin}, "ip")
	code := notify.lastOTPCode

	err := svc.VerifyOTP(context.Background(), OTPVerifyInput{UserID: 1, Code: code, Purpose: models.OTPPurposeLogin}, "ip")
	if err != nil {
		t.Fatalf("verify should succeed: %v", err)
	}
	// second use must fail (single-use)
	err = svc.VerifyOTP(context.Background(), OTPVerifyInput{UserID: 1, Code: code, Purpose: models.OTPPurposeLogin}, "ip")
	if !errors.Is(err, ErrInvalidOTP) {
		t.Errorf("reused code should fail with ErrInvalidOTP, got %v", err)
	}
}

func TestVerifyOTP_WrongCodeIncrementsAttempts(t *testing.T) {
	svc, otps, users, _ := newTestMFAService()
	if err := users.Create(context.Background(), &models.User{ID: 1, Email: "a@example.com", IsActive: true}); err != nil {
		t.Fatal(err)
	}
	_ = svc.SendOTP(context.Background(), OTPSendInput{UserID: 1, Purpose: models.OTPPurposeLogin}, "ip")

	for i := 0; i < 5; i++ {
		_ = svc.VerifyOTP(context.Background(), OTPVerifyInput{
			UserID: 1, Code: "000000", Purpose: models.OTPPurposeLogin,
		}, "ip")
	}
	if otps.rows[0].IsUsed == false {
		t.Error("after max attempts the OTP should be force-invalidated (used)")
	}
}

func TestSendOTP_RejectsUnknownPurpose(t *testing.T) {
	svc, _, users, _ := newTestMFAService()
	if err := users.Create(context.Background(), &models.User{ID: 1, Email: "a@example.com", IsActive: true}); err != nil {
		t.Fatal(err)
	}
	err := svc.SendOTP(context.Background(), OTPSendInput{UserID: 1, Purpose: "bogus"}, "ip")
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput for bogus purpose, got %v", err)
	}
}

func TestVerifyOTP_NoActiveCode(t *testing.T) {
	svc, _, users, _ := newTestMFAService()
	if err := users.Create(context.Background(), &models.User{ID: 1, Email: "a@example.com", IsActive: true}); err != nil {
		t.Fatal(err)
	}
	err := svc.VerifyOTP(context.Background(), OTPVerifyInput{
		UserID: 1, Code: "123456", Purpose: models.OTPPurposeLogin,
	}, "ip")
	if !errors.Is(err, ErrInvalidOTP) {
		t.Errorf("expected ErrInvalidOTP when no code issued, got %v", err)
	}
}
