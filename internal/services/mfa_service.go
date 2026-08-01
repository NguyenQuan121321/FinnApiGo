package services

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/finnapigo/finnapigo/internal/config"
	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/utils"
)

// MFAService implements OTP-based two-step verification. It is independent of
// the transport layer (no Gin) and depends on OtpRepo + UserRepo interfaces.
type MFAService struct {
	otps   OtpRepo
	users  UserRepo
	audits AuditRepo
	notify Notifier
	cfg    config.AuthConfig
}

func NewMFAService(
	otps OtpRepo,
	users UserRepo,
	audits AuditRepo,
	notify Notifier,
	cfg config.AuthConfig,
) *MFAService {
	return &MFAService{otps: otps, users: users, audits: audits, notify: notify, cfg: cfg}
}

// SendOTP generates a new numeric code, stores its hash, and delivers it via
// the notifier. A previous active code for the same purpose is left to lapse
// (the newest is always returned by FindLatestActive).
func (s *MFAService) SendOTP(ctx context.Context, in OTPSendInput, ip string) error {
	purpose := strings.TrimSpace(in.Purpose)
	if !validPurpose(purpose) {
		return fmt.Errorf("%w: unknown purpose %q", ErrInvalidInput, purpose)
	}
	user, err := s.users.FindByID(in.UserID)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}

	code, err := utils.GenerateNumericOTP(s.cfg.OTPLength)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrOTPIssue, err)
	}
	otp := &models.OtpCode{
		UserID:    user.ID,
		CodeHash:  utils.HashToken(code),
		Purpose:   purpose,
		ExpiresAt: time.Now().Add(s.cfg.OTPTTL),
	}
	if err := s.otps.Create(otp); err != nil {
		return fmt.Errorf("send otp: create: %w", err)
	}

	if err := s.notify.SendOTP(user.Email, code, purpose); err != nil {
		return fmt.Errorf("send otp: notify: %w", err)
	}
	s.audits.Record(&models.AuditLog{
		UserID: &user.ID, Event: models.AuditEventOTPSent,
		IPAddress: ip, Success: true, Detail: purpose,
	})
	return nil
}

// VerifyOTP checks the submitted code against the latest active code for the
// purpose, enforcing expiry, single-use, and a max-attempt limit. On success
// the code is marked used immediately (single-use).
func (s *MFAService) VerifyOTP(ctx context.Context, in OTPVerifyInput, ip string) error {
	otp, err := s.otps.FindLatestActive(in.UserID, in.Purpose)
	if err != nil {
		return err
	}
	if otp == nil {
		return ErrInvalidOTP
	}

	// OTPs are stored as SHA-256 hashes (HashToken), not bcrypt — compare the
	// hash of the submitted code against the stored hash directly.
	if otp.CodeHash != utils.HashToken(in.Code) {
		attempts, _ := s.otps.IncrementAttempts(otp)
		if attempts >= s.cfg.OTPMaxAttempts {
			_ = s.otps.MarkUsed(otp) // force a fresh code to be issued
			return ErrOTPMaxAttempts
		}
		return ErrInvalidOTP
	}

	if err := s.otps.MarkUsed(otp); err != nil {
		return err
	}
	uid := otp.UserID
	s.audits.Record(&models.AuditLog{
		UserID: &uid, Event: models.AuditEventOTPVerified,
		IPAddress: ip, Success: true, Detail: in.Purpose,
	})
	return nil
}

func validPurpose(p string) bool {
	switch p {
	case models.OTPPurposeLogin, models.OTPPurposeVerifyEmail, models.OTPPurposeResetPassword:
		return true
	}
	return false
}
