package services

import (
	"context"
	"crypto/subtle"
	"fmt"
	"strings"
	"time"

	"github.com/finnapigo/finnapigo/internal/config"
	"github.com/finnapigo/finnapigo/internal/hash"
	"github.com/finnapigo/finnapigo/internal/models"
)

// MFAService implements OTP-based two-step verification. It is independent of
// the transport layer (no Gin) and depends on OtpRepo + UserRepo interfaces.
type MFAService struct {
	otps   OtpRepo
	users  UserRepo
	audits AuditRepo
	notify Notifier
	store  StoreProvider // §5 — per-user OTP send limiting (shared across instances)
	cfg    config.AuthConfig
	rlCfg  config.RateLimitConfig
}

// NewMFAService constructs the MFA service. store may be nil (OTP send limiter
// will be a no-op, matching single-instance dev setups).
func NewMFAService(
	otps OtpRepo,
	users UserRepo,
	audits AuditRepo,
	notify Notifier,
	cfg config.AuthConfig,
	rlCfg config.RateLimitConfig,
	store StoreProvider,
) *MFAService {
	return &MFAService{otps: otps, users: users, audits: audits, notify: notify,
		store: store, cfg: cfg, rlCfg: rlCfg}
}

// SendOTP generates a new numeric code, stores its hash, and delivers it via
// the notifier. A previous active code for the same purpose is left to lapse
// (the newest is always returned by FindLatestActive).
//
// §5 — Per-user OTP send rate limit: prevents a script hammering OTP generation
// against one account from multiple IPs (each OTP send may cost money if backed
// by a real SMS/email provider). Uses the store so the limit is shared across
// instances.
func (s *MFAService) SendOTP(ctx context.Context, in OTPSendInput, ip string) error {
	purpose := strings.TrimSpace(in.Purpose)
	if !validPurpose(purpose) {
		return fmt.Errorf("%w: unknown purpose %q", ErrInvalidInput, purpose)
	}
	// §5 — per-user OTP send velocity limit.
	if s.store != nil {
		key := fmt.Sprintf("otp:send:%d", in.UserID)
		count := s.store.IncrBy(key, 1, s.rlCfg.OTPSendWindow)
		if count > int64(s.rlCfg.OTPSendPerUserMax) {
			return ErrRateLimited
		}
	}
	user, err := s.users.FindByID(ctx, in.UserID)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}

	code, err := hash.GenerateNumericOTP(s.cfg.OTPLength)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrOTPIssue, err)
	}
	otp := &models.OtpCode{
		UserID:    user.ID,
		CodeHash:  hash.HashToken(code),
		Purpose:   purpose,
		ExpiresAt: time.Now().Add(s.cfg.OTPTTL),
	}
	if err := s.otps.Create(ctx, otp); err != nil {
		return fmt.Errorf("send otp: create: %w", err)
	}

	if err := s.notify.SendOTP(user.Email, code, purpose); err != nil {
		return fmt.Errorf("send otp: notify: %w", err)
	}
	s.audits.Record(ctx, &models.AuditLog{
		UserID: &user.ID, Event: models.AuditEventOTPSent,
		IPAddress: ip, Success: true, Detail: purpose,
	})
	return nil
}

// VerifyOTP checks the submitted code against the latest active code for the
// purpose, enforcing expiry, single-use, and a max-attempt limit. On success
// the code is marked used immediately (single-use).
//
// §1.5 — The hash comparison uses subtle.ConstantTimeCompare instead of a
// plain != so the comparison does not short-circuit on a byte mismatch
// (timing side-channel).
func (s *MFAService) VerifyOTP(ctx context.Context, in OTPVerifyInput, ip string) error {
	otp, err := s.otps.FindLatestActive(ctx, in.UserID, in.Purpose)
	if err != nil {
		return err
	}
	if otp == nil {
		return ErrInvalidOTP
	}

	// OTPs are stored as SHA-256 hashes (HashToken), not bcrypt. Compare the
	// hash of the submitted code against the stored hash with a constant-time
	// comparison to remove the timing side-channel (§1.5).
	submitted := hash.HashToken(in.Code)
	if subtle.ConstantTimeCompare([]byte(otp.CodeHash), []byte(submitted)) != 1 {
		attempts, _ := s.otps.IncrementAttempts(ctx, otp)
		if attempts >= s.cfg.OTPMaxAttempts {
			_ = s.otps.MarkUsed(ctx, otp) // force a fresh code to be issued
			return ErrOTPMaxAttempts
		}
		return ErrInvalidOTP
	}

	if err := s.otps.MarkUsed(ctx, otp); err != nil {
		return err
	}
	uid := otp.UserID
	s.audits.Record(ctx, &models.AuditLog{
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
