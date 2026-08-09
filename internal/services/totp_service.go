package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/finnapigo/finnapigo/internal/config"
	"github.com/finnapigo/finnapigo/internal/hash"
	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// TOTPSkew allows ±n 30-second steps when validating a TOTP code. 1 means a
// code is accepted if it matches the current, previous, or next step — the
// standard allowance that compensates for minor client/server clock drift.
const TOTPSkew uint = 1

// totpPeriod is the RFC 6238 default step length (30s).
const totpPeriod uint = 30

// totpReplayTTL is how long a used 6-digit code's hash is remembered so it
// cannot be replayed within its validity window. With skew=1 a code is valid
// for at most 3 steps (90s), so 120s covers it with margin.
const totpReplayTTL = 120 * time.Second

// TOTPService implements RFC 6238 TOTP enrollment + validation with recovery
// codes and replay protection. It is deliberately decoupled from Gin — every
// method takes a context.Context and returns sentinel errors that the handler
// layer maps to HTTP statuses.
//
// Performance / DoS posture (the reason this service exists in this form):
//   - Recovery codes are high-entropy random tokens verified with SHA-256 +
//     constant-time compare (NOT bcrypt), so a flood of invalid recovery
//     codes costs O(1) per attempt instead of ~100ms of CPU each.
//   - Per-user failed-attempt counters (shared via the store) cap how many
//     wrong codes one account can absorb in a window before 429 — backstopping
//     the per-IP rate limiter when an attacker rotates IPs.
//   - Replay protection uses a single atomic SetNX per validation.
type TOTPService struct {
	repo   TOTPRepo
	store  StoreProvider
	audits AuditRepo
	issuer string
	cfg    config.AuthConfig
}

// NewTOTPService constructs the service. store may be nil (replay protection
// and the per-user attempt counter become no-ops); audits may be nil (audit
// writes are skipped). cfg drives recovery-code entropy/count and the
// brute-force window; when zero-valued the fields default to safe values so
// callers that only care about the core flow (e.g. legacy tests) still work.
func NewTOTPService(repo TOTPRepo, store StoreProvider, audits AuditRepo, issuer string, cfg config.AuthConfig) *TOTPService {
	if cfg.TOTPMaxAttempts <= 0 {
		cfg.TOTPMaxAttempts = 5
	}
	if cfg.TOTPAttemptWindow <= 0 {
		cfg.TOTPAttemptWindow = 5 * time.Minute
	}
	if cfg.RecoveryCodeCount <= 0 {
		cfg.RecoveryCodeCount = 10
	}
	if cfg.RecoveryCodeBytes <= 0 {
		cfg.RecoveryCodeBytes = 16
	}
	return &TOTPService{repo: repo, store: store, audits: audits, issuer: issuer, cfg: cfg}
}

// Enable starts (or restarts) TOTP enrollment: it generates a fresh shared
// secret and returns the secret + the otpauth:// provisioning URI. The device
// is left disabled until VerifyEnable confirms the user can read it.
func (s *TOTPService) Enable(ctx context.Context, userID uint, email string) (string, string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer: s.issuer, AccountName: email,
	})
	if err != nil {
		return "", "", fmt.Errorf("totp generate: %w", err)
	}
	old, err := s.repo.FindByUserID(ctx, userID)
	if err != nil {
		return "", "", err
	}
	var d *models.TOTPDevice
	if old != nil {
		// Rotate the secret on every enable; the device stays disabled until
		// the new secret is confirmed via VerifyEnable.
		old.Secret = key.Secret()
		old.Enabled = false
		d = old
	} else {
		d = &models.TOTPDevice{UserID: userID, Secret: key.Secret(), Enabled: false}
	}
	if err = s.repo.Upsert(ctx, d); err != nil {
		return "", "", err
	}
	return key.Secret(), key.URL(), nil
}

// VerifyEnable confirms an enrollment: validates the provided 6-digit code
// against the pending secret and, on success, activates the device and issues
// a fresh batch of recovery codes. The plaintext recovery codes are returned
// exactly once — only their SHA-256 hashes are persisted.
func (s *TOTPService) VerifyEnable(ctx context.Context, userID uint, code string) ([]string, error) {
	if err := s.guardBruteForce(ctx, userID); err != nil {
		return nil, err
	}
	d, err := s.repo.FindByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if d == nil {
		s.recordFailure(ctx, userID, "no pending device")
		return nil, ErrInvalidOTP
	}
	if d.Enabled {
		return nil, ErrInvalidInput
	}
	if !totpValid(code, d.Secret) {
		s.recordFailure(ctx, userID, "bad enable code")
		return nil, ErrInvalidOTP
	}
	d.Enabled = true
	if err = s.repo.Upsert(ctx, d); err != nil {
		return nil, err
	}
	codes, err := s.newRecoveryCodes(ctx, userID)
	if err != nil {
		// Roll back activation so the user can retry Enable -> VerifyEnable.
		d.Enabled = false
		_ = s.repo.Upsert(ctx, d)
		return nil, fmt.Errorf("không thể tạo mã khôi phục: %w", err)
	}
	s.recordSuccess(ctx, userID, models.AuditEventTOTPEnabled, "totp enabled")
	return codes, nil
}

// Validate verifies a code for an already-enabled device. It accepts either a
// 6-digit TOTP code (validated against the secret, with replay protection) or
// a recovery code (verified by SHA-256 + constant-time compare, marked used on
// success). The 6-digit path is intentionally separated so it can stay cheap.
func (s *TOTPService) Validate(ctx context.Context, userID uint, code string) error {
	if err := s.guardBruteForce(ctx, userID); err != nil {
		return err
	}
	d, err := s.repo.FindByUserID(ctx, userID)
	if err != nil {
		return err
	}
	if d == nil || !d.Enabled {
		s.recordFailure(ctx, userID, "device not enabled")
		return ErrInvalidOTP
	}

	// ---- 6-digit TOTP fast path ----
	if len(code) == 6 {
		if !totpValid(code, d.Secret) {
			s.recordFailure(ctx, userID, "bad totp code")
			return ErrInvalidOTP
		}
		// Replay protection: a code may only be used once within its validity
		// window. SetNX is atomic, so concurrent identical submissions collide
		// and exactly one wins.
		sum := sha256.Sum256([]byte(code))
		if s.store != nil {
			key := "totp:replay:" + fmt.Sprint(userID) + ":" + hex.EncodeToString(sum[:])
			if !s.store.SetNX(key, "1", totpReplayTTL) {
				// Same code reused within the window — treat as a failed
				// attempt so repeat offenders hit the brute-force cap.
				s.recordFailure(ctx, userID, "totp replay")
				return ErrInvalidOTP
			}
		}
		s.recordSuccess(ctx, userID, models.AuditEventTOTPValidated, "totp validated")
		return nil
	}

	// ---- recovery-code path (O(1) per code, NOT bcrypt) ----
	codes, err := s.repo.ActiveRecoveryCodes(ctx, userID)
	if err != nil {
		return err
	}
	want := hash.HashRecoveryCode(code)
	for i := range codes {
		if hash.ConstantTimeCompare(codes[i].CodeHash, want) {
			if err := s.repo.MarkRecoveryCodeUsed(ctx, &codes[i]); err != nil {
				return err
			}
			s.recordSuccess(ctx, userID, models.AuditEventRecoveryCodeUsed, "recovery code used")
			return nil
		}
	}
	s.recordFailure(ctx, userID, "bad recovery code")
	return ErrInvalidOTP
}

// newRecoveryCodes generates a batch of high-entropy recovery codes, persists
// their SHA-256 hashes, and returns the plaintext codes (once) to the caller.
func (s *TOTPService) newRecoveryCodes(ctx context.Context, userID uint) ([]string, error) {
	n := s.cfg.RecoveryCodeCount
	plain := make([]string, n)
	rows := make([]*models.RecoveryCode, n)
	for i := 0; i < n; i++ {
		b, err := hash.GenerateRandomBytes(s.cfg.RecoveryCodeBytes)
		if err != nil {
			return nil, err
		}
		plain[i] = hex.EncodeToString(b)
		rows[i] = &models.RecoveryCode{
			UserID:   userID,
			CodeHash: hash.HashRecoveryCode(plain[i]),
		}
	}
	return plain, s.repo.CreateRecoveryCodes(ctx, rows)
}

// guardBruteForce enforces the per-user failed-attempt cap. It increments a
// counter in the shared store (so it holds across instances) and rejects with
// ErrRateLimited once the cap is exceeded. The cap backstops the per-IP rate
// limiter: an attacker rotating IPs to bypass it is still throttled per
// account. A nil store disables the check (single-instance dev / legacy tests).
func (s *TOTPService) guardBruteForce(ctx context.Context, userID uint) error {
	if s.store == nil {
		return nil
	}
	key := fmt.Sprintf("totp:fail:%d", userID)
	if n := s.store.IncrBy(key, 1, s.cfg.TOTPAttemptWindow); n > int64(s.cfg.TOTPMaxAttempts) {
		s.recordFailure(ctx, userID, "brute-force lockout")
		return ErrRateLimited
	}
	return nil
}

// recordSuccess fires-and-forgets a successful audit entry (best-effort,
// never blocks — the underlying AuditRepo is the async writer).
func (s *TOTPService) recordSuccess(ctx context.Context, userID uint, event, detail string) {
	if s.audits == nil {
		return
	}
	uid := userID
	s.audits.Record(ctx, &models.AuditLog{
		UserID: &uid, Event: event, Success: true, Detail: detail,
		CreatedAt: time.Now(),
	})
}

// recordFailure fires-and-forgets a failed attempt. Wrapped in a defer/recover
// because audit logging must NEVER break the auth flow.
func (s *TOTPService) recordFailure(ctx context.Context, userID uint, detail string) {
	if s.audits == nil {
		return
	}
	defer func() { _ = recover() }()
	uid := userID
	s.audits.Record(ctx, &models.AuditLog{
		UserID: &uid, Event: models.AuditEventTOTPFailed, Success: false, Detail: detail,
		CreatedAt: time.Now(),
	})
}

// IsTOTPError reports whether err is one of the TOTP-related sentinel errors,
// so callers (e.g. handlers) can branch without importing the sentinels.
func IsTOTPError(err error) bool {
	return errors.Is(err, ErrInvalidOTP) || errors.Is(err, ErrRateLimited)
}

// totpValid validates a 6-digit code against the secret with a ±1 step skew to
// tolerate minor clock drift between the client authenticator and the server.
// It wraps totp.ValidateCustom so the skew is applied consistently everywhere
// a code is checked.
func totpValid(code, secret string) bool {
	ok, err := totp.ValidateCustom(code, secret, time.Now(), totp.ValidateOpts{
		Period:    totpPeriod,
		Skew:      TOTPSkew,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	return err == nil && ok
}
