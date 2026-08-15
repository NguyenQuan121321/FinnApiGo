package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/finnapigo/finnapigo/internal/config"
	"github.com/finnapigo/finnapigo/internal/crypto"
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
	// encKey seals the re-viewable copy of each recovery code (AES-256-GCM).
	// The SHA-256 hash remains the only thing the login-verification path
	// touches; the sealed copy is decrypted solely for the TOTP-gated view
	// endpoint.
	encKey []byte
}

// NewTOTPService constructs the service. store may be nil (replay protection
// and the per-user attempt counter become no-ops); audits may be nil (audit
// writes are skipped). cfg drives recovery-code entropy/count and the
// brute-force window; when zero-valued the fields default to safe values so
// callers that only care about the core flow (e.g. legacy tests) still work.
// encKey must be a 32-byte AES-256 key; it seals the displayable recovery-code
// copies (see cmd/server wiring for how it is sourced).
func NewTOTPService(repo TOTPRepo, store StoreProvider, audits AuditRepo, issuer string, cfg config.AuthConfig, encKey []byte) *TOTPService {
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
	return &TOTPService{repo: repo, store: store, audits: audits, issuer: issuer, cfg: cfg, encKey: encKey}
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
// to the caller; at rest only their SHA-256 hashes (for login verification)
// and an AES-256-GCM sealed copy (for the TOTP-gated view endpoint) persist.
// Issuing a fresh batch also replaces any codes left over from a previous
// enrollment.
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
		return nil, fmt.Errorf("generate recovery codes: %w", err)
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
		if !s.replayGuard(ctx, userID, code) {
			// Same code reused within the window — treat as a failed
			// attempt so repeat offenders hit the brute-force cap.
			s.recordFailure(ctx, userID, "totp replay")
			return ErrInvalidOTP
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

// ViewRecoveryCodes re-displays the user's saved (unused) recovery codes.
// GitHub-style: the request must carry a CURRENT 6-digit TOTP code — a
// recovery code deliberately cannot unlock the list, since a leaked recovery
// code would then reveal all its siblings. On success the caller (handler
// layer) also mints a short-lived sudo token so follow-up sensitive actions
// (regenerating) don't re-prompt within the sudo window.
func (s *TOTPService) ViewRecoveryCodes(ctx context.Context, userID uint, code string) ([]string, error) {
	if err := s.guardBruteForce(ctx, userID); err != nil {
		return nil, err
	}
	d, err := s.repo.FindByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if d == nil || !d.Enabled {
		s.recordFailure(ctx, userID, "view codes: device not enabled")
		return nil, ErrInvalidOTP
	}
	if len(code) != 6 || !totpValid(code, d.Secret) {
		s.recordFailure(ctx, userID, "view codes: bad totp code")
		return nil, ErrInvalidOTP
	}
	if !s.replayGuard(ctx, userID, code) {
		s.recordFailure(ctx, userID, "view codes: totp replay")
		return nil, ErrInvalidOTP
	}
	rows, err := s.repo.ActiveRecoveryCodes(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for i := range rows {
		if rows[i].CodeEncrypted == "" {
			// Row predates encrypted storage — it can be used at login but
			// not re-displayed; regenerating replaces the whole set.
			continue
		}
		plain, err := crypto.Decrypt(s.encKey, rows[i].CodeEncrypted)
		if err != nil {
			// Key rotated or row corrupted — same remedy as above.
			continue
		}
		out = append(out, plain)
	}
	s.recordSuccess(ctx, userID, models.AuditEventRecoveryCodesViewed, "recovery codes viewed")
	return out, nil
}

// RegenerateRecoveryCodes invalidates the user's ENTIRE current set (used and
// unused rows are deleted) and issues a brand-new batch of one-time codes.
// The fresh plaintext codes are returned once. This method performs NO TOTP
// check itself: the HTTP layer gates it behind sudo mode, which requires a
// verified TOTP-derived token bound to the same user.
func (s *TOTPService) RegenerateRecoveryCodes(ctx context.Context, userID uint) ([]string, error) {
	d, err := s.repo.FindByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if d == nil || !d.Enabled {
		s.recordFailure(ctx, userID, "regenerate codes: device not enabled")
		return nil, ErrInvalidOTP
	}
	codes, err := s.newRecoveryCodes(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("regenerate recovery codes: %w", err)
	}
	s.recordSuccess(ctx, userID, models.AuditEventRecoveryCodesRegenerated, "recovery codes regenerated")
	return codes, nil
}

// newRecoveryCodes generates a batch of high-entropy recovery codes, atomically
// replaces any existing set for the user, and returns the plaintext codes to
// the caller. Each row persists the SHA-256 hash (login verification) and an
// AES-256-GCM sealed copy (TOTP-gated re-viewing).
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
		sealed, err := crypto.Encrypt(s.encKey, plain[i])
		if err != nil {
			return nil, fmt.Errorf("seal recovery code: %w", err)
		}
		rows[i] = &models.RecoveryCode{
			UserID:        userID,
			CodeHash:      hash.HashRecoveryCode(plain[i]),
			CodeEncrypted: sealed,
		}
	}
	return plain, s.repo.ReplaceRecoveryCodes(ctx, userID, rows)
}

// replayGuard enforces that a 6-digit TOTP code is consumed at most once per
// validity window: it SetNXs the code's hash in the shared store and reports
// false when the key already existed (a replay). A nil store (single-instance
// dev / legacy tests) disables the check.
func (s *TOTPService) replayGuard(ctx context.Context, userID uint, code string) bool {
	if s.store == nil {
		return true
	}
	sum := sha256.Sum256([]byte(code))
	key := "totp:replay:" + fmt.Sprint(userID) + ":" + hex.EncodeToString(sum[:])
	return s.store.SetNX(key, "1", totpReplayTTL)
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
