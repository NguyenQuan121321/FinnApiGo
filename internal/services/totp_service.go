package services

import (
	"log/slog"

	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/finnapigo/finnapigo/internal/config"
	"github.com/finnapigo/finnapigo/internal/crypto"
	"github.com/finnapigo/finnapigo/internal/hash"
	"github.com/finnapigo/finnapigo/internal/jwt"
	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/repositories"
	"github.com/finnapigo/finnapigo/internal/store"
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
	store  store.Store
	audits AuditRepo
	issuer string
	cfg    config.AuthConfig
	// enc seals the re-viewable copy of each recovery code (AES-256-GCM).
	// The SHA-256 hash remains the only thing the login-verification path
	// touches; the sealed copy is decrypted solely for the TOTP-gated view
	// endpoint. Built once at startup so the AES key schedule is not
	// re-derived on every seal/open call.
	enc *crypto.Encryptor
	// jwtMgr verifies the sudo token required to rotate an ACTIVE device
	// (C6). Nil fails closed — sudo can never be proven without it.
	jwtMgr *jwt.JWTManager
}

// NewTOTPService constructs the service. store may be nil (replay protection
// and the per-user attempt counter become no-ops); audits may be nil (audit
// writes are skipped). cfg drives recovery-code entropy/count and the
// brute-force window; when zero-valued the fields default to safe values so
// callers that only care about the core flow (e.g. legacy tests) still work.
// enc seals the displayable recovery-code copies with AES-256-GCM (see
// cmd/server wiring for how the key is sourced). jwtMgr verifies sudo tokens
// for re-enrollment of active devices.
func NewTOTPService(repo TOTPRepo, store store.Store, audits AuditRepo, issuer string, cfg config.AuthConfig, enc *crypto.Encryptor, jwtMgr *jwt.JWTManager) *TOTPService {
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
	return &TOTPService{repo: repo, store: store, audits: audits, issuer: issuer, cfg: cfg, enc: enc, jwtMgr: jwtMgr}
}

// Enable starts (or restarts) TOTP enrollment: it generates a fresh shared
// secret and returns the secret + the otpauth:// provisioning URI. The secret
// is persisted ONLY as an AES-256-GCM sealed copy (C7) — the plaintext exists
// in memory and in the API response for the user's authenticator, never at
// rest.
//
// Re-enrolling an ACTIVE device (C6) requires a valid sudo token for this
// user; the fresh secret is staged (sealed) as pending and the device STAYS
// enabled on its old secret until VerifyEnable confirms the new one — a
// stolen access token alone can neither rotate nor disable MFA. A device that
// was never confirmed (disabled) rotates freely, matching first-time
// enrollment.
func (s *TOTPService) Enable(ctx context.Context, userID uint, email, sudoToken string) (string, string, error) {
	if !s.acquireRotationLock(userID) {
		return "", "", ErrRateLimited
	}
	defer s.releaseRotationLock(userID)
	old, err := s.repo.FindByUserID(ctx, userID)
	if err != nil {
		return "", "", err
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer: s.issuer, AccountName: email,
	})
	if err != nil {
		return "", "", fmt.Errorf("totp generate: %w", err)
	}
	sealed, err := s.enc.Encrypt(key.Secret())
	if err != nil {
		return "", "", fmt.Errorf("seal totp secret: %w", err)
	}
	var d *models.TOTPDevice
	switch {
	case old == nil:
		d = &models.TOTPDevice{UserID: userID, SecretEncrypted: sealed, Enabled: false}
	case old.Enabled:
		if err := s.verifySudoToken(sudoToken, userID); err != nil {
			return "", "", err
		}
		old.PendingSecretEncrypted = sealed
		d = old
	default:
		// Abandoned enrollment: the device was never confirmed, so rotating
		// the secret outright is safe. This also wipes any legacy plaintext.
		old.Secret, old.SecretEncrypted, old.PendingSecretEncrypted = "", sealed, ""
		d = old
	}
	if err = s.repo.Upsert(ctx, d); err != nil {
		return "", "", err
	}
	return key.Secret(), key.URL(), nil
}

// verifySudoToken proves the caller holds a sudo JWT bound to this user —
// issued only after a current TOTP proof (see ViewRecoveryCodes). A missing
// manager or token, a bad signature/type/owner, or an absent expiry all
// refuse; sudo is never proven by default (fail closed).
func (s *TOTPService) verifySudoToken(token string, userID uint) error {
	if s.jwtMgr == nil || token == "" {
		return ErrSudoRequired
	}
	claims, err := s.jwtMgr.Verify(token)
	if err != nil || claims.Type != jwt.TokenTypeSudo || claims.UserID != userID || claims.ExpiresAt == nil {
		return ErrSudoRequired
	}
	return nil
}

// VerifyEnable confirms an enrollment: validates the provided 6-digit code
// and, on success, activates the device and issues a fresh batch of recovery
// codes. During a sudo-gated rotation of an ACTIVE device (C6) the code must
// match the pending secret; the active secret keeps serving logins until this
// confirmation swaps them (the swap moves ciphertext — no re-sealing needed).
// The plaintext recovery codes are returned to the caller; at rest only their
// SHA-256 hashes (for login verification) and an AES-256-GCM sealed copy (for
// the TOTP-gated view endpoint) persist. Issuing a fresh batch also replaces
// any codes left over from a previous enrollment.
func (s *TOTPService) VerifyEnable(ctx context.Context, userID uint, code string) ([]string, error) {
	if err := s.guardBruteForce(ctx, userID); err != nil {
		return nil, err
	}
	// Serialize the activation critical section: two concurrent verify
	// submissions (double-click, retry storm) must not both pass the enabled
	// check and race the secret swap + recovery-code replacement — the loser
	// would silently invalidate the codes the first response just displayed.
	if !s.acquireRotationLock(userID) {
		return nil, ErrRateLimited
	}
	defer s.releaseRotationLock(userID)
	d, err := s.repo.FindByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if d == nil {
		s.recordFailure(ctx, userID, "no pending device")
		return nil, ErrInvalidCode
	}
	confirming := d.PendingSecretEncrypted != ""
	if d.Enabled && !confirming {
		return nil, ErrInvalidInput
	}
	secret := d.PendingSecretEncrypted
	if confirming {
		if secret, err = s.enc.Decrypt(secret); err != nil {
			return nil, fmt.Errorf("open pending totp secret: %w", err)
		}
	} else if secret, err = s.openActiveSecret(ctx, d); err != nil {
		return nil, err
	}
	if !totpValid(code, secret) {
		s.recordFailure(ctx, userID, "bad enable code")
		return nil, ErrInvalidCode
	}
	prevActive := d.SecretEncrypted
	if confirming {
		// Promote the sealed pending secret; the device stays enabled
		// throughout, and any legacy plaintext is wiped.
		d.SecretEncrypted, d.PendingSecretEncrypted = d.PendingSecretEncrypted, ""
		d.Secret = ""
	}
	d.Enabled = true
	if err = s.repo.Upsert(ctx, d); err != nil {
		return nil, err
	}
	codes, err := s.newRecoveryCodes(ctx, userID)
	if err != nil {
		// Roll back so the user can retry Enable -> VerifyEnable: a pending
		// rotation returns to staged state, a fresh enrollment is deactivated.
		if confirming {
			d.PendingSecretEncrypted, d.SecretEncrypted = d.SecretEncrypted, prevActive
		} else {
			d.Enabled = false
		}
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
		return ErrInvalidCode
	}

	// ---- 6-digit TOTP fast path ----
	if len(code) == 6 {
		secret, err := s.openActiveSecret(ctx, d)
		if err != nil {
			return err
		}
		if !totpValid(code, secret) {
			s.recordFailure(ctx, userID, "bad totp code")
			return ErrInvalidCode
		}
		// Replay protection: a code may only be used once within its validity
		// window. SetNX is atomic, so concurrent identical submissions collide
		// and exactly one wins.
		if !s.replayGuard(ctx, userID, code) {
			// Same code reused within the window — treat as a failed
			// attempt so repeat offenders hit the brute-force cap.
			s.recordFailure(ctx, userID, "totp replay")
			return ErrInvalidCode
		}
		s.recordSuccess(ctx, userID, models.AuditEventTOTPValidated, "totp validated")
		return nil
	}

	// ---- recovery-code path (O(1) per code, NOT bcrypt) ----
	codes, err := s.repo.ActiveRecoveryCodes(ctx, userID)
	if err != nil {
		return err
	}
	hashes := make([]string, len(codes))
	for i := range codes {
		hashes[i] = codes[i].CodeHash
	}
	if idx := hash.MatchRecoveryCode(code, hashes); idx >= 0 {
		if err := s.repo.MarkRecoveryCodeUsed(ctx, &codes[idx]); err != nil {
			if errors.Is(err, repositories.ErrRecoveryCodeUsed) {
				// A concurrent request consumed the code between our read
				// and the mark — same outcome as any failed attempt.
				s.recordFailure(ctx, userID, "recovery code replay")
				return ErrInvalidCode
			}
			return err
		}
		s.recordSuccess(ctx, userID, models.AuditEventRecoveryCodeUsed, "recovery code used")
		return nil
	}
	s.recordFailure(ctx, userID, "bad recovery code")
	return ErrInvalidCode
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
		return nil, ErrInvalidCode
	}
	secret, err := s.openActiveSecret(ctx, d)
	if err != nil {
		return nil, err
	}
	if len(code) != 6 || !totpValid(code, secret) {
		s.recordFailure(ctx, userID, "view codes: bad totp code")
		return nil, ErrInvalidCode
	}
	if !s.replayGuard(ctx, userID, code) {
		s.recordFailure(ctx, userID, "view codes: totp replay")
		return nil, ErrInvalidCode
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
		plain, err := s.enc.Decrypt(rows[i].CodeEncrypted)
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
		return nil, ErrInvalidCode
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
		sealed, err := s.enc.Encrypt(plain[i])
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

// openActiveSecret returns the device's active secret, decrypting the sealed
// copy; rows written before encrypted storage existed fall back to their
// plaintext Secret (lazy migration on read — C7).
// openActiveSecret resolves the device's TOTP shared secret. The sealed copy
// is authoritative; when it cannot be opened with the current key (key
// rotated / JWT_SECRET-derived key changed — the K1/C7 rotation consequence)
// the legacy plaintext column, if present, keeps the SAME secret valid and is
// re-sealed under the current key immediately (lazy migration on read). A row
// with neither a readable seal nor plaintext is unrecoverable and surfaces as
// ErrTOTPUnrecoverable so the handler answers 4xx with a re-enroll hint
// instead of an opaque 500.
func (s *TOTPService) openActiveSecret(ctx context.Context, d *models.TOTPDevice) (string, error) {
	if d.SecretEncrypted == "" {
		return d.Secret, nil
	}
	plain, err := s.enc.Decrypt(d.SecretEncrypted)
	if err == nil {
		return plain, nil
	}
	// Sealed copy is unreadable under the current key.
	if d.Secret == "" {
		return "", fmt.Errorf("%w: sealed TOTP secret cannot be opened with the active key", ErrTOTPUnrecoverable)
	}
	// Legacy plaintext holds the same shared secret — heal the row. Best
	// effort: a failed re-seal must not block the login; the plaintext path
	// stays active and the next read retries.
	resealed, sealErr := s.enc.Encrypt(d.Secret)
	if sealErr == nil {
		d.SecretEncrypted = resealed
		if upsertErr := s.repo.Upsert(ctx, d); upsertErr != nil {
			slog.Warn("totp: re-seal of legacy secret failed; plaintext path stays active", "user_id", d.UserID, "err", upsertErr)
		}
	} else {
		slog.Warn("totp: could not re-seal legacy secret; plaintext path stays active", "user_id", d.UserID, "err", sealErr)
	}
	return d.Secret, nil //nolint:nilerr // plaintext keeps the ceremony working; healing is best-effort
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

// guardBruteForce enforces the per-user failed-attempt cap by READING the
// current count — it never increments: successes must not feed the window
// (C9); only recordFailure does. The cap backstops the per-IP rate limiter:
// an attacker rotating IPs to bypass it is still throttled per account.
// A nil store disables the check (single-instance dev / legacy tests).
func (s *TOTPService) guardBruteForce(ctx context.Context, userID uint) error {
	if s.store == nil {
		return nil
	}
	key := fmt.Sprintf("totp:fail:%d", userID)
	if storeCounterValue(s.store, key) >= int64(s.cfg.TOTPMaxAttempts) {
		s.recordFailure(ctx, userID, "brute-force lockout")
		return ErrRateLimited
	}
	return nil
}

// recordSuccess fires-and-forgets a successful audit entry (best-effort,
// never blocks — the underlying AuditRepo is the async writer). A success
// also clears the per-user brute-force window (C9): having proven possession
// of the factor, earlier failures should not linger toward the cap.
func (s *TOTPService) recordSuccess(ctx context.Context, userID uint, event, detail string) {
	if s.store != nil {
		s.store.Delete(fmt.Sprintf("totp:fail:%d", userID))
	}
	if s.audits == nil {
		return
	}
	uid := userID
	s.audits.Record(ctx, &models.AuditLog{
		UserID: &uid, Event: event, Success: true, Detail: detail,
		CreatedAt: time.Now(),
	})
}

// recordFailure fires-and-forgets a failed attempt — and this is the ONLY
// place the per-user brute-force counter grows (C9: failures only). Wrapped
// in a defer/recover because audit logging must NEVER break the auth flow.
func (s *TOTPService) recordFailure(ctx context.Context, userID uint, detail string) {
	TOTPFailures.Add(1)
	if s.store != nil {
		s.store.IncrBy(fmt.Sprintf("totp:fail:%d", userID), 1, s.cfg.TOTPAttemptWindow)
	}
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

// rotationLockTTL bounds the per-user enrollment/rotation critical section.
const rotationLockTTL = 10 * time.Second

// acquireRotationLock serializes the read-modify-write enrollment flows
// (Enable / VerifyEnable) per user via the shared store. Returns false when
// another rotation is in flight (429 to the caller). Nil store (tests) = no-op.
func (s *TOTPService) acquireRotationLock(userID uint) bool {
	if s.store == nil {
		return true
	}
	return s.store.SetNX(fmt.Sprintf("totp:rotatelock:%d", userID), "1", rotationLockTTL)
}

// releaseRotationLock drops the per-user rotation critical section.
func (s *TOTPService) releaseRotationLock(userID uint) {
	if s.store != nil {
		s.store.Delete(fmt.Sprintf("totp:rotatelock:%d", userID))
	}
}

// storeCounterValue reads a counter written by IncrBy WITHOUT incrementing
// it. Redis hands counters back as strings; the in-memory store keeps int64.
func storeCounterValue(s store.Store, key string) int64 {
	v, ok := s.Get(key)
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case int64:
		return n
	case int:
		return int64(n)
	case string:
		c, _ := strconv.ParseInt(n, 10, 64)
		return c
	}
	return 0
}

// IsTOTPError reports whether err is one of the TOTP-related sentinel errors,
// so callers (e.g. handlers) can branch without importing the sentinels.
func IsTOTPError(err error) bool {
	return errors.Is(err, ErrInvalidCode) || errors.Is(err, ErrRateLimited)
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
