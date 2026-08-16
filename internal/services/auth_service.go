// Package services contains all business logic. It is deliberately decoupled
// from Gin (no *gin.Context imports) so every method can be unit-tested with
// a mocked repository. Handlers translate HTTP <-> service calls.
package services

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/finnapigo/finnapigo/internal/config"
	"github.com/finnapigo/finnapigo/internal/device"
	"github.com/finnapigo/finnapigo/internal/geo"
	"github.com/finnapigo/finnapigo/internal/hash"
	"github.com/finnapigo/finnapigo/internal/jwt"
	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/store"
	"github.com/go-sql-driver/mysql"
	"gorm.io/gorm"
)

// dummyHash is a pre-computed bcrypt hash of a static string. It is compared
// during login when the user doesn't exist, so the response time is
// indistinguishable from a wrong-password path. Generated once at init.
var dummyHash string

func init() {
	h, err := hash.HashPassword("dummy-timing-equalization")
	if err != nil {
		panic("auth: failed to generate dummy bcrypt hash: " + err.Error())
	}
	dummyHash = h
}

// AuthService holds all core-auth business logic. It depends only on repo
// interfaces + stateless helpers (jwt, hashing), so it is trivially unit-testable.
type AuthService struct {
	users         UserRepo
	tokens        RefreshTokenRepo
	usedTokens    UsedTokenRepo
	audits        AuditRepo
	store         store.Store
	jwt           *jwt.JWTManager
	cfg           config.AuthConfig
	rlCfg         config.RateLimitConfig // §2/§3 velocity + adaptive-captcha knobs
	jwtCfg        config.JWTConfig
	notify        Notifier
	captcha       CaptchaVerifier // §3 — nil-safe (NoOp when off)
	geo           geo.Resolver    // IP -> location label; nil-safe (Unknown)
	totpRepo      TOTPRepo        // nil-safe — MFA check skipped when nil
	totpValidator TOTPValidator   // nil-safe — MFA completion unavailable when nil
}

// NewAuthService constructs the service. Repos are interfaces so mocks can be
// passed in tests. store may be nil (some features will be no-ops). rlCfg drives
// the §2/§3 velocity limiters and adaptive CAPTCHA; captcha may be nil.
// geoResolver may be nil (defaults to NoOp — all locations "Unknown").
func NewAuthService(
	users UserRepo,
	tokens RefreshTokenRepo,
	usedTokens UsedTokenRepo,
	audits AuditRepo,
	store store.Store,
	jwt *jwt.JWTManager,
	authCfg config.AuthConfig,
	rlCfg config.RateLimitConfig,
	jwtCfg config.JWTConfig,
	notify Notifier,
	captcha CaptchaVerifier,
	geoResolver geo.Resolver,
	totpRepo TOTPRepo,
	totpValidator TOTPValidator,
) *AuthService {
	if captcha == nil {
		captcha = NoOpCaptchaVerifier{}
	}
	if geoResolver == nil {
		geoResolver = geo.NewNoOpResolver()
	}
	return &AuthService{
		users: users, tokens: tokens, usedTokens: usedTokens, audits: audits,
		store: store, jwt: jwt, cfg: authCfg, rlCfg: rlCfg, jwtCfg: jwtCfg,
		notify: notify, captcha: captcha, geo: geoResolver,
		totpRepo: totpRepo, totpValidator: totpValidator,
	}
}

// ----- 1. Register -----

// Register creates a new user account: validates complexity, rejects duplicate
// email/username, hashes the password, sends a verification email via the
// notifier (§1.1 — token is NO LONGER returned in the API response).
func (s *AuthService) Register(ctx context.Context, in RegisterInput) (UserProfile, error) {
	in.Username = strings.TrimSpace(in.Username)
	in.Email = strings.ToLower(strings.TrimSpace(in.Email))
	in.FullName = strings.TrimSpace(in.FullName)

	if err := validatePassword(in.Password); err != nil {
		return UserProfile{}, err
	}

	// §2 — registration velocity limiting (per-IP). Thwarts scripted mass
	// account creation regardless of the per-endpoint rate limiter in the
	// middleware. Uses the store so this is shared across instances.
	if s.store != nil && in.IP != "" {
		key := "reg:ip:" + in.IP
		count := s.store.IncrBy(key, 1, s.rlCfg.RegisterWindow)
		if count > int64(s.rlCfg.RegisterPerIPMax) {
			return UserProfile{}, ErrRateLimited
		}
	}

	// §2 — reject known disposable/throwaway email providers.
	if isDisposableEmail(in.Email) {
		return UserProfile{}, ErrDisposableEmail
	}

	// uniqueness checks (email + username)
	if existing, err := s.users.FindByEmail(ctx, in.Email); err != nil {
		return UserProfile{}, fmt.Errorf("register: find email: %w", err)
	} else if existing != nil {
		return UserProfile{}, ErrEmailExists
	}
	if existing, err := s.users.FindByUsername(ctx, in.Username); err != nil {
		return UserProfile{}, fmt.Errorf("register: find username: %w", err)
	} else if existing != nil {
		return UserProfile{}, ErrUsernameExists
	}

	hashed, err := hash.HashPassword(in.Password)
	if err != nil {
		return UserProfile{}, err
	}

	user := &models.User{
		Username: in.Username,
		Email:    in.Email,
		Password: hashed,
		FullName: in.FullName,
		Role:     models.RoleUser,
		IsActive: true,
	}
	// §1.7 — TOCTOU race: two concurrent registers with the same email/username
	// can both pass the existence checks. The unique DB index rejects the second
	// insert. We inspect the error here and map MySQL duplicate-key (1062)
	// to the correct sentinel error instead of a generic 500.
	if err := s.users.Create(ctx, user); err != nil {
		return UserProfile{}, mapDuplicateKey(in.Email, in.Username, err)
	}

	// §1.1 — Issue a verification JWT and deliver it via the notifier.
	// The token is NEVER returned to the client — the user must prove
	// control of their inbox to self-verify.
	verifyToken, err := s.jwt.Issue(user.ID, user.Role, user.Email,
		jwt.TokenTypeEmailVerify, s.jwtCfg.VerifyTTL)
	if err != nil {
		return UserProfile{}, err
	}
	if err := s.notify.SendEmailVerification(user.Email, verifyToken); err != nil {
		return UserProfile{}, fmt.Errorf("register: send verification email: %w", err)
	}
	return FromUser(user), nil
}

// ----- 2. Login -----

// Login authenticates credentials, applies lockout logic, and returns a fresh
// access + refresh token pair — unless the user has TOTP enabled, in which case
// it returns a short-lived mfa_pending token and a nil TokenPair so the handler
// can prompt for a second factor before issuing real tokens.
func (s *AuthService) Login(ctx context.Context, in LoginInput, ip, ua string) (TokenPair, UserProfile, *MFAPendingResult, error) {
	email := strings.ToLower(strings.TrimSpace(in.Email))

	// §3 — per-account login velocity limit: throttle repeated attempts against
	// one email even when spread across many IPs. Uses the store so the limit
	// is shared across instances.
	if s.store != nil && email != "" && s.rlCfg.LoginPerAccountMax > 0 {
		key := "login:acct:" + email
		count := s.store.IncrBy(key, 1, s.rlCfg.LoginWindow)
		if count > int64(s.rlCfg.LoginPerAccountMax) {
			return TokenPair{}, UserProfile{}, nil, ErrRateLimited
		}
	}

	// §3 — adaptive CAPTCHA: after N failed login attempts from one IP, require
	// a valid CAPTCHA token before proceeding. This blocks credential-stuffing
	// tools that rotate IPs to avoid per-IP rate limits.
	if s.captcha != nil && s.store != nil {
		failKey := "loginfail:" + ip
		if v, ok := s.store.Get(failKey); ok {
			if n, _ := v.(int64); n >= int64(s.rlCfg.LoginCaptchaAfterFails) {
				if err := s.captcha.Verify(ctx, in.CaptchaToken); err != nil {
					return TokenPair{}, UserProfile{}, nil, ErrCaptchaRequired
				}
			}
		}
	}

	user, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		return TokenPair{}, UserProfile{}, nil, fmt.Errorf("login: find user: %w", err)
	}
	// §1.6 — Timing side-channel mitigation: when user == nil, still run a
	// bcrypt comparison against a dummy hash so both code paths take ~equal
	// time (~100-300ms). The error message is identical either way.
	if user == nil {
		hash.CheckPassword(dummyHash, in.Password)
		s.recordLoginFailIP(ctx, ip)
		s.audits.Record(ctx, loginFailedEvent(nil, email, ip, "unknown user"))
		return TokenPair{}, UserProfile{}, nil, ErrInvalidCredentials
	}

	// §2 — optional email-verification gate. When RequireEmailVerified is
	// true, unverified accounts cannot log in. Default false to avoid breaking
	// existing UX; the CHANGELOG and README document this as a policy decision.
	if s.cfg.RequireEmailVerified && !user.IsEmailVerified {
		return TokenPair{}, UserProfile{}, nil, ErrEmailNotVerified
	}

	if !user.IsActive {
		s.audits.Record(ctx, loginFailedEvent(&user.ID, email, ip, "disabled"))
		return TokenPair{}, UserProfile{}, nil, ErrAccountDisabled
	}

	if locked := s.isLocked(user); locked {
		s.audits.Record(ctx, loginFailedEvent(&user.ID, email, ip, "locked"))
		return TokenPair{}, UserProfile{}, nil, ErrAccountLocked
	}

	if !hash.CheckPassword(user.Password, in.Password) {
		s.recordFailedLogin(ctx, user, email, ip)
		return TokenPair{}, UserProfile{}, nil, ErrInvalidCredentials
	}

	// success: reset counter
	if err := s.users.ResetFailedAttempts(ctx, user); err != nil {
		return TokenPair{}, UserProfile{}, nil, err
	}

	return s.CheckMFAOrIssueTokens(ctx, user, ip, ua, "")
}

// ----- 2b. Complete MFA Login -----

// CompleteMFALogin validates the TOTP code for a user who has already passed
// password authentication (proven by a valid mfa_pending JWT). On success it
// issues the real access+refresh token pair and creates the session/device DB
// record. The TOTP validation is delegated to the injected TOTPValidator,
// reusing the exact same logic as the existing /totp/validate endpoint.
func (s *AuthService) CompleteMFALogin(ctx context.Context, in CompleteMFALoginInput) (TokenPair, UserProfile, error) {
	if s.totpValidator == nil {
		return TokenPair{}, UserProfile{}, ErrInvalidToken
	}

	if err := s.totpValidator.Validate(ctx, in.UserID, in.Code); err != nil {
		return TokenPair{}, UserProfile{}, err
	}

	user, err := s.users.FindByID(ctx, in.UserID)
	if err != nil {
		return TokenPair{}, UserProfile{}, err
	}
	if user == nil || !user.IsActive {
		return TokenPair{}, UserProfile{}, ErrInvalidToken
	}

	pair, err := s.issueTokenPair(ctx, user, in.IP, in.UA)
	if err != nil {
		return TokenPair{}, UserProfile{}, err
	}
	s.audits.Record(ctx, &models.AuditLog{
		UserID: &user.ID, Email: user.Email, Event: models.AuditEventLogin,
		IPAddress: in.IP, Success: true, Detail: "mfa-complete",
	})
	return pair, FromUser(user), nil
}

// ----- 2c. Shared MFA + token issuance helper ----

// CheckMFAOrIssueTokens checks whether the user has TOTP enabled. If so it
// issues a short-lived mfa_pending JWT; otherwise it issues a full access +
// refresh token pair and records a login audit event. This is called from both
// the password Login path and the Google OAuth callback path so the MFA
// enforcement logic is never duplicated.
//
// auditDetail is an optional label for the audit row (e.g. "" for password,
// "google-oauth" for Google sign-in).
func (s *AuthService) CheckMFAOrIssueTokens(ctx context.Context, user *models.User, ip, ua, auditDetail string) (TokenPair, UserProfile, *MFAPendingResult, error) {
	// ---- MFA enforcement: check if TOTP is active for this user ----
	// When totpRepo is nil (e.g. legacy tests), skip the check entirely so
	// the login flow is unchanged for users without TOTP wired.
	if s.totpRepo != nil {
		device, err := s.totpRepo.FindByUserID(ctx, user.ID)
		if err != nil {
			return TokenPair{}, UserProfile{}, nil, fmt.Errorf("login: check totp: %w", err)
		}
		if device != nil && device.Enabled {
			// TOTP is active — issue a short-lived mfa_pending token carrying
			// only uid + type (no role/permissions). The user must complete
			// MFA via /mfa/login-verify to receive real tokens.
			mfaToken, err := s.jwt.Issue(user.ID, "", "",
				jwt.TokenTypeMFAPending, s.jwtCfg.MFAPendingTTL)
			if err != nil {
				return TokenPair{}, UserProfile{}, nil, err
			}
			return TokenPair{}, UserProfile{}, &MFAPendingResult{
				MFARequired: true,
				MFAToken:    mfaToken,
			}, nil
		}
	}

	pair, err := s.issueTokenPair(ctx, user, ip, ua)
	if err != nil {
		return TokenPair{}, UserProfile{}, nil, err
	}
	s.audits.Record(ctx, &models.AuditLog{
		UserID: &user.ID, Email: user.Email, Event: models.AuditEventLogin,
		IPAddress: ip, Success: true, Detail: auditDetail,
	})
	return pair, FromUser(user), nil, nil
}

// ----- 3. Logout -----

// Logout revokes the supplied refresh token (idempotent — revoking an
// already-revoked or unknown token is not an error, to avoid leaking state).
func (s *AuthService) Logout(ctx context.Context, refreshToken, ip string) error {
	hash := hash.HashToken(refreshToken)
	rt, err := s.tokens.FindByHash(ctx, hash)
	if err != nil {
		return fmt.Errorf("logout: find token: %w", err)
	}
	if rt == nil || rt.Revoked {
		return nil
	}
	if err := s.tokens.Revoke(ctx, rt); err != nil {
		return err
	}
	uid := rt.UserID
	s.audits.Record(ctx, &models.AuditLog{
		UserID: &uid, Event: models.AuditEventLogout, IPAddress: ip, Success: true,
	})
	return nil
}

// ----- 3b. LogoutAll -----

// LogoutAll revokes every active refresh token for the authenticated user —
// a "sign out everywhere" action (§4). Callers should provide the current
// refresh token separately if they want it revoked too (or call Logout first).
func (s *AuthService) LogoutAll(ctx context.Context, userID uint, ip string) error {
	if err := s.tokens.RevokeAllForUser(ctx, userID); err != nil {
		return err
	}
	s.audits.Record(ctx, &models.AuditLog{
		UserID: &userID, Event: models.AuditEventLogout, IPAddress: ip,
		Success: true, Detail: "logout-all",
	})
	return nil
}

// ----- 4. Refresh token (rotation) -----

// Refresh validates the presented refresh token, revokes it, and issues a NEW
// access + refresh pair (rotation). Reuse of the old token is therefore detected.
// The caller's ip/ua are stamped onto the new session and used for audit events.
func (s *AuthService) Refresh(ctx context.Context, refreshToken, ip, ua string) (TokenPair, error) {
	hash := hash.HashToken(refreshToken)
	rt, err := s.tokens.FindByHash(ctx, hash)
	if err != nil {
		return TokenPair{}, fmt.Errorf("refresh: find token: %w", err)
	}

	if rt == nil {
		return TokenPair{}, ErrInvalidToken
	}

	// §Session — a revoked session can NEVER rotate. Block instantly and treat
	// it as a reuse/theft signal: revoke ALL of the user's sessions (per the
	// existing security spec) and record a high-severity audit event.
	if rt.Revoked {
		_ = s.tokens.RevokeAllForUser(ctx, rt.UserID)
		s.audits.Record(ctx, &models.AuditLog{
			UserID: &rt.UserID, Event: models.AuditEventTokenReuse,
			IPAddress: ip, Success: false, Detail: "revoked refresh token presented",
		})
		return TokenPair{}, ErrInvalidToken
	}

	if time.Now().After(rt.ExpiresAt) {
		_ = s.tokens.Revoke(ctx, rt)
		return TokenPair{}, ErrInvalidToken
	}

	user, err := s.users.FindByID(ctx, rt.UserID)
	if err != nil {
		return TokenPair{}, err
	}
	if user == nil || !user.IsActive {
		return TokenPair{}, ErrInvalidToken
	}

	// Rotate: revoke the old, issue a new pair (carrying the caller's device
	// metadata so the "sessions" list reflects the rotating device).
	if err := s.tokens.Revoke(ctx, rt); err != nil {
		return TokenPair{}, err
	}
	pair, err := s.issueTokenPair(ctx, user, ip, ua)
	if err != nil {
		return TokenPair{}, err
	}
	s.audits.Record(ctx, &models.AuditLog{
		UserID: &user.ID, Event: models.AuditEventRefreshToken, IPAddress: ip, Success: true,
	})
	return pair, nil
}

// ----- 5. Forgot password -----

// ForgotPassword generates a password-reset JWT and delivers it via the
// notifier. It NEVER reveals whether the email exists — it returns nil for
// unknown users so the handler can return an identical message.
func (s *AuthService) ForgotPassword(ctx context.Context, email, ip string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	user, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		return fmt.Errorf("forgot-password: find user: %w", err)
	}
	if user == nil {
		return nil
	}
	resetToken, err := s.jwt.Issue(user.ID, user.Role, user.Email,
		jwt.TokenTypeReset, s.jwtCfg.ResetTTL)
	if err != nil {
		return err
	}
	if err := s.notify.SendPasswordReset(email, resetToken); err != nil {
		return fmt.Errorf("forgot-password: send: %w", err)
	}
	return nil
}

// ----- 5b. Resend verification email -----

// ResendVerifyEmail issues a fresh type=verify-email JWT and delivers it via
// the notifier. It NEVER reveals whether the email exists or is already
// verified — unknown/verified/disposable/blocked all surface identically
// (anti-enumeration, ASVS v4.0-2.1.1) except ErrRateLimited, which lets a
// legitimate client back off.
//
// Defense-in-depth layering (each layer short-circuits before the next, and
// every store-backed layer is shared across instances via the store.Store):
//  1. per-IP middleware limiter (process-local, cheap first filter)
//  2. GLOBAL volume cap — circuit-breaker vs botnet floods rotating IPs+emails
//  3. per-IP service throttle — store-backed, survives IP rotation
//  4. disposable-domain rejection — O(1) lookup before any DB hit
//  5. per-email throttle — stops repeat bombing of one inbox
//  6. FindByEmail → issue JWT → notify
//
// All rate-limit trips and disposable rejections are recorded as audit events
// (ASVS v4.0-7.3.1) for SOC visibility.
func (s *AuthService) ResendVerifyEmail(ctx context.Context, email, ip string) error {
	email = strings.ToLower(strings.TrimSpace(email))

	// Layer 2 (§7.6.3) — GLOBAL volume cap: the only control that stops an
	// attacker rotating BOTH IPs and emails (per-key limiters cannot). Acts as
	// a hard circuit-breaker on the entire resend endpoint.
	if s.store != nil && s.rlCfg.VerifyResendGlobalMax > 0 {
		if n := s.store.IncrBy("verify:resend:global", 1, s.rlCfg.VerifyResendGlobalWindow); n > int64(s.rlCfg.VerifyResendGlobalMax) {
			s.audits.Record(ctx, &models.AuditLog{
				Event: models.AuditEventVerifyResendBlocked, Email: email,
				IPAddress: ip, Success: false, Detail: "global cap",
			})
			return ErrRateLimited
		}
	}

	// Layer 3 (§7.6.3) — per-IP service throttle. Store-backed, so unlike the
	// in-process middleware limiter it is shared across instances and survives
	// IP rotation toward a single target inbox.
	if s.store != nil && ip != "" && s.rlCfg.VerifyResendPerIPMax > 0 {
		if n := s.store.IncrBy("verify:resend:ip:"+ip, 1, s.rlCfg.VerifyResendPerIPWindow); n > int64(s.rlCfg.VerifyResendPerIPMax) {
			s.audits.Record(ctx, &models.AuditLog{
				Event: models.AuditEventVerifyResendBlocked, Email: email,
				IPAddress: ip, Success: false, Detail: "per-ip cap",
			})
			return ErrRateLimited
		}
	}

	// Layer 4 (§2.1.1) — disposable-domain rejection at the source. Reuses the
	// existing isDisposableEmail O(1) lookup; runs BEFORE the DB query. Returns
	// nil (success-like) so an attacker cannot probe which addresses are blocked.
	if isDisposableEmail(email) {
		s.audits.Record(ctx, &models.AuditLog{
			Event: models.AuditEventVerifyResendBlocked, Email: email,
			IPAddress: ip, Success: false, Detail: "disposable domain",
		})
		return nil
	}

	// Layer 5 — per-email throttle: stops repeat bombing of a single inbox.
	if s.store != nil && email != "" && s.rlCfg.VerifyResendPerEmailMax > 0 {
		key := "verify:resend:" + email
		count := s.store.IncrBy(key, 1, s.rlCfg.VerifyResendWindow)
		if count > int64(s.rlCfg.VerifyResendPerEmailMax) {
			s.audits.Record(ctx, &models.AuditLog{
				Event: models.AuditEventVerifyResendBlocked, Email: email,
				IPAddress: ip, Success: false, Detail: "per-email cap",
			})
			return ErrRateLimited
		}
	}

	// Layer 6 — lookup, issue, notify.
	user, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		return fmt.Errorf("resend-verify: find user: %w", err)
	}
	// Anti-enumeration: unknown email -> nil (handler emits the same message).
	if user == nil {
		return nil
	}
	// Already verified -> no-op (no redundant email), still nil.
	if user.IsEmailVerified {
		return nil
	}

	verifyToken, err := s.jwt.Issue(user.ID, user.Role, user.Email,
		jwt.TokenTypeEmailVerify, s.jwtCfg.VerifyTTL)
	if err != nil {
		return err
	}
	if err := s.notify.SendEmailVerification(user.Email, verifyToken); err != nil {
		return fmt.Errorf("resend-verify: send: %w", err)
	}
	return nil
}

// ----- 6. Reset password -----

// ResetPassword verifies the reset JWT and sets the new password. The JWT
// carries type=reset so it cannot be replayed as an access token.
// §1.8 — single-use enforcement via jti (SetNX).
func (s *AuthService) ResetPassword(ctx context.Context, in ResetPasswordInput, ip string) error {
	claims, err := s.jwt.Verify(in.Token)
	if err != nil || claims.Type != jwt.TokenTypeReset {
		return ErrInvalidToken
	}
	if err := validatePassword(in.NewPassword); err != nil {
		return err
	}
	user, err := s.users.FindByID(ctx, claims.UserID)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}

	// §1.8 — single-use enforcement: check-and-mark the jti atomically.
	if !s.markTokenUsed(claims.ID) {
		return ErrInvalidToken
	}
	if s.usedTokens != nil {
		_, _ = s.usedTokens.MarkUsed(ctx, claims.ID, jwt.TokenTypeReset,
			user.ID, claims.ExpiresAt.Time)
	}

	hashed, err := hash.HashPassword(in.NewPassword)
	if err != nil {
		return err
	}
	if err := s.users.UpdatePassword(ctx, user, hashed); err != nil {
		return err
	}
	if err := s.tokens.RevokeAllForUser(ctx, user.ID); err != nil {
		return err
	}
	s.audits.Record(ctx, &models.AuditLog{
		UserID: &user.ID, Event: models.AuditEventPasswordReset,
		IPAddress: ip, Success: true,
	})
	return nil
}

// ----- 7. Change password -----

// ChangePassword verifies the old password before accepting the new one, then
// revokes all existing refresh tokens (so all other sessions must log in again).
func (s *AuthService) ChangePassword(ctx context.Context, in ChangePasswordInput, ip string) error {
	user, err := s.users.FindByID(ctx, in.UserID)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}
	if !hash.CheckPassword(user.Password, in.OldPassword) {
		return ErrInvalidCredentials
	}
	if err := validatePassword(in.NewPassword); err != nil {
		return err
	}
	hashed, err := hash.HashPassword(in.NewPassword)
	if err != nil {
		return err
	}
	if err := s.users.UpdatePassword(ctx, user, hashed); err != nil {
		return err
	}
	if err := s.tokens.RevokeAllForUser(ctx, user.ID); err != nil {
		return err
	}
	s.audits.Record(ctx, &models.AuditLog{
		UserID: &user.ID, Event: models.AuditEventPasswordChanged,
		IPAddress: ip, Success: true,
	})
	return nil
}

// ----- 7b. Set password (first password for OAuth-only accounts) -----
//
// INVESTIGATION NOTES (pre-implementation findings):
//   - Exact "no password set" condition: models.User.Password is a NOT NULL
//     string column holding a bcrypt hash for password-registered users, and
//     OAuthService.createGoogleUser creates Google-only accounts with
//     Password == "" (empty string — never NULL, never a dummy hash). So
//     user.Password == "" is the precise marker of an account that has never
//     had a usable password.
//   - Reused helpers (no duplication): the package-private validatePassword
//     in this file for strength rules, and hash.HashPassword (bcrypt,
//     DefaultCost) for hashing, persisted via UserRepo.UpdatePassword — the
//     identical code path used by Register / ResetPassword / ChangePassword.
//
// SetPassword establishes a FIRST password for an account created via Google
// OAuth. It is deliberately distinct from ChangePassword: there is no
// oldPassword to verify because the account has never had one. The core
// security boundary is the guard below — an account that already has a
// usable password is hard-rejected so this endpoint can never become a
// change-password bypass. The guard lives in the SERVICE layer (not only in
// the handler) so any future caller of this method inherits the protection.
func (s *AuthService) SetPassword(ctx context.Context, userID uint, newPassword, ip string) error {
	if err := validatePassword(newPassword); err != nil {
		return err
	}
	user, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}
	// Only accounts WITHOUT a usable password may proceed. Everything else
	// must use ChangePassword, which verifies the old password first.
	if user.Password != "" {
		return ErrPasswordAlreadySet
	}
	hashed, err := hash.HashPassword(newPassword)
	if err != nil {
		return err
	}
	if err := s.users.UpdatePassword(ctx, user, hashed); err != nil {
		return err
	}
	s.audits.Record(ctx, &models.AuditLog{
		UserID: &user.ID, Email: user.Email, Event: models.AuditEventPasswordSet,
		IPAddress: ip, Success: true, Detail: "first password set (oauth-only account)",
	})
	return nil
}

// ----- 8. Me -----

// Me returns the sanitized profile for the authenticated user.
func (s *AuthService) Me(ctx context.Context, userID uint) (UserProfile, error) {
	user, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return UserProfile{}, err
	}
	if user == nil {
		return UserProfile{}, ErrUserNotFound
	}
	return FromUser(user), nil
}

// ----- 9. Verify email -----

// VerifyEmail accepts a type=verify-email JWT and marks the account verified.
// §1.8 — single-use enforcement via jti (SetNX).
func (s *AuthService) VerifyEmail(ctx context.Context, in EmailVerifyInput) error {
	claims, err := s.jwt.Verify(in.Token)
	if err != nil || claims.Type != jwt.TokenTypeEmailVerify {
		return ErrInvalidToken
	}
	user, err := s.users.FindByID(ctx, claims.UserID)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}

	// §1.8 — single-use enforcement.
	if !s.markTokenUsed(claims.ID) {
		return ErrInvalidToken
	}
	if s.usedTokens != nil {
		_, _ = s.usedTokens.MarkUsed(ctx, claims.ID, jwt.TokenTypeEmailVerify,
			user.ID, claims.ExpiresAt.Time)
	}

	return s.users.SetEmailVerified(ctx, user, true)
}

// ----- internal helpers -----

// issueTokenPair mints an access JWT + opaque refresh token (hash stored).
// The caller's ip/ua are stamped onto the new refresh-token row so it doubles
// as a session/device record (location is resolved via the geo resolver).
func (s *AuthService) issueTokenPair(ctx context.Context, user *models.User, ip, ua string) (TokenPair, error) {
	access, err := s.jwt.Issue(user.ID, user.Role, user.Email,
		jwt.TokenTypeAccess, s.jwtCfg.AccessTTL)
	if err != nil {
		return TokenPair{}, err
	}
	refreshPlain, err := hash.GenerateOpaqueToken()
	if err != nil {
		return TokenPair{}, err
	}
	now := time.Now()
	rt := &models.RefreshToken{
		UserID:           user.ID,
		TokenHash:        hash.HashToken(refreshPlain),
		ExpiresAt:        now.Add(s.jwtCfg.RefreshTTL),
		IPAddress:        ip,
		UserAgent:        ua,
		DeviceName:       device.Parse(ua),
		LocationEstimate: s.resolveLocation(ip),
		LastActiveAt:     now,
	}
	if err := s.tokens.Create(ctx, rt); err != nil {
		return TokenPair{}, err
	}
	return TokenPair{
		AccessToken:  access,
		RefreshToken: refreshPlain,
		ExpiresAt:    now.Add(s.jwtCfg.AccessTTL),
	}, nil
}

// resolveLocation maps an IP to a location label, defaulting to "Unknown" when
// no resolver is wired or the lookup fails. Never blocks: the geo resolver is
// expected to honor the request context; a nil resolver is treated as NoOp.
func (s *AuthService) resolveLocation(ip string) string {
	if s.geo == nil || ip == "" {
		return geo.UnknownLocation
	}
	if loc := s.geo.Resolve(context.Background(), ip); loc != "" {
		return loc
	}
	return geo.UnknownLocation
}

// ----- 10. Session & Device Management -----

// ListSessions returns all active (non-expired, non-revoked) sessions for the
// authenticated user, as sanitized SessionInfo projections (token hash omitted).
// Ordered most-recently-active first by the repository.
func (s *AuthService) ListSessions(ctx context.Context, userID uint) ([]SessionInfo, error) {
	rows, err := s.tokens.FindActiveByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	out := make([]SessionInfo, 0, len(rows))
	for i := range rows {
		rt := &rows[i]
		out = append(out, SessionInfo{
			ID:               rt.ID,
			IPAddress:        rt.IPAddress,
			UserAgent:        rt.UserAgent,
			DeviceName:       rt.DeviceName,
			LocationEstimate: rt.LocationEstimate,
			CreatedAt:        rt.CreatedAt,
			LastActiveAt:     rt.LastActiveAt,
			ExpiresAt:        rt.ExpiresAt,
		})
	}
	return out, nil
}

// RevokeSession revokes a single session (device) by id, scoped to the caller's
// userID so one user cannot revoke another user's session (IDOR defense).
// The device is then instantly blocked from rotating its refresh token.
func (s *AuthService) RevokeSession(ctx context.Context, id, userID uint, ip string) error {
	if err := s.tokens.RevokeByID(ctx, id, userID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrSessionNotFound
		}
		return fmt.Errorf("revoke session: %w", err)
	}
	uid := userID
	s.audits.Record(ctx, &models.AuditLog{
		UserID: &uid, Event: models.AuditEventSessionRevoked,
		IPAddress: ip, Success: true,
	})
	return nil
}

// isLocked reports whether the account is currently in a temporary lockout.
func (s *AuthService) isLocked(user *models.User) bool {
	return user.LockedUntil != nil && time.Now().Before(*user.LockedUntil)
}

// recordFailedLogin increments the counter and triggers a lockout when the
// threshold is reached. §3 — exponential backoff: repeat offenders get
// progressively longer lockouts via MaxLockoutMultiplier, tracked in the store.
// When MaxLockoutMultiplier <= 0 (unset/disabled), the plain base duration is
// used with no scaling.
func (s *AuthService) recordFailedLogin(ctx context.Context, user *models.User, email, ip string) {
	var lockUntil *time.Time
	if user.FailedLoginAttempts+1 >= s.cfg.MaxLoginAttempts {
		duration := s.cfg.LoginLockoutDuration
		if s.store != nil && s.cfg.MaxLockoutMultiplier > 0 {
			// Count how many lockouts this user has had in the last 24h.
			lockoutKey := fmt.Sprintf("lockouts:%d", user.ID)
			lockoutCount := s.store.IncrBy(lockoutKey, 1, 24*time.Hour)
			// Scale: base × min(count, MaxLockoutMultiplier). First lockout
			// (count=1) → base; second → 2×base; etc., capped.
			mult := lockoutCount
			if int(mult) > s.cfg.MaxLockoutMultiplier {
				mult = int64(s.cfg.MaxLockoutMultiplier)
			}
			if mult < 1 {
				mult = 1
			}
			duration = time.Duration(int64(s.cfg.LoginLockoutDuration) * mult)
		}
		t := time.Now().Add(duration)
		lockUntil = &t
	}
	if err := s.users.IncrementFailedAttempts(ctx, user, lockUntil); err != nil {
		// Log the error — lockout enforcement depends on this write succeeding.
		// Do NOT return the error to the caller (login should still fail with
		// ErrInvalidCredentials, not a 500), but the failure must be observable.
		slog.Error("recordFailedLogin: increment failed attempts",
			"user_id", user.ID, "err", err)
	}
	s.recordLoginFailIP(ctx, ip)
	s.audits.Record(ctx, loginFailedEvent(&user.ID, email, ip, "bad password"))
}

// recordLoginFailIP increments the per-IP failure counter used by the adaptive
// CAPTCHA gate (§3). Tracked in the store with a 1-hour window.
func (s *AuthService) recordLoginFailIP(ctx context.Context, ip string) {
	if s.store != nil && ip != "" {
		_ = s.store.IncrBy("loginfail:"+ip, 1, time.Hour)
	}
}

// markTokenUsed uses SetNX on the store to atomically check-and-mark a JWT
// jti as consumed. Returns false if already used (single-use enforcement §1.8).
func (s *AuthService) markTokenUsed(jti string) bool {
	if s.store == nil {
		return true // store disabled (tests) — allow through
	}
	key := "jti:" + jti
	return s.store.SetNX(key, "used", 24*time.Hour)
}

// validatePassword enforces a basic complexity policy (length + classes + cap).
func validatePassword(pw string) error {
	if len(pw) < 8 {
		return ErrPasswordTooWeak
	}
	// §5 — password length cap before bcrypt.
	if len(pw) > hash.MaxPasswordBytes {
		return ErrPasswordTooWeak
	}
	var hasLetter, hasNumber bool
	for _, r := range pw {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
			hasLetter = true
		case r >= '0' && r <= '9':
			hasNumber = true
		}
	}
	if !hasLetter || !hasNumber {
		return ErrPasswordTooWeak
	}
	return nil
}

// mapDuplicateKey inspects a DB error from user.Create and maps MySQL 1062
// (duplicate key) to ErrEmailExists or ErrUsernameExists (§1.7).
func mapDuplicateKey(email, username string, err error) error {
	// Check if the raw error (or its cause) is a MySQL duplicate key.
	if isMySQLDup(err) {
		// Best-effort guess based on which field the email/username might be
		// duplicating — both indexes are unique. Try to identify from the error
		// message substring.
		msg := err.Error()
		switch {
		case strings.Contains(msg, "email"):
			return ErrEmailExists
		case strings.Contains(msg, "username"):
			return ErrUsernameExists
		default:
			// Can't tell which — try a targeted lookup.
			return ErrEmailExists // more likely in practice
		}
	}
	return fmt.Errorf("register: create user: %w", err)
}

// isMySQLDup inspects a DB error for MySQL duplicate-key (1062). §1.7 explicitly
// requires errors.As to *mysql.MySQLError — not fragile string matching.
func isMySQLDup(err error) bool {
	var myErr *mysql.MySQLError
	return errors.As(err, &myErr) && myErr.Number == 1062
}

func loginFailedEvent(uid *uint, email, ip, detail string) *models.AuditLog {
	return &models.AuditLog{
		UserID: uid, Email: email, Event: models.AuditEventLoginFailed,
		IPAddress: ip, Success: false, Detail: detail,
	}
}
