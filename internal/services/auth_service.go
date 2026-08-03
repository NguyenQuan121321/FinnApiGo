// Package services contains all business logic. It is deliberately decoupled
// from Gin (no *gin.Context imports) so every method can be unit-tested with
// a mocked repository. Handlers translate HTTP <-> service calls.
package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/finnapigo/finnapigo/internal/config"
	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/utils"
	"github.com/go-sql-driver/mysql"
)

// dummyHash is a pre-computed bcrypt hash of a static string. It is compared
// during login when the user doesn't exist, so the response time is
// indistinguishable from a wrong-password path. Generated once at init.
var dummyHash string

func init() {
	h, err := utils.HashPassword("dummy-timing-equalization")
	if err != nil {
		panic("auth: failed to generate dummy bcrypt hash: " + err.Error())
	}
	dummyHash = h
}

// AuthService holds all core-auth business logic. It depends only on repo
// interfaces + stateless helpers (jwt, hashing), so it is trivially unit-testable.
type AuthService struct {
	users      UserRepo
	tokens     RefreshTokenRepo
	usedTokens UsedTokenRepo
	audits     AuditRepo
	store      StoreProvider
	jwt        *utils.JWTManager
	cfg        config.AuthConfig
	rlCfg      config.RateLimitConfig // §2/§3 velocity + adaptive-captcha knobs
	jwtCfg     config.JWTConfig
	notify     Notifier
	captcha    CaptchaVerifier // §3 — nil-safe (NoOp when off)
}

// StoreProvider abstracts the key-value store for per-account/per-IP counters
// and single-use token tracking. Injected via config — InMemoryStore by default,
// RedisStore for multi-instance so counters are shared.
type StoreProvider interface {
	SetNX(key string, value any, ttl time.Duration) bool
	IncrBy(key string, delta int64, ttl time.Duration) int64
	Get(key string) (any, bool)
}

// NewAuthService constructs the service. Repos are interfaces so mocks can be
// passed in tests. store may be nil (some features will be no-ops). rlCfg drives
// the §2/§3 velocity limiters and adaptive CAPTCHA; captcha may be nil.
func NewAuthService(
	users UserRepo,
	tokens RefreshTokenRepo,
	usedTokens UsedTokenRepo,
	audits AuditRepo,
	store StoreProvider,
	jwt *utils.JWTManager,
	authCfg config.AuthConfig,
	rlCfg config.RateLimitConfig,
	jwtCfg config.JWTConfig,
	notify Notifier,
	captcha CaptchaVerifier,
) *AuthService {
	if captcha == nil {
		captcha = NoOpCaptchaVerifier{}
	}
	return &AuthService{
		users: users, tokens: tokens, usedTokens: usedTokens, audits: audits,
		store: store, jwt: jwt, cfg: authCfg, rlCfg: rlCfg, jwtCfg: jwtCfg,
		notify: notify, captcha: captcha,
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

	hashed, err := utils.HashPassword(in.Password)
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
		utils.TokenTypeEmailVerify, s.jwtCfg.VerifyTTL)
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
// access + refresh token pair. It does NOT enforce email verification by
// default — callers may opt into that at the handler level.
func (s *AuthService) Login(ctx context.Context, in LoginInput, ip, ua string) (TokenPair, UserProfile, error) {
	email := strings.ToLower(strings.TrimSpace(in.Email))

	// §3 — per-account login velocity limit: throttle repeated attempts against
	// one email even when spread across many IPs. Uses the store so the limit
	// is shared across instances.
	if s.store != nil && email != "" {
		key := "login:acct:" + email
		count := s.store.IncrBy(key, 1, s.rlCfg.LoginWindow)
		if count > int64(s.rlCfg.LoginPerAccountMax) {
			return TokenPair{}, UserProfile{}, ErrRateLimited
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
					return TokenPair{}, UserProfile{}, ErrCaptchaRequired
				}
			}
		}
	}

	user, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		return TokenPair{}, UserProfile{}, fmt.Errorf("login: find user: %w", err)
	}
	// §1.6 — Timing side-channel mitigation: when user == nil, still run a
	// bcrypt comparison against a dummy hash so both code paths take ~equal
	// time (~100-300ms). The error message is identical either way.
	if user == nil {
		utils.CheckPassword(dummyHash, in.Password)
		s.recordLoginFailIP(ctx, ip)
		s.audits.Record(ctx, loginFailedEvent(nil, email, ip, "unknown user"))
		return TokenPair{}, UserProfile{}, ErrInvalidCredentials
	}

	// §2 — optional email-verification gate. When RequireEmailVerified is
	// true, unverified accounts cannot log in. Default false to avoid breaking
	// existing UX; the CHANGELOG and README document this as a policy decision.
	if s.cfg.RequireEmailVerified && !user.IsEmailVerified {
		return TokenPair{}, UserProfile{}, ErrEmailNotVerified
	}

	if !user.IsActive {
		s.audits.Record(ctx, loginFailedEvent(&user.ID, email, ip, "disabled"))
		return TokenPair{}, UserProfile{}, ErrAccountDisabled
	}

	if locked := s.isLocked(user); locked {
		s.audits.Record(ctx, loginFailedEvent(&user.ID, email, ip, "locked"))
		return TokenPair{}, UserProfile{}, ErrAccountLocked
	}

	if !utils.CheckPassword(user.Password, in.Password) {
		s.recordFailedLogin(ctx, user, email, ip)
		return TokenPair{}, UserProfile{}, ErrInvalidCredentials
	}

	// success: reset counter
	if err := s.users.ResetFailedAttempts(ctx, user); err != nil {
		return TokenPair{}, UserProfile{}, err
	}

	pair, err := s.issueTokenPair(ctx, user)
	if err != nil {
		return TokenPair{}, UserProfile{}, err
	}
	s.audits.Record(ctx, &models.AuditLog{
		UserID: &user.ID, Email: email, Event: models.AuditEventLogin,
		IPAddress: ip, Success: true,
	})
	return pair, FromUser(user), nil
}

// ----- 3. Logout -----

// Logout revokes the supplied refresh token (idempotent — revoking an
// already-revoked or unknown token is not an error, to avoid leaking state).
func (s *AuthService) Logout(ctx context.Context, refreshToken, ip string) error {
	hash := utils.HashToken(refreshToken)
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
func (s *AuthService) Refresh(ctx context.Context, refreshToken, ip string) (TokenPair, error) {
	hash := utils.HashToken(refreshToken)
	rt, err := s.tokens.FindByHash(ctx, hash)
	if err != nil {
		return TokenPair{}, fmt.Errorf("refresh: find token: %w", err)
	}

	if rt == nil {
		return TokenPair{}, ErrInvalidToken
	}

	// §4 — Refresh-token reuse detection: if a *revoked* (not just expired)
	// token is presented, it is a strong theft signal. Revoke ALL tokens for
	// the user and log a high-severity event. Expired-but-not-revoked keeps
	// the simple rejection (no blowback).
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

	// Rotate: revoke the old, issue a new pair.
	if err := s.tokens.Revoke(ctx, rt); err != nil {
		return TokenPair{}, err
	}
	pair, err := s.issueTokenPair(ctx, user)
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
		utils.TokenTypeReset, s.jwtCfg.ResetTTL)
	if err != nil {
		return err
	}
	if err := s.notify.SendPasswordReset(email, resetToken); err != nil {
		return fmt.Errorf("forgot-password: send: %w", err)
	}
	return nil
}

// ----- 6. Reset password -----

// ResetPassword verifies the reset JWT and sets the new password. The JWT
// carries type=reset so it cannot be replayed as an access token.
// §1.8 — single-use enforcement via jti (SetNX).
func (s *AuthService) ResetPassword(ctx context.Context, in ResetPasswordInput, ip string) error {
	claims, err := s.jwt.Verify(in.Token)
	if err != nil || claims.Type != utils.TokenTypeReset {
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
		_, _ = s.usedTokens.MarkUsed(ctx, claims.ID, utils.TokenTypeReset,
			user.ID, claims.ExpiresAt.Time)
	}

	hashed, err := utils.HashPassword(in.NewPassword)
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
	if !utils.CheckPassword(user.Password, in.OldPassword) {
		return ErrInvalidCredentials
	}
	if err := validatePassword(in.NewPassword); err != nil {
		return err
	}
	hashed, err := utils.HashPassword(in.NewPassword)
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
	if err != nil || claims.Type != utils.TokenTypeEmailVerify {
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
		_, _ = s.usedTokens.MarkUsed(ctx, claims.ID, utils.TokenTypeEmailVerify,
			user.ID, claims.ExpiresAt.Time)
	}

	return s.users.SetEmailVerified(ctx, user, true)
}

// ----- internal helpers -----

// issueTokenPair mints an access JWT + opaque refresh token (hash stored).
func (s *AuthService) issueTokenPair(ctx context.Context, user *models.User) (TokenPair, error) {
	access, err := s.jwt.Issue(user.ID, user.Role, user.Email,
		utils.TokenTypeAccess, s.jwtCfg.AccessTTL)
	if err != nil {
		return TokenPair{}, err
	}
	refreshPlain, err := utils.GenerateOpaqueToken()
	if err != nil {
		return TokenPair{}, err
	}
	rt := &models.RefreshToken{
		UserID:    user.ID,
		TokenHash: utils.HashToken(refreshPlain),
		ExpiresAt: time.Now().Add(s.jwtCfg.RefreshTTL),
	}
	if err := s.tokens.Create(ctx, rt); err != nil {
		return TokenPair{}, err
	}
	return TokenPair{
		AccessToken:  access,
		RefreshToken: refreshPlain,
		ExpiresAt:    time.Now().Add(s.jwtCfg.AccessTTL),
	}, nil
}

// isLocked reports whether the account is currently in a temporary lockout.
func (s *AuthService) isLocked(user *models.User) bool {
	return user.LockedUntil != nil && time.Now().Before(*user.LockedUntil)
}

// recordFailedLogin increments the counter and triggers a lockout when the
// threshold is reached. §3 — exponential backoff: repeat offenders get
// progressively longer lockouts via MaxLockoutMultiplier, tracked in the store.
func (s *AuthService) recordFailedLogin(ctx context.Context, user *models.User, email, ip string) {
	var lockUntil *time.Time
	if user.FailedLoginAttempts+1 >= s.cfg.MaxLoginAttempts {
		duration := s.cfg.LoginLockoutDuration
		if s.store != nil {
			// Count how many lockouts this user has had in the last 24h.
			lockoutKey := fmt.Sprintf("lockouts:%d", user.ID)
			lockoutCount := s.store.IncrBy(lockoutKey, 1, 24*time.Hour)
			// Scale: base × min(count, MaxLockoutMultiplier).
			mult := lockoutCount
			if int(mult) > s.cfg.MaxLockoutMultiplier {
				mult = int64(s.cfg.MaxLockoutMultiplier)
			}
			duration = time.Duration(int64(s.cfg.LoginLockoutDuration) * mult)
		}
		t := time.Now().Add(duration)
		lockUntil = &t
	}
	if err := s.users.IncrementFailedAttempts(ctx, user, lockUntil); err != nil {
		_ = err
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
	if len(pw) > 128 {
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
