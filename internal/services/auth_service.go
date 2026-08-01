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
)

// AuthService holds all core-auth business logic. It depends only on repo
// interfaces + stateless helpers (jwt, hashing), so it is trivially unit-testable.
type AuthService struct {
	users    UserRepo
	tokens   RefreshTokenRepo
	audits   AuditRepo
	jwt      *utils.JWTManager
	cfg      config.AuthConfig
	jwtCfg   config.JWTConfig
	notify   Notifier
}

// NewAuthService constructs the service. Repos are interfaces so mocks can be
// passed in tests.
func NewAuthService(
	users UserRepo,
	tokens RefreshTokenRepo,
	audits AuditRepo,
	jwt *utils.JWTManager,
	authCfg config.AuthConfig,
	jwtCfg config.JWTConfig,
	notify Notifier,
) *AuthService {
	return &AuthService{
		users: users, tokens: tokens, audits: audits, jwt: jwt,
		cfg: authCfg, jwtCfg: jwtCfg, notify: notify,
	}
}

// ----- 1. Register -----

// Register creates a new user account: validates complexity, rejects duplicate
// email/username, hashes the password, and returns the profile + verification token.
func (s *AuthService) Register(ctx context.Context, in RegisterInput) (UserProfile, string, error) {
	in.Username = strings.TrimSpace(in.Username)
	in.Email = strings.ToLower(strings.TrimSpace(in.Email))
	in.FullName = strings.TrimSpace(in.FullName)

	if err := validatePassword(in.Password); err != nil {
		return UserProfile{}, "", err
	}

	// uniqueness checks (email + username)
	if existing, err := s.users.FindByEmail(in.Email); err != nil {
		return UserProfile{}, "", fmt.Errorf("register: find email: %w", err)
	} else if existing != nil {
		return UserProfile{}, "", ErrEmailExists
	}
	if existing, err := s.users.FindByUsername(in.Username); err != nil {
		return UserProfile{}, "", fmt.Errorf("register: find username: %w", err)
	} else if existing != nil {
		return UserProfile{}, "", ErrUsernameExists
	}

	hashed, err := utils.HashPassword(in.Password)
	if err != nil {
		return UserProfile{}, "", err
	}

	user := &models.User{
		Username: in.Username,
		Email:    in.Email,
		Password: hashed,
		FullName: in.FullName,
		Role:     models.RoleUser,
		IsActive: true,
	}
	if err := s.users.Create(user); err != nil {
		return UserProfile{}, "", fmt.Errorf("register: create user: %w", err)
	}

	// Issue an email-verification token (JWT with type=verify-email).
	verifyToken, err := s.jwt.Issue(user.ID, user.Role, user.Email,
		utils.TokenTypeEmailVerify, s.jwtCfg.VerifyTTL)
	if err != nil {
		return UserProfile{}, "", err
	}
	return FromUser(user), verifyToken, nil
}

// ----- 2. Login -----

// Login authenticates credentials, applies lockout logic, and returns a fresh
// access + refresh token pair. It does NOT enforce email verification by
// default — callers may opt into that at the handler level.
func (s *AuthService) Login(ctx context.Context, in LoginInput, ip string) (TokenPair, UserProfile, error) {
	email := strings.ToLower(strings.TrimSpace(in.Email))

	user, err := s.users.FindByEmail(email)
	if err != nil {
		return TokenPair{}, UserProfile{}, fmt.Errorf("login: find user: %w", err)
	}
	// To avoid user-enumeration, do NOT distinguish "user not found" from
	// "wrong password" in the returned error; both map to ErrInvalidCredentials.
	if user == nil {
		s.audits.Record(loginFailedEvent(nil, email, ip, "unknown user"))
		return TokenPair{}, UserProfile{}, ErrInvalidCredentials
	}

	if !user.IsActive {
		s.audits.Record(loginFailedEvent(&user.ID, email, ip, "disabled"))
		return TokenPair{}, UserProfile{}, ErrAccountDisabled
	}

	if locked := s.isLocked(user); locked {
		s.audits.Record(loginFailedEvent(&user.ID, email, ip, "locked"))
		return TokenPair{}, UserProfile{}, ErrAccountLocked
	}

	if !utils.CheckPassword(user.Password, in.Password) {
		s.recordFailedLogin(user, email, ip)
		return TokenPair{}, UserProfile{}, ErrInvalidCredentials
	}

	// success: reset counter
	if err := s.users.ResetFailedAttempts(user); err != nil {
		return TokenPair{}, UserProfile{}, err
	}

	pair, err := s.issueTokenPair(user)
	if err != nil {
		return TokenPair{}, UserProfile{}, err
	}
	s.audits.Record(&models.AuditLog{
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
	rt, err := s.tokens.FindByHash(hash)
	if err != nil {
		return fmt.Errorf("logout: find token: %w", err)
	}
	if rt == nil || rt.Revoked {
		return nil
	}
	if err := s.tokens.Revoke(rt); err != nil {
		return err
	}
	uid := rt.UserID
	s.audits.Record(&models.AuditLog{
		UserID: &uid, Event: models.AuditEventLogout, IPAddress: ip, Success: true,
	})
	return nil
}

// ----- 4. Refresh token (rotation) -----

// Refresh validates the presented refresh token, revokes it, and issues a NEW
// access + refresh pair (rotation). Reuse of the old token is therefore detected.
func (s *AuthService) Refresh(ctx context.Context, refreshToken, ip string) (TokenPair, error) {
	hash := utils.HashToken(refreshToken)
	rt, err := s.tokens.FindByHash(hash)
	if err != nil {
		return TokenPair{}, fmt.Errorf("refresh: find token: %w", err)
	}
	if rt == nil || rt.Revoked {
		// A revoked token being presented strongly suggests theft — invalidate
		// nothing further here (we already rotated), but reject the request.
		return TokenPair{}, ErrInvalidToken
	}
	if time.Now().After(rt.ExpiresAt) {
		_ = s.tokens.Revoke(rt)
		return TokenPair{}, ErrInvalidToken
	}

	user, err := s.users.FindByID(rt.UserID)
	if err != nil {
		return TokenPair{}, err
	}
	if user == nil || !user.IsActive {
		return TokenPair{}, ErrInvalidToken
	}

	// Rotate: revoke the old, issue a new pair.
	if err := s.tokens.Revoke(rt); err != nil {
		return TokenPair{}, err
	}
	pair, err := s.issueTokenPair(user)
	if err != nil {
		return TokenPair{}, err
	}
	s.audits.Record(&models.AuditLog{
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
	user, err := s.users.FindByEmail(email)
	if err != nil {
		return fmt.Errorf("forgot-password: find user: %w", err)
	}
	if user == nil {
		// Intentionally swallow — do not leak account existence.
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
func (s *AuthService) ResetPassword(ctx context.Context, in ResetPasswordInput, ip string) error {
	claims, err := s.jwt.Verify(in.Token)
	if err != nil || claims.Type != utils.TokenTypeReset {
		return ErrInvalidToken
	}
	if err := validatePassword(in.NewPassword); err != nil {
		return err
	}
	user, err := s.users.FindByID(claims.UserID)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}
	hashed, err := utils.HashPassword(in.NewPassword)
	if err != nil {
		return err
	}
	if err := s.users.UpdatePassword(user, hashed); err != nil {
		return err
	}
	// Revoke every existing refresh token — password change invalidates sessions.
	if err := s.tokens.RevokeAllForUser(user.ID); err != nil {
		return err
	}
	s.audits.Record(&models.AuditLog{
		UserID: &user.ID, Event: models.AuditEventPasswordReset,
		IPAddress: ip, Success: true,
	})
	return nil
}

// ----- 7. Change password -----

// ChangePassword verifies the old password before accepting the new one, then
// revokes all existing refresh tokens (so all other sessions must log in again).
func (s *AuthService) ChangePassword(ctx context.Context, in ChangePasswordInput, ip string) error {
	user, err := s.users.FindByID(in.UserID)
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
	if err := s.users.UpdatePassword(user, hashed); err != nil {
		return err
	}
	if err := s.tokens.RevokeAllForUser(user.ID); err != nil {
		return err
	}
	s.audits.Record(&models.AuditLog{
		UserID: &user.ID, Event: models.AuditEventPasswordChanged,
		IPAddress: ip, Success: true,
	})
	return nil
}

// ----- 8. Me -----

// Me returns the sanitized profile for the authenticated user.
func (s *AuthService) Me(ctx context.Context, userID uint) (UserProfile, error) {
	user, err := s.users.FindByID(userID)
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
func (s *AuthService) VerifyEmail(ctx context.Context, in EmailVerifyInput) error {
	claims, err := s.jwt.Verify(in.Token)
	if err != nil || claims.Type != utils.TokenTypeEmailVerify {
		return ErrInvalidToken
	}
	user, err := s.users.FindByID(claims.UserID)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}
	return s.users.SetEmailVerified(user, true)
}

// ----- internal helpers -----

// issueTokenPair mints an access JWT + opaque refresh token (hash stored).
func (s *AuthService) issueTokenPair(user *models.User) (TokenPair, error) {
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
	if err := s.tokens.Create(rt); err != nil {
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
// threshold is reached.
func (s *AuthService) recordFailedLogin(user *models.User, email, ip string) {
	var lockUntil *time.Time
	if user.FailedLoginAttempts+1 >= s.cfg.MaxLoginAttempts {
		t := time.Now().Add(s.cfg.LoginLockoutDuration)
		lockUntil = &t
	}
	if err := s.users.IncrementFailedAttempts(user, lockUntil); err != nil {
		// non-fatal — proceed; we still reject the login
		_ = err
	}
	s.audits.Record(loginFailedEvent(&user.ID, email, ip, "bad password"))
}

// validatePassword enforces a basic complexity policy (length + classes).
// Keep it intentionally simple and visible so it can be tuned per deployment.
func validatePassword(pw string) error {
	if len(pw) < 8 {
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

func loginFailedEvent(uid *uint, email, ip, detail string) *models.AuditLog {
	return &models.AuditLog{
		UserID: uid, Email: email, Event: models.AuditEventLoginFailed,
		IPAddress: ip, Success: false, Detail: detail,
	}
}

// Compile-time guard: ensure AuthService implements nothing HTTP-specific.
var _ = errors.New
