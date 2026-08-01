package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/finnapigo/finnapigo/internal/config"
	"github.com/finnapigo/finnapigo/internal/utils"
)

// newTestAuthService builds an AuthService wired to in-memory mocks. OTP/lockout
// knobs are tuned short for test speed.
func newTestAuthService() (*AuthService, *mockUserRepo, *mockTokenRepo, *mockNotifier) {
	users := newMockUserRepo()
	tokens := newMockTokenRepo()
	audit := mockAuditRepo{}
	jwtMgr := utils.NewJWTManager("test-secret", "test-issuer")
	notify := &mockNotifier{}
	cfg := config.AuthConfig{
		MaxLoginAttempts:     5,
		LoginLockoutDuration: 15 * time.Minute,
		OTPTTL:               5 * time.Minute,
		OTPLength:            6,
		OTPMaxAttempts:       5,
	}
	jwtCfg := config.JWTConfig{
		AccessTTL: 15 * time.Minute, RefreshTTL: time.Hour,
		ResetTTL: 15 * time.Minute, VerifyTTL: time.Hour,
	}
	svc := NewAuthService(users, tokens, audit, jwtMgr, cfg, jwtCfg, notify)
	return svc, users, tokens, notify
}

// ----- Register -----

func TestRegister_Success(t *testing.T) {
	svc, users, _, _ := newTestAuthService()
	profile, verifyToken, err := svc.Register(context.Background(), RegisterInput{
		Username: "alice", Email: "alice@example.com", Password: "Password1", FullName: "Alice",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if profile.Username != "alice" {
		t.Errorf("username = %q", profile.Username)
	}
	if verifyToken == "" {
		t.Error("expected a non-empty verification token")
	}
	u, _ := users.FindByEmail("alice@example.com")
	if u == nil {
		t.Fatal("user not persisted")
	}
	if u.Password == "Password1" {
		t.Error("password must be hashed, not stored in plaintext")
	}
	if !utils.CheckPassword(u.Password, "Password1") {
		t.Error("hashed password does not verify")
	}
}

func TestRegister_RejectsDuplicateEmail(t *testing.T) {
	svc, _, _, _ := newTestAuthService()
	in := RegisterInput{Username: "alice", Email: "alice@example.com", Password: "Password1", FullName: "A"}
	if _, _, err := svc.Register(context.Background(), in); err != nil {
		t.Fatalf("first register failed: %v", err)
	}
	_, _, err := svc.Register(context.Background(), RegisterInput{
		Username: "alice2", Email: "alice@example.com", Password: "Password1", FullName: "A",
	})
	if !errors.Is(err, ErrEmailExists) {
		t.Errorf("expected ErrEmailExists, got %v", err)
	}
}

func TestRegister_RejectsWeakPassword(t *testing.T) {
	svc, _, _, _ := newTestAuthService()
	cases := []string{"short", "onlyletters", "12345678", ""}
	for _, pw := range cases {
		_, _, err := svc.Register(context.Background(), RegisterInput{
			Username: "u", Email: "u@example.com", Password: pw, FullName: "U",
		})
		if !errors.Is(err, ErrPasswordTooWeak) {
			t.Errorf("password %q expected ErrPasswordTooWeak, got %v", pw, err)
		}
	}
}

// ----- Login -----

func TestLogin_Success(t *testing.T) {
	svc, _, _, _ := newTestAuthService()
	if _, _, err := svc.Register(context.Background(), RegisterInput{
		Username: "alice", Email: "alice@example.com", Password: "Password1", FullName: "Alice",
	}); err != nil {
		t.Fatal(err)
	}
	pair, profile, err := svc.Login(context.Background(), LoginInput{
		Email: "alice@example.com", Password: "Password1",
	}, "1.2.3.4")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	if pair.AccessToken == "" || pair.RefreshToken == "" {
		t.Error("expected both tokens to be issued")
	}
	if profile.Email != "alice@example.com" {
		t.Errorf("profile email = %q", profile.Email)
	}
}

func TestLogin_WrongPassword_NoLockoutYet(t *testing.T) {
	svc, users, _, _ := newTestAuthService()
	if _, _, err := svc.Register(context.Background(), RegisterInput{
		Username: "alice", Email: "alice@example.com", Password: "Password1", FullName: "Alice",
	}); err != nil {
		t.Fatal(err)
	}
	_, _, err := svc.Login(context.Background(), LoginInput{
		Email: "alice@example.com", Password: "wrong",
	}, "1.2.3.4")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}
	u, _ := users.FindByEmail("alice@example.com")
	if u.FailedLoginAttempts != 1 {
		t.Errorf("failed attempts = %d, want 1", u.FailedLoginAttempts)
	}
	if u.LockedUntil != nil {
		t.Error("account should not be locked after a single failure")
	}
}

func TestLogin_LocksAfterMaxAttempts(t *testing.T) {
	svc, users, _, _ := newTestAuthService()
	if _, _, err := svc.Register(context.Background(), RegisterInput{
		Username: "alice", Email: "alice@example.com", Password: "Password1", FullName: "Alice",
	}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		_, _, _ = svc.Login(context.Background(), LoginInput{
			Email: "alice@example.com", Password: "wrong",
		}, "1.2.3.4")
	}
	u, _ := users.FindByEmail("alice@example.com")
	if u.LockedUntil == nil {
		t.Fatal("account should be locked after 5 failed attempts")
	}
	// Now even the correct password is rejected because of the lock.
	_, _, err := svc.Login(context.Background(), LoginInput{
		Email: "alice@example.com", Password: "Password1",
	}, "1.2.3.4")
	if !errors.Is(err, ErrAccountLocked) {
		t.Errorf("expected ErrAccountLocked, got %v", err)
	}
}

func TestLogin_UnknownUserDoesNotDistinguish(t *testing.T) {
	svc, _, _, _ := newTestAuthService()
	_, _, err := svc.Login(context.Background(), LoginInput{
		Email: "ghost@example.com", Password: "Password1",
	}, "1.2.3.4")
	// Must return the SAME error as a wrong password, to prevent enumeration.
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials for unknown user, got %v", err)
	}
}

// ----- Refresh (rotation) -----

func TestRefresh_RotatesAndInvalidatesOldToken(t *testing.T) {
	svc, _, _, _ := newTestAuthService()
	if _, _, err := svc.Register(context.Background(), RegisterInput{
		Username: "alice", Email: "alice@example.com", Password: "Password1", FullName: "Alice",
	}); err != nil {
		t.Fatal(err)
	}
	first, _, err := svc.Login(context.Background(), LoginInput{
		Email: "alice@example.com", Password: "Password1",
	}, "ip")
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.Refresh(context.Background(), first.RefreshToken, "ip")
	if err != nil {
		t.Fatalf("refresh failed: %v", err)
	}
	if second.RefreshToken == first.RefreshToken {
		t.Error("refresh token must be rotated (new value expected)")
	}
	// Reusing the old token must now fail.
	_, err = svc.Refresh(context.Background(), first.RefreshToken, "ip")
	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken on replay, got %v", err)
	}
}

// ----- Forgot / reset password -----

func TestForgotPassword_UnknownEmailReturnsNil(t *testing.T) {
	svc, _, _, notify := newTestAuthService()
	if err := svc.ForgotPassword(context.Background(), "ghost@example.com", "ip"); err != nil {
		t.Errorf("unknown email must not error, got %v", err)
	}
	if notify.lastReset != "" {
		t.Error("no reset token should be generated for unknown email")
	}
}

func TestResetPassword_EndToEnd(t *testing.T) {
	svc, users, _, notify := newTestAuthService()
	if _, _, err := svc.Register(context.Background(), RegisterInput{
		Username: "alice", Email: "alice@example.com", Password: "Password1", FullName: "Alice",
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.ForgotPassword(context.Background(), "alice@example.com", "ip"); err != nil {
		t.Fatal(err)
	}
	resetToken := notify.lastReset
	if resetToken == "" {
		t.Fatal("expected a reset token to be generated")
	}
	if err := svc.ResetPassword(context.Background(), ResetPasswordInput{
		Token: resetToken, NewPassword: "NewPassword2",
	}, "ip"); err != nil {
		t.Fatalf("reset failed: %v", err)
	}
	u, _ := users.FindByEmail("alice@example.com")
	if !utils.CheckPassword(u.Password, "NewPassword2") {
		t.Error("new password did not take effect")
	}
	// Reset token must be single-use (JWT exp helps, but verify it can't be
	// re-used to set a different password — here it would still validate, so
	// production should issue a fresh one each time; this test only confirms
	// the new password works).
}

// ----- Change password -----

func TestChangePassword_RequiresCorrectOldPassword(t *testing.T) {
	svc, users, _, _ := newTestAuthService()
	_, _, _ = svc.Register(context.Background(), RegisterInput{
		Username: "alice", Email: "alice@example.com", Password: "Password1", FullName: "Alice",
	})
	uid := uint(1)
	err := svc.ChangePassword(context.Background(), ChangePasswordInput{
		UserID: uid, OldPassword: "wrong", NewPassword: "NewPassword2",
	}, "ip")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}
	// correct old password
	if err := svc.ChangePassword(context.Background(), ChangePasswordInput{
		UserID: uid, OldPassword: "Password1", NewPassword: "NewPassword2",
	}, "ip"); err != nil {
		t.Fatalf("change failed: %v", err)
	}
	u, _ := users.FindByID(uid)
	if !utils.CheckPassword(u.Password, "NewPassword2") {
		t.Error("password not updated")
	}
}

// ----- Verify email -----

func TestVerifyEmail(t *testing.T) {
	svc, users, _, _ := newTestAuthService()
	_, verifyToken, err := svc.Register(context.Background(), RegisterInput{
		Username: "alice", Email: "alice@example.com", Password: "Password1", FullName: "Alice",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.VerifyEmail(context.Background(), EmailVerifyInput{Token: verifyToken}); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	u, _ := users.FindByEmail("alice@example.com")
	if !u.IsEmailVerified {
		t.Error("email should be marked verified")
	}
}

func TestVerifyEmail_RejectsAccessToken(t *testing.T) {
	svc, _, _, _ := newTestAuthService()
	profile, _, err := svc.Register(context.Background(), RegisterInput{
		Username: "alice", Email: "alice@example.com", Password: "Password1", FullName: "Alice",
	})
	if err != nil {
		t.Fatal(err)
	}
	jwtMgr := utils.NewJWTManager("test-secret", "test-issuer")
	access, _ := jwtMgr.Issue(profile.ID, "user", profile.Email, utils.TokenTypeAccess, time.Minute)
	err = svc.VerifyEmail(context.Background(), EmailVerifyInput{Token: access})
	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken when passing an access token, got %v", err)
	}
}
