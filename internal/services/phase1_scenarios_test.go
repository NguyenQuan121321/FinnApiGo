package services

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/finnapigo/finnapigo/internal/hash"
	"github.com/finnapigo/finnapigo/internal/models"
)

func TestPhase1_Scenarios_FullCoverage(t *testing.T) {
	ctx := context.Background()
	passkeyRepo := newMockPasskeyRepo()
	oauthRepo := newMockOAuthIdentityRepo()

	svc, users, _, audit, _ := newTestAuthService(
		WithMinPasswordScore(3),
		WithAuthPasskeys(passkeyRepo),
		WithAuthOAuthIdents(oauthRepo),
	)

	totpRepo := &mockTOTPRepo{devices: map[uint]*models.TOTPDevice{}}
	totpSvc := newTestTOTPService(t, totpRepo, newMockStore(), audit)
	totpSvc.passkeys = passkeyRepo
	totpSvc.users = users

	oauthSvc := NewOAuthService(
		users, oauthRepo, newMockStore(), svc, nil, nil,
		WithOAuthAudits(audit),
		WithOAuthPasskeys(passkeyRepo),
	)

	// Create user
	hashed, _ := hash.HashPassword("ComplexP@ssw0rd!2026", hash.MinCost)
	user := &models.User{
		Email:           "charlie@example.com",
		Username:        "charlie",
		Password:        hashed,
		FullName:        "Charlie Brown",
		Role:            models.RoleUser,
		IsActive:        true,
		IsEmailVerified: true,
	}
	_ = users.Create(ctx, user)

	// Add passkey
	_ = passkeyRepo.Create(ctx, &models.PasskeyCredential{
		UserID:       user.ID,
		CredentialID: []byte("passkey-id-1"),
		Revoked:      false,
	})

	// Add OAuth identity
	_ = oauthRepo.Create(ctx, &models.OAuthIdentity{
		UserID:         user.ID,
		Provider:       "google",
		ProviderUserID: "google-sub-charlie",
	})

	// Add audit logs
	audit.Record(ctx, &models.AuditLog{
		UserID:    &user.ID,
		Email:     user.Email,
		Event:     models.AuditEventLogin,
		IPAddress: "1.1.1.1",
		Success:   true,
	})

	// 1. Verify MFA methods aggregation
	mfaMethods, err := totpSvc.GetMFAMethods(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetMFAMethods failed: %v", err)
	}
	if mfaMethods.PasskeysCount != 1 || mfaMethods.DefaultMethod != "passkey" {
		t.Fatalf("expected 1 passkey with default=passkey, got %+v", mfaMethods)
	}

	// 2. Verify OAuth unlink with password succeeds
	err = oauthSvc.Unlink(ctx, user.ID, "google", "1.1.1.1")
	if err != nil {
		t.Fatalf("oauth unlink failed: %v", err)
	}
	ident, _ := oauthRepo.FindByUserIDAndProvider(ctx, user.ID, "google")
	if ident != nil {
		t.Fatal("expected google identity link removed")
	}

	// Re-link google identity
	_ = oauthRepo.Create(ctx, &models.OAuthIdentity{
		UserID:         user.ID,
		Provider:       "google",
		ProviderUserID: "google-sub-charlie",
	})

	// 3. Verify GDPR Right-to-Erasure (EraseAccount) purges ALL resources
	err = svc.EraseAccount(ctx, user.ID, "", "ComplexP@ssw0rd!2026", "access-jti-1", "1.1.1.1")
	if err != nil {
		t.Fatalf("EraseAccount failed: %v", err)
	}

	// Assert user scrambled
	erasedUser, _ := users.FindByID(ctx, user.ID)
	if !strings.HasPrefix(erasedUser.Email, "deleted_") || erasedUser.Password != "" || erasedUser.FullName != "" || erasedUser.IsActive {
		t.Fatalf("user profile not properly erased: %+v", erasedUser)
	}

	// Assert passkeys revoked
	pks, _ := passkeyRepo.ListByUser(ctx, user.ID, false)
	if len(pks) != 0 {
		t.Fatalf("expected 0 active passkeys, got %d", len(pks))
	}

	// Assert oauth identity purged
	relinked, _ := oauthRepo.FindByUserIDAndProvider(ctx, user.ID, "google")
	if relinked != nil {
		t.Fatal("expected oauth identities deleted")
	}

	// Assert audit log email anonymized
	userLogs, _, _ := audit.FindByUserIDPaginated(ctx, user.ID, 1, 10)
	for _, l := range userLogs {
		if l.Event == models.AuditEventLogin && l.Email != "anonymized@gdpr.local" {
			t.Fatalf("audit email not anonymized: got %s, want anonymized@gdpr.local", l.Email)
		}
	}
}

func TestPhase1_Scenarios_ChangeEmail_ReplayAndCollisionGuards(t *testing.T) {
	ctx := context.Background()
	svc, users, _, _, notify := newTestAuthService()

	hashed, _ := hash.HashPassword("StrongP@ssw0rd!1", hash.MinCost)
	u1 := &models.User{
		Email:           "bob@example.com",
		Username:        "bob",
		Password:        hashed,
		IsActive:        true,
		IsEmailVerified: true,
	}
	_ = users.Create(ctx, u1)

	hashed2, _ := hash.HashPassword("StrongP@ssw0rd!2", hash.MinCost)
	u2 := &models.User{
		Email:           "existing@example.com",
		Username:        "existing",
		Password:        hashed2,
		IsActive:        true,
		IsEmailVerified: true,
	}
	_ = users.Create(ctx, u2)

	// 1. Requesting with existing email is rejected
	err := svc.RequestChangeEmail(ctx, u1.ID, ChangeEmailRequestInput{
		Password: "StrongP@ssw0rd!1",
		NewEmail: "existing@example.com",
	}, "127.0.0.1")
	if !errors.Is(err, ErrEmailExists) {
		t.Fatalf("expected ErrEmailExists, got %v", err)
	}

	// 2. Requesting valid email succeeds and sends token
	err = svc.RequestChangeEmail(ctx, u1.ID, ChangeEmailRequestInput{
		Password: "StrongP@ssw0rd!1",
		NewEmail: "fresh@example.com",
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("RequestChangeEmail failed: %v", err)
	}
	token := notify.lastVerify
	if token == "" {
		t.Fatal("expected verification token sent")
	}

	// 3. Confirm email consumes token (single use)
	err = svc.ConfirmChangeEmail(ctx, token, "127.0.0.1")
	if err != nil {
		t.Fatalf("ConfirmChangeEmail failed: %v", err)
	}

	// 4. Replaying the same token fails (single use)
	err = svc.ConfirmChangeEmail(ctx, token, "127.0.0.1")
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken on token replay, got %v", err)
	}

	// 5. User email is updated
	updated, _ := users.FindByID(ctx, u1.ID)
	if updated.Email != "fresh@example.com" {
		t.Fatalf("expected fresh@example.com, got %s", updated.Email)
	}
}

func TestPhase1_Scenarios_PasswordStrengthScoring(t *testing.T) {
	ctx := context.Background()
	svc, users, _, _, _ := newTestAuthService(WithMinPasswordScore(3))

	u := &models.User{
		Email:           "david@example.com",
		Username:        "david",
		Password:        "",
		IsActive:        true,
		IsEmailVerified: true,
	}
	_ = users.Create(ctx, u)

	// 1. Password score < 3 is rejected
	err := svc.SetPassword(ctx, u.ID, "12345678", "127.0.0.1")
	if !errors.Is(err, ErrPasswordTooWeak) {
		t.Fatalf("expected ErrPasswordTooWeak for simple password, got %v", err)
	}

	// 2. Password containing username is rejected
	err = svc.SetPassword(ctx, u.ID, "david!StrongP@ss2026", "127.0.0.1")
	if !errors.Is(err, ErrPasswordTooWeak) {
		t.Fatalf("expected ErrPasswordTooWeak when containing username, got %v", err)
	}

	// 3. Strong password succeeds
	err = svc.SetPassword(ctx, u.ID, "Correct-Horse-Battery-Staple-99!", "127.0.0.1")
	if err != nil {
		t.Fatalf("expected success with strong password, got %v", err)
	}
}
