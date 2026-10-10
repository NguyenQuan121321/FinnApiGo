package services_test

import (
	"context"
	"errors"
	"testing"

	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/services"
	"github.com/finnapigo/finnapigo/internal/tenant"
)

type failingAdminSessions struct {
	services.AdminSessionRepo
	err error
}

func (r failingAdminSessions) RevokeAllForUser(context.Context, uint) error { return r.err }

type failingAdminTokens struct {
	services.RefreshTokenRepo
	err error
}

func (r failingAdminTokens) RevokeAllForUser(context.Context, uint) error { return r.err }

type failingAdminUsers struct {
	services.AdminUserRepo
	err error
}

func (r failingAdminUsers) BumpPwdVersion(context.Context, uint) error { return r.err }

func TestF01ForceLogoutReportsMutationFailures(t *testing.T) {
	ctx := tenant.WithTenant(context.Background(), "A")
	failure := errors.New("synthetic persistence failure")
	for _, stage := range []string{"tokens", "sessions", "version"} {
		t.Run(stage, func(t *testing.T) {
			u := newMockAdminUserRepo()
			u.users[2] = &models.User{ID: 2, TenantID: "A"}
			var users services.AdminUserRepo = u
			var sessions services.AdminSessionRepo = &mockAdminSessionRepo{}
			var tokens services.RefreshTokenRepo = &mockAdminTokenRepo{}
			switch stage {
			case "tokens":
				tokens = failingAdminTokens{tokens, failure}
			case "sessions":
				sessions = failingAdminSessions{sessions, failure}
			case "version":
				users = failingAdminUsers{users, failure}
			}
			audits := &mockAdminAuditRepo{}
			svc := services.NewAdminService(users, sessions, tokens, audits, nil)
			if err := svc.ForceLogout(ctx, 1, 2, "127.0.0.1"); !errors.Is(err, failure) {
				t.Fatalf("mutation failure concealed: %v", err)
			}
			if len(audits.logs) != 0 {
				t.Fatal("success audit recorded for failed mutation")
			}
		})
	}
}

func TestF01AdminServiceRejectsForeignRepositoryResult(t *testing.T) {
	ctx := tenant.WithTenant(context.Background(), "default")
	u := newMockAdminUserRepo() // Deliberately returns records without filtering.
	u.users[2] = &models.User{ID: 2, TenantID: "B"}
	svc := services.NewAdminService(u, nil, nil, nil, nil)
	for _, mutate := range []func() error{
		func() error { return svc.LockUser(ctx, 1, 2, 0, "127.0.0.1") },
		func() error { return svc.UnlockUser(ctx, 1, 2, "127.0.0.1") },
		func() error { return svc.ForceLogout(ctx, 1, 2, "127.0.0.1") },
	} {
		if err := mutate(); !errors.Is(err, services.ErrUserNotFound) {
			t.Fatalf("foreign adapter result accepted: %v", err)
		}
	}
	if len(u.lockedUntil) != 0 || len(u.pwdVersions) != 0 {
		t.Fatal("foreign mutation reached adapter")
	}
}
