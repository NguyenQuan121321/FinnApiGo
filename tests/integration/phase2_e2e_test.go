package integration_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/repositories"
	"github.com/finnapigo/finnapigo/internal/services"
	"github.com/finnapigo/finnapigo/internal/tenant"
)

func setupPhase2DB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:p2_test_%d?mode=memory&cache=shared", time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("failed to open in-memory sqlite: %v", err)
	}

	err = db.AutoMigrate(
		&models.Tenant{},
		&models.User{},
		&models.Session{},
		&models.AuditLog{},
		&models.Permission{},
		&models.Role{},
		&models.RolePermission{},
		&models.UserRole{},
		&models.TrustedDevice{},
		&models.WebhookEndpoint{},
		&models.WebhookDelivery{},
	)
	if err != nil {
		t.Fatalf("AutoMigrate failed: %v", err)
	}
	return db
}

func TestE2E_Phase2_MultiTenantIsolation(t *testing.T) {
	db := setupPhase2DB(t)
	userRepo := repositories.NewUserRepository(db)

	ctxTenantA := tenant.WithTenant(context.Background(), "org-apple")
	ctxTenantB := tenant.WithTenant(context.Background(), "org-banana")

	// 1. Create same username and email in two different tenants
	userA := &models.User{
		TenantID: "org-apple",
		Username: "admin",
		Email:    "admin@company.com",
		Password: "hash-apple-123",
		Role:     "admin",
		IsActive: true,
	}
	userB := &models.User{
		TenantID: "org-banana",
		Username: "admin",
		Email:    "admin@company.com",
		Password: "hash-banana-456",
		Role:     "admin",
		IsActive: true,
	}

	if err := userRepo.Create(ctxTenantA, userA); err != nil {
		t.Fatalf("failed to create user in Tenant A: %v", err)
	}
	if err := userRepo.Create(ctxTenantB, userB); err != nil {
		t.Fatalf("failed to create user in Tenant B (should coexist): %v", err)
	}

	// 2. Query by email in Tenant A -> gets Tenant A's user
	foundA, err := userRepo.FindByEmail(ctxTenantA, "admin@company.com")
	if err != nil || foundA == nil {
		t.Fatalf("FindByEmail Tenant A failed: %v", err)
	}
	if foundA.TenantID != "org-apple" || foundA.Password != "hash-apple-123" {
		t.Fatalf("expected Tenant A user, got: %+v", foundA)
	}

	// 3. Query by email in Tenant B -> gets Tenant B's user
	foundB, err := userRepo.FindByEmail(ctxTenantB, "admin@company.com")
	if err != nil || foundB == nil {
		t.Fatalf("FindByEmail Tenant B failed: %v", err)
	}
	if foundB.TenantID != "org-banana" || foundB.Password != "hash-banana-456" {
		t.Fatalf("expected Tenant B user, got: %+v", foundB)
	}
}

func TestE2E_Phase2_RBAC(t *testing.T) {
	db := setupPhase2DB(t)
	rbacRepo := repositories.NewRBACRepository(db)
	ctx := tenant.WithTenant(context.Background(), "corp-main")

	// 1. Insert permissions
	permRead := &models.Permission{Name: "users:read", Description: "View users"}
	permWrite := &models.Permission{Name: "users:write", Description: "Edit users"}
	db.Create(permRead)
	db.Create(permWrite)

	// 2. Create Role "Editor" with "users:read"
	editorRole := &models.Role{
		TenantID: "corp-main",
		Name:     "Editor",
	}
	if err := rbacRepo.CreateRole(ctx, editorRole, []string{"users:read"}); err != nil {
		t.Fatalf("CreateRole Editor failed: %v", err)
	}

	// 3. Assign role to user 77
	if err := rbacRepo.AssignRoleToUser(ctx, 77, editorRole.ID); err != nil {
		t.Fatalf("AssignRoleToUser failed: %v", err)
	}

	// 4. Verify permission checks
	hasRead, err := rbacRepo.UserHasPermission(ctx, 77, "users:read")
	if err != nil || !hasRead {
		t.Fatalf("expected users:read allowed, got: %v (err: %v)", hasRead, err)
	}

	hasWrite, err := rbacRepo.UserHasPermission(ctx, 77, "users:write")
	if err != nil || hasWrite {
		t.Fatalf("expected users:write denied, got: %v (err: %v)", hasWrite, err)
	}
}

func TestE2E_Phase2_AuditHashChainingAndTamperDetection(t *testing.T) {
	db := setupPhase2DB(t)
	secret := []byte("cryptographic-audit-ledger-test-key-32b")
	auditRepo := repositories.NewAuditRepository(db, repositories.WithAuditHMACKey(secret))
	ctx := tenant.WithTenant(context.Background(), "security-org")

	// 1. Record series of audit entries
	events := []string{"login", "password_changed", "totp_enabled", "session_revoked"}
	for _, ev := range events {
		auditRepo.Record(ctx, &models.AuditLog{
			TenantID:  "security-org",
			Event:     ev,
			IPAddress: "1.1.1.1",
			Success:   true,
			Detail:    "event " + ev,
		})
	}

	// 2. Verify audit chain validity
	valid, err := auditRepo.VerifyChain(ctx, "security-org")
	if err != nil || !valid {
		t.Fatalf("VerifyChain failed for untampered ledger: %v", err)
	}

	// 3. Tamper with the 2nd record directly in the database!
	var secondRecord models.AuditLog
	db.Where("tenant_id = ? AND event = ?", "security-org", "password_changed").First(&secondRecord)
	db.Model(&secondRecord).Update("detail", "TAMPERED_CONTENT_INJECTED")

	// 4. Chain verification MUST FAIL and detect the tamper!
	validTampered, err := auditRepo.VerifyChain(ctx, "security-org")
	if validTampered || err == nil {
		t.Fatal("VerifyChain must fail on tampered audit ledger")
	}
}

func TestE2E_Phase2_TrustedDeviceMFA(t *testing.T) {
	db := setupPhase2DB(t)
	tdRepo := repositories.NewTrustedDeviceRepository(db)
	tdSvc := services.NewTrustedDeviceService(tdRepo)
	ctx := context.Background()

	// 1. Issue trusted device token for user 101
	token, exp, err := tdSvc.Issue(ctx, 101, "Pixel 9 Pro", "10.0.0.99")
	if err != nil || token == "" {
		t.Fatalf("Issue failed: %v", err)
	}
	if exp.Before(time.Now().Add(29 * 24 * time.Hour)) {
		t.Fatalf("expected 30d expiry: %v", exp)
	}

	// 2. Validate token
	valid, err := tdSvc.Validate(ctx, 101, token)
	if err != nil || !valid {
		t.Fatalf("Validate failed: %v", err)
	}

	// 3. User lists devices
	devs, err := tdSvc.ListByUser(ctx, 101)
	if err != nil || len(devs) != 1 {
		t.Fatalf("ListByUser unexpected: %+v", devs)
	}

	// 4. User revokes device
	if err := tdSvc.Revoke(ctx, devs[0].ID, 101); err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}

	// 5. Revoked device cannot validate
	validRevoked, _ := tdSvc.Validate(ctx, 101, token)
	if validRevoked {
		t.Fatal("revoked device must be invalid")
	}
}
