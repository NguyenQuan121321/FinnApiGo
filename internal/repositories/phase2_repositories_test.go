package repositories

import (
	"context"
	"testing"
	"time"

	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/tenant"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func testPhase2DB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
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
		t.Fatal(err)
	}
	return db
}

func TestSessionRepository_AllMethods(t *testing.T) {
	ctx := tenant.WithTenant(context.Background(), "tenant-sess")
	db := testPhase2DB(t)
	repo := NewSessionRepository(db)

	sess := &models.Session{
		ID:           "sess-123",
		TenantID:     "tenant-sess",
		UserID:       10,
		IPAddress:    "127.0.0.1",
		UserAgent:    "Go-Test",
		DeviceName:   "TestDevice",
		ExpiresAt:    time.Now().Add(time.Hour),
		LastActiveAt: time.Now(),
	}

	// 1. Create
	if err := repo.Create(ctx, sess); err != nil {
		t.Fatalf("Create session failed: %v", err)
	}

	// 2. FindByID
	got, err := repo.FindByID(ctx, "sess-123")
	if err != nil || got == nil || got.ID != "sess-123" {
		t.Fatalf("FindByID failed: got=%v, err=%v", got, err)
	}

	// 3. FindActiveByUser
	userSessions, err := repo.FindActiveByUser(ctx, 10)
	if err != nil || len(userSessions) != 1 {
		t.Fatalf("FindActiveByUser failed: len=%d, err=%v", len(userSessions), err)
	}

	// 4. FindAllActiveByTenant
	tenantSessions, err := repo.FindAllActiveByTenant(ctx, "tenant-sess")
	if err != nil || len(tenantSessions) != 1 {
		t.Fatalf("FindAllActiveByTenant failed: len=%d, err=%v", len(tenantSessions), err)
	}

	// 5. Touch
	if err := repo.Touch(ctx, "sess-123", "127.0.0.2", "UA-New", "Device-New", "Location-New", time.Now()); err != nil {
		t.Fatalf("Touch failed: %v", err)
	}

	// 6. RevokeByID
	if err := repo.RevokeByID(ctx, "sess-123", 10); err != nil {
		t.Fatalf("RevokeByID failed: %v", err)
	}

	// 7. RevokeAllForUser
	sess2 := &models.Session{ID: "sess-456", TenantID: "tenant-sess", UserID: 10, ExpiresAt: time.Now().Add(time.Hour)}
	_ = repo.Create(ctx, sess2)
	if err := repo.RevokeAllForUser(ctx, 10); err != nil {
		t.Fatalf("RevokeAllForUser failed: %v", err)
	}

	// 8. RevokeAllForUserTx
	sess3 := &models.Session{ID: "sess-789", TenantID: "tenant-sess", UserID: 10, ExpiresAt: time.Now().Add(time.Hour)}
	_ = repo.Create(ctx, sess3)
	err = db.Transaction(func(tx *gorm.DB) error {
		return repo.RevokeAllForUserTx(tx, 10)
	})
	if err != nil {
		t.Fatalf("RevokeAllForUserTx failed: %v", err)
	}
}

func TestRBACRepository_AllMethods(t *testing.T) {
	ctx := context.Background()
	db := testPhase2DB(t)
	repo := NewRBACRepository(db)

	p1 := &models.Permission{Name: "users:read", Description: "Read users"}
	p2 := &models.Permission{Name: "users:write", Description: "Write users"}
	_ = db.Create(p1).Error
	_ = db.Create(p2).Error

	// 1. ListPermissions
	perms, err := repo.ListPermissions(ctx)
	if err != nil || len(perms) < 2 {
		t.Fatalf("ListPermissions failed: %v", err)
	}

	// 2. CreateRole
	role := &models.Role{
		TenantID:    "tenant-rbac",
		Name:        "admin",
		Description: "Admin role",
	}
	if err := repo.CreateRole(ctx, role, []string{"users:read", "users:write"}); err != nil {
		t.Fatalf("CreateRole failed: %v", err)
	}

	// 3. AssignRoleToUser
	if err := repo.AssignRoleToUser(ctx, 42, role.ID); err != nil {
		t.Fatalf("AssignRoleToUser failed: %v", err)
	}

	// 4. GetUserPermissions
	userPerms, err := repo.GetUserPermissions(ctx, 42)
	if err != nil || len(userPerms) != 2 {
		t.Fatalf("GetUserPermissions failed: got=%v, err=%v", userPerms, err)
	}

	// 5. UserHasPermission
	has, err := repo.UserHasPermission(ctx, 42, "users:read")
	if err != nil || !has {
		t.Fatalf("UserHasPermission expected true, got=%v, err=%v", has, err)
	}
	hasNot, err := repo.UserHasPermission(ctx, 42, "non:existent")
	if err != nil || hasNot {
		t.Fatalf("UserHasPermission expected false, got=%v, err=%v", hasNot, err)
	}
}

func TestTrustedDeviceRepository_AllMethods(t *testing.T) {
	ctx := context.Background()
	db := testPhase2DB(t)
	repo := NewTrustedDeviceRepository(db)

	now := time.Now()
	d := &models.TrustedDevice{
		DeviceHash: "hash-device-1",
		UserID:     55,
		DeviceName: "MacBook",
		IPAddress:  "1.1.1.1",
		ExpiresAt:  time.Now().Add(30 * 24 * time.Hour),
		LastUsedAt: &now,
		Revoked:    false,
	}

	// 1. Create
	if err := repo.Create(ctx, d); err != nil {
		t.Fatalf("Create trusted device failed: %v", err)
	}

	// 2. FindByDeviceHash
	got, err := repo.FindByDeviceHash(ctx, "hash-device-1")
	if err != nil || got == nil || got.DeviceHash != "hash-device-1" {
		t.Fatalf("FindByDeviceHash failed: %v", err)
	}

	// 3. TouchUsage
	if err := repo.TouchUsage(ctx, d.ID, time.Now()); err != nil {
		t.Fatalf("TouchUsage failed: %v", err)
	}

	// 4. ListByUser
	devices, err := repo.ListByUser(ctx, 55)
	if err != nil || len(devices) != 1 {
		t.Fatalf("ListByUser failed: %v", err)
	}

	// 5. Revoke
	if err := repo.Revoke(ctx, d.ID, 55); err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}
	revokedDevice, err := repo.FindByDeviceHash(ctx, "hash-device-1")
	if err != nil || revokedDevice != nil {
		t.Fatalf("expected nil device for revoked hash, got %v, err=%v", revokedDevice, err)
	}
}

func TestWebhookRepository_AllMethods(t *testing.T) {
	ctx := context.Background()
	db := testPhase2DB(t)
	repo := NewWebhookRepository(db)

	ep := &models.WebhookEndpoint{
		ID:       "ep-1",
		TenantID: "tenant-hook",
		URL:      "https://example.com/webhook",
		Secret:   "sec-123",
		Events:   "user.created,user.locked",
		IsActive: true,
	}

	// 1. CreateEndpoint
	if err := repo.CreateEndpoint(ctx, ep); err != nil {
		t.Fatalf("CreateEndpoint failed: %v", err)
	}

	// 2. FindActiveEndpointsByEvent
	eps, err := repo.FindActiveEndpointsByEvent(ctx, "tenant-hook", "user.created")
	if err != nil || len(eps) != 1 {
		t.Fatalf("FindActiveEndpointsByEvent failed: len=%d, err=%v", len(eps), err)
	}

	// 3. CreateDelivery
	delivery := &models.WebhookDelivery{
		ID:         "del-1",
		EndpointID: ep.ID,
		Event:      "user.created",
		Payload:    `{"userId":1}`,
		Status:     "pending",
		Attempts:   0,
	}
	if err := repo.CreateDelivery(ctx, delivery); err != nil {
		t.Fatalf("CreateDelivery failed: %v", err)
	}

	// 4. GetPendingDeliveries
	pending, err := repo.GetPendingDeliveries(ctx, 10)
	if err != nil || len(pending) != 1 {
		t.Fatalf("GetPendingDeliveries failed: len=%d, err=%v", len(pending), err)
	}

	// 5. UpdateDeliveryStatus
	code := 200
	if err := repo.UpdateDeliveryStatus(ctx, delivery.ID, "delivered", 1, nil, &code, ""); err != nil {
		t.Fatalf("UpdateDeliveryStatus failed: %v", err)
	}
}

func TestUserRepository_ListPaginatedAndSetLock(t *testing.T) {
	ctx := tenant.WithTenant(context.Background(), "tenant-users")
	db := testPhase2DB(t)
	repo := NewUserRepository(db)

	u := &models.User{
		TenantID: "tenant-users",
		Username: "bob",
		Email:    "bob@users.org",
		FullName: "Bob User",
		Role:     models.RoleUser,
		IsActive: true,
	}
	_ = repo.Create(ctx, u)

	// ListPaginated
	users, total, err := repo.ListPaginated(ctx, "tenant-users", 1, 10, "bob")
	if err != nil || total != 1 || len(users) != 1 {
		t.Fatalf("ListPaginated failed: total=%d, err=%v", total, err)
	}

	// SetLock
	lockTime := time.Now().Add(time.Hour)
	if err := repo.SetLock(ctx, u.ID, &lockTime); err != nil {
		t.Fatalf("SetLock failed: %v", err)
	}
}

func TestAuditRepository_VerifyChainAndStreaming(t *testing.T) {
	ctx := tenant.WithTenant(context.Background(), "tenant-audit")
	db := testPhase2DB(t)
	repo := NewAuditRepository(db, WithAuditHMACKey([]byte("test-audit-hmac-key-32-chars!")))

	uID := uint(1)
	repo.Record(ctx, &models.AuditLog{
		TenantID: "tenant-audit",
		UserID:   &uID,
		Email:    "test@audit.org",
		Event:    models.AuditEventLogin,
		Success:  true,
		Detail:   "first login",
	})
	repo.Record(ctx, &models.AuditLog{
		TenantID: "tenant-audit",
		UserID:   &uID,
		Email:    "test@audit.org",
		Event:    models.AuditEventPasswordChanged,
		Success:  true,
		Detail:   "password updated",
	})

	// 1. VerifyChain valid
	valid, err := repo.VerifyChain(ctx, "tenant-audit")
	if err != nil || !valid {
		t.Fatalf("VerifyChain failed: valid=%v, err=%v", valid, err)
	}

	// 2. FindAllPaginated
	items, total, err := repo.FindAllPaginated(ctx, "tenant-audit", 1, 10)
	if err != nil || total != 2 || len(items) != 2 {
		t.Fatalf("FindAllPaginated failed: total=%d, len=%d, err=%v", total, len(items), err)
	}

	// 3. StreamAll
	streamItems, err := repo.StreamAll(ctx, "tenant-audit")
	if err != nil || len(streamItems) != 2 {
		t.Fatalf("StreamAll failed: len=%d, err=%v", len(streamItems), err)
	}
}
