package repositories

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/tenant"
)

func fullTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{TranslateError: true})
	if err != nil {
		t.Fatal(err)
	}
	err = db.AutoMigrate(
		&models.User{},
		&models.RefreshToken{},
		&models.AuditLog{},
		&models.UsedToken{},
		&models.OAuthIdentity{},
		&models.PasskeyCredential{},
		&models.TOTPDevice{},
		&models.RecoveryCode{},
		&models.Session{},
		&models.TrustedDevice{},
		&models.WebhookEndpoint{},
		&models.Role{},
		&models.Permission{},
		&models.UserRole{},
		&models.RolePermission{},
	)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func TestTOTPRepository_CompleteCoverage(t *testing.T) {
	ctx := context.Background()
	db := fullTestDB(t)
	u := testUser(t, db)
	repo := NewTOTPRepository(db)

	// 1. FindByUserID missing
	dev, err := repo.FindByUserID(ctx, u.ID)
	if err != nil || dev != nil {
		t.Fatalf("expected nil device, got dev=%v err=%v", dev, err)
	}

	// 2. Create device via Upsert
	dev = &models.TOTPDevice{
		UserID:                 u.ID,
		SecretEncrypted:        "secret",
		PendingSecretEncrypted: "pending",
		Enabled:                true,
	}
	if err := repo.Upsert(ctx, dev); err != nil {
		t.Fatal(err)
	}

	// 3. FindByUserID found
	got, err := repo.FindByUserID(ctx, u.ID)
	if err != nil || got == nil || got.UserID != u.ID {
		t.Fatalf("expected found device, got %+v, err=%v", got, err)
	}

	// 4. ReplaceRecoveryCodes
	codes := []*models.RecoveryCode{
		{UserID: u.ID, CodeHash: "hash1", CodeEncrypted: "enc1"},
		{UserID: u.ID, CodeHash: "hash2", CodeEncrypted: "enc2"},
	}
	if err := repo.ReplaceRecoveryCodes(ctx, u.ID, codes); err != nil {
		t.Fatal(err)
	}

	// 5. ActiveRecoveryCodes
	active, err := repo.ActiveRecoveryCodes(ctx, u.ID)
	if err != nil || len(active) != 2 {
		t.Fatalf("expected 2 active codes, got %d, err=%v", len(active), err)
	}

	// 6. Disable
	if err := repo.Disable(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	gotDisabled, err := repo.FindByUserID(ctx, u.ID)
	if err != nil || gotDisabled.Enabled {
		t.Fatalf("expected device to be disabled, got %+v", gotDisabled)
	}
}

func TestUserRepository_CompleteCoverage(t *testing.T) {
	ctx := context.Background()
	db := fullTestDB(t)
	u := testUser(t, db)
	repo := NewUserRepository(db)

	// 1. Update
	u.FullName = "Alice Smith"
	if err := repo.Update(ctx, u); err != nil {
		t.Fatal(err)
	}
	updated, err := repo.FindByID(ctx, u.ID)
	if err != nil || updated.FullName != "Alice Smith" {
		t.Fatalf("Update failed: got %+v", updated)
	}

	// 2. BumpPwdVersion
	if err := repo.BumpPwdVersion(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	v, err := repo.FindByID(ctx, u.ID)
	if err != nil || v.PwdVersion != 1 {
		t.Fatalf("BumpPwdVersion failed: got %d", v.PwdVersion)
	}

	// 3. CredentialChangeTx
	if err := repo.CredentialChangeTx(ctx, u.ID, "newhash", func(tx *gorm.DB) error { return nil }); err != nil {
		t.Fatal(err)
	}
	u2, err := repo.FindByID(ctx, u.ID)
	if err != nil || u2.Password != "newhash" || u2.PwdVersion != 2 {
		t.Fatalf("CredentialChangeTx failed: got %+v", u2)
	}

	// 4. SetFirstPassword
	oauthUser := &models.User{Username: "oauthuser", Email: "oauth@ex.com", Password: "", Role: models.RoleUser, IsActive: true}
	_ = db.Create(oauthUser).Error
	ok, err := repo.SetFirstPassword(ctx, oauthUser.ID, "firsthash")
	if err != nil || !ok {
		t.Fatalf("SetFirstPassword failed: ok=%v, err=%v", ok, err)
	}

	// 5. ListPaginated
	users, total, err := repo.ListPaginated(ctx, "default", 1, 10, "alice")
	if err != nil || total == 0 || len(users) == 0 {
		t.Fatalf("ListPaginated failed: total=%d, users=%v, err=%v", total, users, err)
	}

	// 6. SetLock & Unlock
	lockUntil := time.Now().Add(time.Hour)
	if err := repo.SetLock(ctx, u.ID, &lockUntil); err != nil {
		t.Fatal(err)
	}
	locked, _ := repo.FindByID(ctx, u.ID)
	if locked.LockedUntil == nil {
		t.Fatal("expected LockedUntil to be set")
	}

	if err := repo.SetLock(ctx, u.ID, nil); err != nil {
		t.Fatal(err)
	}
	unlocked, _ := repo.FindByID(ctx, u.ID)
	if unlocked.LockedUntil != nil {
		t.Fatal("expected LockedUntil to be nil")
	}
}

func TestOAuthRepository_DeleteAll(t *testing.T) {
	ctx := context.Background()
	db := fullTestDB(t)
	u := testUser(t, db)
	repo := NewOAuthIdentityRepository(db)

	ident1 := &models.OAuthIdentity{UserID: u.ID, Provider: "google", ProviderUserID: "g-1"}
	ident2 := &models.OAuthIdentity{UserID: u.ID, Provider: "github", ProviderUserID: "gh-1"}
	_ = repo.Create(ctx, ident1)
	_ = repo.Create(ctx, ident2)

	// Delete by user and provider
	if err := repo.DeleteByUserIDAndProvider(ctx, u.ID, "google"); err != nil {
		t.Fatal(err)
	}

	// Delete all by user
	if err := repo.DeleteAllByUserID(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
}

func TestPasskeyRepository_RevokeAll(t *testing.T) {
	ctx := context.Background()
	db := fullTestDB(t)
	u := testUser(t, db)
	repo := NewPasskeyRepository(db)

	cred := &models.PasskeyCredential{
		UserID:       u.ID,
		CredentialID: []byte("cred-1"),
		PublicKey:    []byte("pub-1"),
		DisplayName:  "TestKey",
	}
	_ = repo.Create(ctx, cred)

	if err := repo.RevokeAllForUser(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	creds, _ := repo.ListByUser(ctx, u.ID, false)
	if len(creds) != 0 {
		t.Fatalf("expected 0 creds, got %d", len(creds))
	}
}

func TestRefreshTokenRepository_RevokeBySessionAndTx(t *testing.T) {
	ctx := context.Background()
	db := fullTestDB(t)
	u := testUser(t, db)
	repo := NewRefreshTokenRepository(db)

	tok := &models.RefreshToken{
		UserID:    u.ID,
		TokenHash: "hash-tok",
		SessionID: "sess-1",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	_ = repo.Create(ctx, tok)

	if err := repo.RevokeBySession(ctx, "sess-1"); err != nil {
		t.Fatal(err)
	}

	// RevokeAllForUserTx
	_ = db.Transaction(func(tx *gorm.DB) error {
		return repo.RevokeAllForUserTx(tx, u.ID)
	})
}

func TestAuditLogRepository_PaginatedAndAnonymize(t *testing.T) {
	ctx := context.Background()
	db := fullTestDB(t)
	u := testUser(t, db)
	repo := NewAuditRepository(db)

	repo.Record(ctx, &models.AuditLog{
		UserID:    &u.ID,
		TenantID:  "default",
		Email:     u.Email,
		Event:     models.AuditEventLogin,
		IPAddress: "1.2.3.4",
		Success:   true,
	})

	logs, total, err := repo.FindByUserIDPaginated(ctx, u.ID, 1, 10)
	if err != nil || total == 0 || len(logs) == 0 {
		t.Fatalf("FindByUserIDPaginated failed: total=%d, logs=%v, err=%v", total, logs, err)
	}

	if err := repo.AnonymizeUser(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
}

func TestErrorsClassification(t *testing.T) {
	if isGormDuplicate(gorm.ErrDuplicatedKey) != true {
		t.Error("isGormDuplicate(gorm.ErrDuplicatedKey) must be true")
	}
	if isGormDuplicate(errors.New("other")) != false {
		t.Error("isGormDuplicate(other) must be false")
	}
	if isMySQLDuplicate(errors.New("other")) != false {
		t.Error("isMySQLDuplicate(other) must be false")
	}
}

func TestRepositories_NotFoundAndEdgeBranches(t *testing.T) {
	ctx := context.Background()
	db := fullTestDB(t)
	userRepo := NewUserRepository(db)
	oauthRepo := NewOAuthIdentityRepository(db)
	sessionRepo := NewSessionRepository(db)
	auditRepo := NewAuditRepository(db)
	usedTokenRepo := NewUsedTokenRepository(db)
	totpRepo := NewTOTPRepository(db)
	rbacRepo := NewRBACRepository(db)

	u := testUser(t, db)

	// 1. UserRepository FindByEmail & FindByUsername missing
	if user, err := userRepo.FindByEmail(ctx, "missing@example.com"); err != nil || user != nil {
		t.Fatalf("expected nil user for missing email, got %v, %v", user, err)
	}
	if user, err := userRepo.FindByUsername(ctx, "missing_user"); err != nil || user != nil {
		t.Fatalf("expected nil user for missing username, got %v, %v", user, err)
	}

	// 2. SetFirstPassword on user with existing password (must return false, nil)
	ok, err := userRepo.SetFirstPassword(ctx, u.ID, "anotherhash")
	if err != nil || ok {
		t.Fatalf("SetFirstPassword on user with existing password must return false, got ok=%v, err=%v", ok, err)
	}

	// 3. OAuth FindByUserIDAndProvider (found & missing)
	ident := &models.OAuthIdentity{UserID: u.ID, Provider: "apple", ProviderUserID: "apple-sub"}
	_ = oauthRepo.Create(ctx, ident)
	if got, err := oauthRepo.FindByUserIDAndProvider(ctx, u.ID, "apple"); err != nil || got == nil {
		t.Fatalf("FindByUserIDAndProvider found failed: got %v, err %v", got, err)
	}
	if got, err := oauthRepo.FindByUserIDAndProvider(ctx, u.ID, "missing-provider"); err != nil || got != nil {
		t.Fatalf("FindByUserIDAndProvider missing failed: got %v, err %v", got, err)
	}

	// 4. SessionRepository FindByID (missing) and FindActiveByUser
	if s, err := sessionRepo.FindByID(ctx, "missing-session"); err != nil || s != nil {
		t.Fatalf("FindByID missing session failed: got %v, err %v", s, err)
	}

	// 5. ReplaceRecoveryCodes with empty slice
	if err := totpRepo.ReplaceRecoveryCodes(ctx, u.ID, nil); err != nil {
		t.Fatalf("ReplaceRecoveryCodes with nil slice failed: %v", err)
	}

	// 6. AuditRepository BatchInsert
	entries := []*models.AuditLog{
		{TenantID: "default", Email: "batch1@ex.com", Event: models.AuditEventLogin, Success: true},
		{TenantID: "default", Email: "batch2@ex.com", Event: models.AuditEventLogin, Success: true},
	}
	if inserted := auditRepo.BatchInsert(ctx, entries); inserted != 2 {
		t.Fatalf("BatchInsert failed: inserted=%d", inserted)
	}

	// 7. UsedTokenRepository IsUsed (false then true)
	if used, err := usedTokenRepo.IsUsed(ctx, "jti-test"); err != nil || used {
		t.Fatalf("expected unused token, got %v, %v", used, err)
	}
	if _, err := usedTokenRepo.MarkUsed(ctx, "jti-test", "access", u.ID, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("MarkUsed failed: %v", err)
	}
	if used, err := usedTokenRepo.IsUsed(ctx, "jti-test"); err != nil || !used {
		t.Fatalf("expected used token, got %v, %v", used, err)
	}

	// 8. RBACRepository UserHasPermission
	perm := &models.Permission{Name: "posts:edit"}
	_ = db.Create(perm).Error
	role := &models.Role{TenantID: "default", Name: "editor"}
	_ = rbacRepo.CreateRole(ctx, role, []string{"posts:edit"})
	_ = rbacRepo.AssignRoleToUser(ctx, u.ID, role.ID)

	hasPerm, err := rbacRepo.UserHasPermission(ctx, u.ID, "posts:edit")
	if err != nil || !hasPerm {
		t.Fatalf("UserHasPermission failed: got %v, %v", hasPerm, err)
	}
	hasNoPerm, err := rbacRepo.UserHasPermission(ctx, u.ID, "nonexistent:perm")
	if err != nil || hasNoPerm {
		t.Fatalf("expected false for nonexistent perm, got %v, %v", hasNoPerm, err)
	}
}

func TestAuditRepository_Advanced(t *testing.T) {
	ctx := context.Background()
	db := fullTestDB(t)
	customKey := []byte("custom-secret-key-for-test-32bytes!")
	repo := NewAuditRepository(db, WithAuditHMACKey(customKey))

	// 1. VerifyChain on empty tenant
	ok, err := repo.VerifyChain(ctx, "empty-tenant")
	if err != nil || !ok {
		t.Fatalf("VerifyChain on empty tenant failed: ok=%v, err=%v", ok, err)
	}

	// 2. Record 2 entries with custom key
	tCtx := tenant.WithTenant(ctx, "tenant-audit")
	u := testUser(t, db)
	repo.Record(tCtx, &models.AuditLog{
		UserID:  &u.ID,
		Email:   u.Email,
		Event:   models.AuditEventLogin,
		Success: true,
		Detail:  "first",
	})
	repo.Record(tCtx, &models.AuditLog{
		UserID:  &u.ID,
		Email:   u.Email,
		Event:   models.AuditEventPasswordChanged,
		Success: true,
		Detail:  "second",
	})

	// 3. VerifyChain on tenant-audit (should pass)
	ok, err = repo.VerifyChain(tCtx, "")
	if err != nil || !ok {
		t.Fatalf("VerifyChain on valid chain failed: ok=%v, err=%v", ok, err)
	}

	// 4. FindAllPaginated (with and without explicit tenant)
	logs, total, err := repo.FindAllPaginated(tCtx, "", 1, 10)
	if err != nil || total != 2 || len(logs) != 2 {
		t.Fatalf("FindAllPaginated tenant from context failed: total=%d, len=%d, err=%v", total, len(logs), err)
	}
	logs, total, err = repo.FindAllPaginated(ctx, "tenant-audit", 0, 0)
	if err != nil || total != 2 || len(logs) != 2 {
		t.Fatalf("FindAllPaginated default pagination failed: total=%d, len=%d, err=%v", total, len(logs), err)
	}

	// 5. StreamAll (with and without explicit tenant)
	all, err := repo.StreamAll(tCtx, "")
	if err != nil || len(all) != 2 {
		t.Fatalf("StreamAll from context failed: len=%d, err=%v", len(all), err)
	}
	all, err = repo.StreamAll(ctx, "tenant-audit")
	if err != nil || len(all) != 2 {
		t.Fatalf("StreamAll explicit tenant failed: len=%d, err=%v", len(all), err)
	}

	// 6. PurgeOlderThan
	purged, err := repo.PurgeOlderThan(ctx, time.Now().Add(-time.Hour))
	if err != nil || purged != 0 {
		t.Fatalf("PurgeOlderThan unexpected: purged=%d, err=%v", purged, err)
	}

	// 7. Tamper with record to trigger VerifyChain failure
	db.Model(&models.AuditLog{}).Where("id = ?", all[0].ID).Update("prev_hash", "tampered-prev-hash")
	ok, err = repo.VerifyChain(tCtx, "tenant-audit")
	if ok || err == nil {
		t.Fatalf("expected VerifyChain to fail on tampered prev_hash, got ok=%v, err=%v", ok, err)
	}

	// Reset prev_hash and tamper record_hash
	db.Model(&models.AuditLog{}).Where("id = ?", all[0].ID).Updates(map[string]any{
		"prev_hash":   all[0].PrevHash,
		"record_hash": "bad-record-hash",
	})
	ok, err = repo.VerifyChain(tCtx, "tenant-audit")
	if ok || err == nil {
		t.Fatalf("expected VerifyChain to fail on tampered record_hash, got ok=%v, err=%v", ok, err)
	}
}

func TestBatchedDelete_MultiBatch(t *testing.T) {
	ctx := context.Background()
	db := fullTestDB(t)
	oldBatch := purgeBatchSize
	purgeBatchSize = 2
	defer func() { purgeBatchSize = oldBatch }()

	usedTokenRepo := NewUsedTokenRepository(db)
	exp := time.Now().Add(-time.Hour)
	for i := 0; i < 5; i++ {
		db.Create(&models.UsedToken{
			JTI:       fmt.Sprintf("jti-batch-%d", i),
			TokenType: "access",
			UserID:    1,
			ExpiresAt: exp,
		})
	}

	purged, err := usedTokenRepo.PurgeExpired(ctx, time.Now())
	if err != nil || purged != 5 {
		t.Fatalf("PurgeExpired multi-batch failed: purged=%d, err=%v", purged, err)
	}
}

func TestUsedTokenRepository_DuplicateMarkUsed(t *testing.T) {
	ctx := context.Background()
	db := fullTestDB(t)
	repo := NewUsedTokenRepository(db)

	ok1, err1 := repo.MarkUsed(ctx, "dup-jti", "access", 1, time.Now().Add(time.Hour))
	if err1 != nil || !ok1 {
		t.Fatalf("first MarkUsed failed: ok=%v, err=%v", ok1, err1)
	}

	// Second call with same JTI should hit isGormDuplicate and return false, nil
	ok2, err2 := repo.MarkUsed(ctx, "dup-jti", "access", 1, time.Now().Add(time.Hour))
	if err2 != nil || ok2 {
		t.Fatalf("second MarkUsed should return (false, nil), got ok=%v, err=%v", ok2, err2)
	}
}

func TestTOTPRepository_RecoveryCodeUsedTwice(t *testing.T) {
	ctx := context.Background()
	db := fullTestDB(t)
	repo := NewTOTPRepository(db)
	u := testUser(t, db)

	codes := []*models.RecoveryCode{
		{UserID: u.ID, CodeHash: "hash-cas", CodeEncrypted: "enc-cas"},
	}
	if err := repo.ReplaceRecoveryCodes(ctx, u.ID, codes); err != nil {
		t.Fatal(err)
	}

	active, err := repo.ActiveRecoveryCodes(ctx, u.ID)
	if err != nil || len(active) != 1 {
		t.Fatalf("expected 1 active code, got %d, err=%v", len(active), err)
	}

	// First mark used: success
	if err := repo.MarkRecoveryCodeUsed(ctx, &active[0]); err != nil {
		t.Fatalf("first MarkRecoveryCodeUsed failed: %v", err)
	}

	// Second mark used: should fail with ErrRecoveryCodeUsed
	if err := repo.MarkRecoveryCodeUsed(ctx, &active[0]); !errors.Is(err, ErrRecoveryCodeUsed) {
		t.Fatalf("expected ErrRecoveryCodeUsed, got %v", err)
	}
}

func TestSessionRepository_RevokeAndFindTenant(t *testing.T) {
	ctx := context.Background()
	db := fullTestDB(t)
	repo := NewSessionRepository(db)
	u := testUser(t, db)

	tCtx := tenant.WithTenant(ctx, "sess-tenant")
	sess := &models.Session{
		ID:           "s-123",
		UserID:       u.ID,
		ExpiresAt:    time.Now().Add(time.Hour),
		LastActiveAt: time.Now(),
		Revoked:      false,
	}
	if err := repo.Create(tCtx, sess); err != nil {
		t.Fatal(err)
	}

	// FindByID
	found, err := repo.FindByID(ctx, "s-123")
	if err != nil || found == nil || found.TenantID != "sess-tenant" {
		t.Fatalf("FindByID failed: found=%v, err=%v", found, err)
	}

	// FindActiveByUser
	active, err := repo.FindActiveByUser(ctx, u.ID)
	if err != nil || len(active) != 1 {
		t.Fatalf("FindActiveByUser failed: len=%d, err=%v", len(active), err)
	}

	// FindAllActiveByTenant (from context and explicit)
	tenantActive, err := repo.FindAllActiveByTenant(tCtx, "")
	if err != nil || len(tenantActive) != 1 {
		t.Fatalf("FindAllActiveByTenant from context failed: len=%d, err=%v", len(tenantActive), err)
	}
	tenantActive, err = repo.FindAllActiveByTenant(ctx, "sess-tenant")
	if err != nil || len(tenantActive) != 1 {
		t.Fatalf("FindAllActiveByTenant explicit failed: len=%d, err=%v", len(tenantActive), err)
	}

	// Touch
	if err := repo.Touch(ctx, "s-123", "1.1.1.1", "curl", "desktop", "US", time.Now()); err != nil {
		t.Fatal(err)
	}

	// RevokeByID matching
	if err := repo.RevokeByID(ctx, "s-123", u.ID); err != nil {
		t.Fatalf("RevokeByID failed: %v", err)
	}

	// RevokeByID non-matching -> ErrRecordNotFound
	if err := repo.RevokeByID(ctx, "nonexistent", u.ID); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("expected ErrRecordNotFound, got %v", err)
	}

	// RevokeAllForUser
	if err := repo.RevokeAllForUser(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
}

func TestRefreshTokenRepository_AllBranches(t *testing.T) {
	ctx := context.Background()
	db := fullTestDB(t)
	repo := NewRefreshTokenRepository(db)
	u := testUser(t, db)

	// FindByHash missing
	if rt, err := repo.FindByHash(ctx, "missing-hash"); err != nil || rt != nil {
		t.Fatalf("FindByHash missing failed: got %v, err=%v", rt, err)
	}

	// Create and FindByHash found
	rt := &models.RefreshToken{
		UserID:       u.ID,
		TokenHash:    "tok-hash-1",
		SessionID:    "s-hash-1",
		ExpiresAt:    time.Now().Add(time.Hour),
		LastActiveAt: time.Now(),
		Revoked:      false,
	}
	if err := repo.Create(ctx, rt); err != nil {
		t.Fatal(err)
	}
	got, err := repo.FindByHash(ctx, "tok-hash-1")
	if err != nil || got == nil {
		t.Fatalf("FindByHash found failed: %v, %v", got, err)
	}

	// FindActiveByUser
	active, err := repo.FindActiveByUser(ctx, u.ID)
	if err != nil || len(active) != 1 {
		t.Fatalf("FindActiveByUser failed: len=%d, err=%v", len(active), err)
	}

	// RevokeByID missing
	if err := repo.RevokeByID(ctx, 999999, u.ID); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("expected ErrRecordNotFound, got %v", err)
	}

	// RevokeByID found
	if err := repo.RevokeByID(ctx, got.ID, u.ID); err != nil {
		t.Fatalf("RevokeByID found failed: %v", err)
	}

	// Create another for CAS Revoke
	rt2 := &models.RefreshToken{
		UserID:       u.ID,
		TokenHash:    "tok-hash-2",
		SessionID:    "s-hash-2",
		ExpiresAt:    time.Now().Add(time.Hour),
		LastActiveAt: time.Now(),
		Revoked:      false,
	}
	_ = repo.Create(ctx, rt2)

	// CAS Revoke first time: success
	if err := repo.Revoke(ctx, rt2); err != nil {
		t.Fatalf("first Revoke failed: %v", err)
	}
	// CAS Revoke second time: returns ErrTokenAlreadyRevoked
	if err := repo.Revoke(ctx, rt2); !errors.Is(err, ErrTokenAlreadyRevoked) {
		t.Fatalf("expected ErrTokenAlreadyRevoked, got %v", err)
	}

	// PurgeExpired
	purged, err := repo.PurgeExpired(ctx, time.Now().Add(2*time.Hour))
	if err != nil || purged == 0 {
		t.Fatalf("PurgeExpired failed: purged=%d, err=%v", purged, err)
	}
}

func TestPasskeyRepository_AllBranches(t *testing.T) {
	ctx := context.Background()
	db := fullTestDB(t)
	repo := NewPasskeyRepository(db)
	u := testUser(t, db)

	// FindByCredentialID missing
	if cred, err := repo.FindByCredentialID(ctx, []byte("missing-cred")); err != nil || cred != nil {
		t.Fatalf("FindByCredentialID missing failed: got %v, err=%v", cred, err)
	}

	cred := &models.PasskeyCredential{
		UserID:       u.ID,
		CredentialID: []byte("cred-branch-1"),
		PublicKey:    []byte("pub-key-1"),
		DisplayName:  "YubiKey",
	}
	if err := repo.Create(ctx, cred); err != nil {
		t.Fatal(err)
	}

	// FindByCredentialID found
	found, err := repo.FindByCredentialID(ctx, []byte("cred-branch-1"))
	if err != nil || found == nil {
		t.Fatalf("FindByCredentialID found failed: got %v, err=%v", found, err)
	}

	// TouchUsage
	if err := repo.TouchUsage(ctx, found.ID, 42, time.Now()); err != nil {
		t.Fatal(err)
	}

	// RevokeByID missing
	if err := repo.RevokeByID(ctx, 999999, u.ID); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("expected ErrRecordNotFound, got %v", err)
	}

	// RevokeByID found
	if err := repo.RevokeByID(ctx, found.ID, u.ID); err != nil {
		t.Fatalf("RevokeByID found failed: %v", err)
	}
}

func TestTrustedDeviceRepository_AllBranches(t *testing.T) {
	ctx := context.Background()
	db := fullTestDB(t)
	repo := NewTrustedDeviceRepository(db)
	u := testUser(t, db)

	// FindByDeviceHash missing
	if dev, err := repo.FindByDeviceHash(ctx, "nonexistent-hash"); err != nil || dev != nil {
		t.Fatalf("FindByDeviceHash missing failed: got %v, err=%v", dev, err)
	}

	dev := &models.TrustedDevice{
		UserID:     u.ID,
		DeviceHash: "dev-hash-1",
		DeviceName: "MacBook Pro",
		ExpiresAt:  time.Now().Add(time.Hour),
	}
	if err := repo.Create(ctx, dev); err != nil {
		t.Fatal(err)
	}

	found, err := repo.FindByDeviceHash(ctx, "dev-hash-1")
	if err != nil || found == nil {
		t.Fatalf("FindByDeviceHash found failed: got %v, err=%v", found, err)
	}

	if err := repo.TouchUsage(ctx, found.ID, time.Now()); err != nil {
		t.Fatal(err)
	}

	list, err := repo.ListByUser(ctx, u.ID)
	if err != nil || len(list) != 1 {
		t.Fatalf("ListByUser failed: len=%d, err=%v", len(list), err)
	}

	// Revoke found
	if err := repo.Revoke(ctx, found.ID, u.ID); err != nil {
		t.Fatalf("Revoke found failed: %v", err)
	}

	// Revoke missing
	if err := repo.Revoke(ctx, 999999, u.ID); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("expected ErrRecordNotFound, got %v", err)
	}
}

func TestWebhookRepository_AllBranches(t *testing.T) {
	ctx := context.Background()
	db := fullTestDB(t)
	_ = db.AutoMigrate(&models.WebhookDelivery{})
	repo := NewWebhookRepository(db)

	tCtx := tenant.WithTenant(ctx, "webhook-tenant")
	ep1 := &models.WebhookEndpoint{
		ID:       "ep-1",
		URL:      "https://example.com/wh1",
		Secret:   "secret-1",
		Events:   "user.login, user.logout",
		IsActive: true,
	}
	if err := repo.CreateEndpoint(tCtx, ep1); err != nil {
		t.Fatal(err)
	}

	epWildcard := &models.WebhookEndpoint{
		ID:       "ep-2",
		URL:      "https://example.com/wh2",
		Secret:   "secret-2",
		Events:   "*",
		IsActive: true,
	}
	if err := repo.CreateEndpoint(tCtx, epWildcard); err != nil {
		t.Fatal(err)
	}

	// FindActiveEndpointsByEvent from context and wildcard matching
	matches, err := repo.FindActiveEndpointsByEvent(tCtx, "", "user.login")
	if err != nil || len(matches) != 2 {
		t.Fatalf("FindActiveEndpointsByEvent login expected 2 matches, got %d, err=%v", len(matches), err)
	}

	matchesOther, err := repo.FindActiveEndpointsByEvent(ctx, "webhook-tenant", "payment.created")
	if err != nil || len(matchesOther) != 1 {
		t.Fatalf("FindActiveEndpointsByEvent wildcard expected 1 match, got %d, err=%v", len(matchesOther), err)
	}

	// Deliveries
	deliv := &models.WebhookDelivery{
		ID:         "deliv-1",
		EndpointID: ep1.ID,
		Event:      "user.login",
		Payload:    "{}",
		Status:     "pending",
		Attempts:   0,
	}
	if err := repo.CreateDelivery(ctx, deliv); err != nil {
		t.Fatal(err)
	}

	pending, err := repo.GetPendingDeliveries(ctx, 10)
	if err != nil || len(pending) != 1 {
		t.Fatalf("GetPendingDeliveries failed: len=%d, err=%v", len(pending), err)
	}

	statusOk := 200
	if err := repo.UpdateDeliveryStatus(ctx, "deliv-1", "success", 1, nil, &statusOk, ""); err != nil {
		t.Fatalf("UpdateDeliveryStatus failed: %v", err)
	}
}

func TestRBACRepository_RolesAndPerms(t *testing.T) {
	ctx := context.Background()
	db := fullTestDB(t)
	repo := NewRBACRepository(db)
	u := testUser(t, db)

	// ListPermissions
	_ = db.Create(&models.Permission{Name: "users:read"}).Error
	_ = db.Create(&models.Permission{Name: "users:write"}).Error
	perms, err := repo.ListPermissions(ctx)
	if err != nil || len(perms) < 2 {
		t.Fatalf("ListPermissions failed: len=%d, err=%v", len(perms), err)
	}

	// CreateRole with empty permNames and tenant from context
	tCtx := tenant.WithTenant(ctx, "rbac-tenant")
	emptyRole := &models.Role{Name: "viewer"}
	if err := repo.CreateRole(tCtx, emptyRole, nil); err != nil {
		t.Fatalf("CreateRole empty permNames failed: %v", err)
	}

	// CreateRole with permNames
	writerRole := &models.Role{Name: "writer"}
	if err := repo.CreateRole(tCtx, writerRole, []string{"users:read", "users:write"}); err != nil {
		t.Fatalf("CreateRole with permNames failed: %v", err)
	}

	// Assign and check
	if err := repo.AssignRoleToUser(ctx, u.ID, writerRole.ID); err != nil {
		t.Fatal(err)
	}
	userPerms, err := repo.GetUserPermissions(ctx, u.ID)
	if err != nil || len(userPerms) != 2 {
		t.Fatalf("GetUserPermissions failed: got %v, err=%v", userPerms, err)
	}
}

func TestOAuthRepository_FindByProviderAndProviderUserID(t *testing.T) {
	ctx := context.Background()
	db := fullTestDB(t)
	repo := NewOAuthIdentityRepository(db)
	u := testUser(t, db)

	// Missing
	if ident, err := repo.FindByProviderAndProviderUserID(ctx, "google", "not-found"); err != nil || ident != nil {
		t.Fatalf("expected nil, got %v, err=%v", ident, err)
	}

	// Found
	created := &models.OAuthIdentity{
		UserID:         u.ID,
		Provider:       "google",
		ProviderUserID: "google-uid-123",
	}
	if err := repo.Create(ctx, created); err != nil {
		t.Fatal(err)
	}
	found, err := repo.FindByProviderAndProviderUserID(ctx, "google", "google-uid-123")
	if err != nil || found == nil || found.ProviderUserID != "google-uid-123" {
		t.Fatalf("FindByProviderAndProviderUserID found failed: got %v, err=%v", found, err)
	}
}

func TestUserRepository_ListPaginatedNoSearch(t *testing.T) {
	ctx := context.Background()
	db := fullTestDB(t)
	repo := NewUserRepository(db)
	_ = testUser(t, db)

	// List without search and with empty tenant (fallback to context)
	tCtx := tenant.WithTenant(ctx, "default")
	users, total, err := repo.ListPaginated(tCtx, "", 0, 0, "")
	if err != nil || total == 0 || len(users) == 0 {
		t.Fatalf("ListPaginated no search failed: total=%d, users=%v, err=%v", total, users, err)
	}

	// CredentialChangeTx rollback on error
	errRollback := repo.CredentialChangeTx(ctx, 1, "hash", func(tx *gorm.DB) error {
		return errors.New("rollback")
	})
	if errRollback == nil {
		t.Fatal("expected error from CredentialChangeTx")
	}

	// FindByEmail and FindByUsername with empty tenant fallback
	foundEmail, _ := repo.FindByEmail(tCtx, "default@test.com")
	_ = foundEmail
	foundUser, _ := repo.FindByUsername(tCtx, "defaultuser")
	_ = foundUser
}

func TestRepositories_ExtraCoverage(t *testing.T) {
	ctx := context.Background()
	db := fullTestDB(t)

	// 1. AuditRepository BatchInsert empty & FindByUserIDPaginated edge pages
	auditRepo := NewAuditRepository(db)
	if count := auditRepo.BatchInsert(ctx, nil); count != 0 {
		t.Fatalf("BatchInsert nil expected 0, got %d", count)
	}
	_, _, err := auditRepo.FindByUserIDPaginated(ctx, 1, 0, 200)
	if err != nil {
		t.Fatal(err)
	}

	// 2. PasskeyRepository ListByUser includeRevoked=true
	passkeyRepo := NewPasskeyRepository(db)
	_ = passkeyRepo.Create(ctx, &models.PasskeyCredential{
		UserID:       1,
		CredentialID: []byte("revoked-cred"),
		PublicKey:    []byte("pub"),
		Revoked:      true,
	})
	revokedList, err := passkeyRepo.ListByUser(ctx, 1, true)
	if err != nil || len(revokedList) != 1 {
		t.Fatalf("ListByUser includeRevoked=true failed: len=%d, err=%v", len(revokedList), err)
	}

	// 3. TOTPRepository ReplaceRecoveryCodes empty
	totpRepo := NewTOTPRepository(db)
	if err := totpRepo.ReplaceRecoveryCodes(ctx, 1, nil); err != nil {
		t.Fatal(err)
	}

	// 4. UserRepository IncrementFailedAttempts with lockUntil and SetEmailVerified
	userRepo := NewUserRepository(db)
	u := testUser(t, db)
	lockTime := time.Now().Add(10 * time.Minute)
	if err := userRepo.IncrementFailedAttempts(ctx, u, &lockTime); err != nil {
		t.Fatal(err)
	}
	if err := userRepo.SetEmailVerified(ctx, u, true); err != nil {
		t.Fatal(err)
	}

	// 5. AuditRepository with empty hmacKey and already-set RecordHash
	noKeyRepo := NewAuditRepository(db, WithAuditHMACKey(nil))
	noKeyRepo.Record(ctx, &models.AuditLog{
		Event:      models.AuditEventLogin,
		RecordHash: "precomputed",
	})

	// 6. AuditRepository error paths via cancelled context
	cancCtx, cancel := context.WithCancel(ctx)
	cancel()

	auditRepo.Record(cancCtx, &models.AuditLog{Event: "fail"})
	_ = auditRepo.BatchInsert(cancCtx, []*models.AuditLog{{Event: "fail"}})
	_, _, _ = auditRepo.FindAllPaginated(cancCtx, "any", 1, 10)
	_, _ = auditRepo.StreamAll(cancCtx, "any")
	_, _ = auditRepo.VerifyChain(cancCtx, "any")
	_, _, _ = auditRepo.FindByUserIDPaginated(cancCtx, 1, 1, 10)
}
