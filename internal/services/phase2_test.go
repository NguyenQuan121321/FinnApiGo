package services_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/services"
	"github.com/finnapigo/finnapigo/internal/tenant"
)

// mockAdminUserRepo implements services.AdminUserRepo for testing.
type mockAdminUserRepo struct {
	users       map[uint]*models.User
	lockedUntil map[uint]*time.Time
	pwdVersions map[uint]int64
}

func newMockAdminUserRepo() *mockAdminUserRepo {
	return &mockAdminUserRepo{
		users:       make(map[uint]*models.User),
		lockedUntil: make(map[uint]*time.Time),
		pwdVersions: make(map[uint]int64),
	}
}

func (m *mockAdminUserRepo) FindByID(_ context.Context, id uint) (*models.User, error) {
	return m.users[id], nil
}

func (m *mockAdminUserRepo) ListPaginated(_ context.Context, tenantID string, page, limit int, search string) ([]models.User, int64, error) {
	var list []models.User
	for _, u := range m.users {
		if tenantID == "" || u.TenantID == tenantID {
			if search == "" || strings.Contains(u.Username, search) || strings.Contains(u.Email, search) {
				list = append(list, *u)
			}
		}
	}
	return list, int64(len(list)), nil
}

func (m *mockAdminUserRepo) SetLock(_ context.Context, userID uint, lockedUntil *time.Time) error {
	m.lockedUntil[userID] = lockedUntil
	return nil
}

func (m *mockAdminUserRepo) BumpPwdVersion(_ context.Context, userID uint) error {
	m.pwdVersions[userID]++
	return nil
}

// mockAdminSessionRepo implements services.AdminSessionRepo.
type mockAdminSessionRepo struct {
	sessions []models.Session
	revoked  map[uint]bool
}

func (m *mockAdminSessionRepo) FindAllActiveByTenant(_ context.Context, tenantID string) ([]models.Session, error) {
	var out []models.Session
	for _, s := range m.sessions {
		if tenantID == "" || s.TenantID == tenantID {
			out = append(out, s)
		}
	}
	return out, nil
}

func (m *mockAdminSessionRepo) RevokeAllForUser(_ context.Context, userID uint) error {
	if m.revoked == nil {
		m.revoked = make(map[uint]bool)
	}
	m.revoked[userID] = true
	return nil
}

// mockAdminAuditRepo implements services.AdminAuditRepo.
type mockAdminAuditRepo struct {
	logs []*models.AuditLog
}

func (m *mockAdminAuditRepo) Record(_ context.Context, entry *models.AuditLog) {
	m.logs = append(m.logs, entry)
}

func (m *mockAdminAuditRepo) StreamAll(_ context.Context, tenantID string) ([]models.AuditLog, error) {
	var out []models.AuditLog
	for _, l := range m.logs {
		if tenantID == "" || l.TenantID == tenantID {
			out = append(out, *l)
		}
	}
	return out, nil
}

func TestAdminService_Lifecycle(t *testing.T) {
	ctx := tenant.WithTenant(context.Background(), "tenant-alpha")
	userRepo := newMockAdminUserRepo()
	sessionRepo := &mockAdminSessionRepo{
		sessions: []models.Session{
			{ID: "sess-1", TenantID: "tenant-alpha", UserID: 10, IPAddress: "1.2.3.4", DeviceName: "MacBook"},
			{ID: "sess-2", TenantID: "tenant-beta", UserID: 20, IPAddress: "5.6.7.8", DeviceName: "iPhone"},
		},
	}
	auditRepo := &mockAdminAuditRepo{}

	userRepo.users[10] = &models.User{
		ID:       10,
		TenantID: "tenant-alpha",
		Username: "alice",
		Email:    "alice@alpha.local",
		Role:     "user",
		IsActive: true,
	}

	svc := services.NewAdminService(userRepo, sessionRepo, nil, auditRepo, nil)

	// 1. ListUsers
	users, total, err := svc.ListUsers(ctx, 1, 10, "")
	if err != nil {
		t.Fatalf("ListUsers failed: %v", err)
	}
	if total != 1 || len(users) != 1 || users[0].Username != "alice" {
		t.Fatalf("unexpected users list: %+v", users)
	}

	// 2. LockUser
	if err := svc.LockUser(ctx, 1, 10, 2*time.Hour, "10.0.0.1"); err != nil {
		t.Fatalf("LockUser failed: %v", err)
	}
	if userRepo.lockedUntil[10] == nil {
		t.Fatal("expected lockedUntil to be set")
	}

	// 2b. Attempt self-lock -> must fail
	if err := svc.LockUser(ctx, 10, 10, 2*time.Hour, "10.0.0.1"); err != services.ErrCannotLockSelf {
		t.Fatalf("expected ErrCannotLockSelf, got: %v", err)
	}

	// 3. UnlockUser
	if err := svc.UnlockUser(ctx, 1, 10, "10.0.0.1"); err != nil {
		t.Fatalf("UnlockUser failed: %v", err)
	}
	if userRepo.lockedUntil[10] != nil {
		t.Fatal("expected lockedUntil to be nil after unlock")
	}

	// 4. ForceLogout
	if err := svc.ForceLogout(ctx, 1, 10, "10.0.0.1"); err != nil {
		t.Fatalf("ForceLogout failed: %v", err)
	}
	if !sessionRepo.revoked[10] {
		t.Fatal("expected user sessions to be revoked")
	}
	if userRepo.pwdVersions[10] != 1 {
		t.Fatalf("expected pwdVersion bumped, got %d", userRepo.pwdVersions[10])
	}

	// 5. ListTenantSessions
	sessList, err := svc.ListTenantSessions(ctx)
	if err != nil {
		t.Fatalf("ListTenantSessions failed: %v", err)
	}
	if len(sessList) != 1 || sessList[0].ID != "sess-1" {
		t.Fatalf("unexpected tenant sessions: %+v", sessList)
	}

	// 6. ExportAuditLogs (CSV and NDJSON)
	csvData, ct, err := svc.ExportAuditLogs(ctx, "csv")
	if err != nil || ct != "text/csv" || len(csvData) == 0 {
		t.Fatalf("ExportAuditLogs CSV failed: %v", err)
	}
	if !strings.Contains(string(csvData), "admin_action") {
		t.Fatalf("CSV missing admin_action: %s", string(csvData))
	}

	ndjsonData, ct, err := svc.ExportAuditLogs(ctx, "ndjson")
	if err != nil || ct != "application/x-ndjson" || len(ndjsonData) == 0 {
		t.Fatalf("ExportAuditLogs NDJSON failed: %v", err)
	}
}

// mockTrustedDeviceRepo implements services.TrustedDeviceRepo.
type mockTrustedDeviceRepo struct {
	devices map[string]*models.TrustedDevice
	byUser  map[uint][]*models.TrustedDevice
}

func newMockTrustedDeviceRepo() *mockTrustedDeviceRepo {
	return &mockTrustedDeviceRepo{
		devices: make(map[string]*models.TrustedDevice),
		byUser:  make(map[uint][]*models.TrustedDevice),
	}
}

func (m *mockTrustedDeviceRepo) Create(_ context.Context, d *models.TrustedDevice) error {
	d.ID = uint(len(m.devices) + 1)
	m.devices[d.DeviceHash] = d
	m.byUser[d.UserID] = append(m.byUser[d.UserID], d)
	return nil
}

func (m *mockTrustedDeviceRepo) FindByDeviceHash(_ context.Context, hash string) (*models.TrustedDevice, error) {
	return m.devices[hash], nil
}

func (m *mockTrustedDeviceRepo) TouchUsage(_ context.Context, id uint, at time.Time) error {
	for _, d := range m.devices {
		if d.ID == id {
			d.LastUsedAt = &at
			return nil
		}
	}
	return nil
}

func (m *mockTrustedDeviceRepo) ListByUser(_ context.Context, userID uint) ([]models.TrustedDevice, error) {
	var out []models.TrustedDevice
	for _, d := range m.byUser[userID] {
		if !d.Revoked {
			out = append(out, *d)
		}
	}
	return out, nil
}

func (m *mockTrustedDeviceRepo) Revoke(_ context.Context, id, userID uint) error {
	for _, d := range m.devices {
		if d.ID == id && d.UserID == userID {
			d.Revoked = true
			return nil
		}
	}
	return nil
}

func TestTrustedDeviceService(t *testing.T) {
	ctx := context.Background()
	repo := newMockTrustedDeviceRepo()
	svc := services.NewTrustedDeviceService(repo)

	// 1. Issue device token
	token, exp, err := svc.Issue(ctx, 42, "Bob's Work Laptop", "192.168.1.50")
	if err != nil || token == "" {
		t.Fatalf("Issue failed: %v", err)
	}
	if exp.Before(time.Now().Add(29 * 24 * time.Hour)) {
		t.Fatalf("expected 30-day expiry, got %v", exp)
	}

	// 2. Validate device token
	valid, err := svc.Validate(ctx, 42, token)
	if err != nil || !valid {
		t.Fatalf("Validate failed: valid=%v, err=%v", valid, err)
	}

	// 3. Reject validation for different user
	validOther, _ := svc.Validate(ctx, 999, token)
	if validOther {
		t.Fatal("device should be invalid for different user")
	}

	// 4. List devices
	list, err := svc.ListByUser(ctx, 42)
	if err != nil || len(list) != 1 || list[0].DeviceName != "Bob's Work Laptop" {
		t.Fatalf("ListByUser unexpected: %+v", list)
	}

	// 5. Revoke device
	if err := svc.Revoke(ctx, list[0].ID, 42); err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}

	// 6. Validating after revoke must fail
	validAfterRevoke, _ := svc.Validate(ctx, 42, token)
	if validAfterRevoke {
		t.Fatal("revoked device must not validate")
	}
}

// mockWebhookRepo implements services.WebhookRepo.
type mockWebhookRepo struct {
	endpoints  map[string]*models.WebhookEndpoint
	deliveries map[string]*models.WebhookDelivery
}

func newMockWebhookRepo() *mockWebhookRepo {
	return &mockWebhookRepo{
		endpoints:  make(map[string]*models.WebhookEndpoint),
		deliveries: make(map[string]*models.WebhookDelivery),
	}
}

func (m *mockWebhookRepo) CreateEndpoint(_ context.Context, ep *models.WebhookEndpoint) error {
	m.endpoints[ep.ID] = ep
	return nil
}

func (m *mockWebhookRepo) FindActiveEndpointsByEvent(_ context.Context, tenantID, event string) ([]models.WebhookEndpoint, error) {
	var out []models.WebhookEndpoint
	for _, ep := range m.endpoints {
		if ep.TenantID == tenantID && ep.IsActive {
			out = append(out, *ep)
		}
	}
	return out, nil
}

func (m *mockWebhookRepo) CreateDelivery(_ context.Context, d *models.WebhookDelivery) error {
	m.deliveries[d.ID] = d
	return nil
}

func (m *mockWebhookRepo) GetPendingDeliveries(_ context.Context, _ int) ([]models.WebhookDelivery, error) {
	var out []models.WebhookDelivery
	for _, d := range m.deliveries {
		if d.Status == "pending" {
			out = append(out, *d)
		}
	}
	return out, nil
}

func (m *mockWebhookRepo) UpdateDeliveryStatus(_ context.Context, id string, status string, attempts int, nextRetry *time.Time, respStatus *int, errMsg string) error {
	if d, ok := m.deliveries[id]; ok {
		d.Status = status
		d.Attempts = attempts
		d.NextRetryAt = nextRetry
		d.ResponseStatus = respStatus
		d.ErrorMsg = errMsg
	}
	return nil
}

func TestWebhookService_OutboxAndSigning(t *testing.T) {
	ctx := context.Background()
	repo := newMockWebhookRepo()
	svc := services.NewWebhookService(repo)
	svc.SetAllowLocalhost(true)

	// 1. Register endpoint
	ep, err := svc.RegisterEndpoint(ctx, "tenant-xyz", "https://example.com/webhook", "user.created,user.locked")
	if err != nil {
		t.Fatalf("RegisterEndpoint failed: %v", err)
	}
	if ep.Secret == "" || ep.URL != "https://example.com/webhook" {
		t.Fatalf("unexpected endpoint: %+v", ep)
	}

	// 2. Enqueue event
	err = svc.EnqueueEvent(ctx, "tenant-xyz", "user.created", map[string]any{"userId": 123})
	if err != nil {
		t.Fatalf("EnqueueEvent failed: %v", err)
	}
	if len(repo.deliveries) != 1 {
		t.Fatalf("expected 1 delivery in outbox, got %d", len(repo.deliveries))
	}

	// 3. Test payload HMAC-SHA256 signature
	sig := services.SignPayload("test-secret", "sample-payload")
	if !strings.HasPrefix(sig, "sha256=") {
		t.Fatalf("invalid signature format: %s", sig)
	}

	// 4. Test SSRF protection: reject loopback / private IPs
	prodSvc := services.NewWebhookService(repo) // allowLocalhost is false by default
	_, ssrfErr := prodSvc.RegisterEndpoint(ctx, "tenant-xyz", "http://127.0.0.1:8080/internal", "user.created")
	if ssrfErr == nil {
		t.Fatal("expected SSRF block for 127.0.0.1")
	}
}
