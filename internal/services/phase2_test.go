package services_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/services"
	"github.com/finnapigo/finnapigo/internal/store"
	"github.com/finnapigo/finnapigo/internal/tenant"
)

type mockAdminTokenRepo struct {
	revokedUser uint
}

func (m *mockAdminTokenRepo) Create(_ context.Context, _ *models.RefreshToken) error { return nil }
func (m *mockAdminTokenRepo) FindByHash(_ context.Context, _ string) (*models.RefreshToken, error) {
	return nil, nil
}
func (m *mockAdminTokenRepo) Revoke(_ context.Context, _ *models.RefreshToken) error { return nil }
func (m *mockAdminTokenRepo) RevokeAllForUser(_ context.Context, userID uint) error {
	m.revokedUser = userID
	return nil
}
func (m *mockAdminTokenRepo) RevokeBySession(_ context.Context, _ string) error { return nil }
func (m *mockAdminTokenRepo) FindActiveByUser(_ context.Context, _ uint) ([]models.RefreshToken, error) {
	return nil, nil
}
func (m *mockAdminTokenRepo) RevokeByID(_ context.Context, _, _ uint) error { return nil }
func (m *mockAdminTokenRepo) PurgeExpired(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}

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

	tokenRepo := &mockAdminTokenRepo{}
	kvStore := store.NewInMemoryStore(time.Minute)
	svc := services.NewAdminService(userRepo, sessionRepo, tokenRepo, auditRepo, kvStore)

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
	if err := svc.LockUser(ctx, 10, 10, 2*time.Hour, "10.0.0.1"); !errors.Is(err, services.ErrCannotLockSelf) {
		t.Fatalf("expected ErrCannotLockSelf, got: %v", err)
	}

	// 2c. Lock non-existent user -> ErrUserNotFound
	if err := svc.LockUser(ctx, 1, 9999, time.Hour, "10.0.0.1"); !errors.Is(err, services.ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound, got: %v", err)
	}

	// 3. UnlockUser
	if err := svc.UnlockUser(ctx, 1, 10, "10.0.0.1"); err != nil {
		t.Fatalf("UnlockUser failed: %v", err)
	}
	if userRepo.lockedUntil[10] != nil {
		t.Fatal("expected lockedUntil to be nil after unlock")
	}

	// 3b. Unlock non-existent user -> ErrUserNotFound
	if err := svc.UnlockUser(ctx, 1, 9999, "10.0.0.1"); !errors.Is(err, services.ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound, got: %v", err)
	}

	// 4. ForceLogout
	if err := svc.ForceLogout(ctx, 1, 10, "10.0.0.1"); err != nil {
		t.Fatalf("ForceLogout failed: %v", err)
	}
	if !sessionRepo.revoked[10] {
		t.Fatal("expected user sessions to be revoked")
	}
	if tokenRepo.revokedUser != 10 {
		t.Fatal("expected refresh tokens to be revoked")
	}
	if userRepo.pwdVersions[10] != 1 {
		t.Fatalf("expected pwdVersion bumped, got %d", userRepo.pwdVersions[10])
	}

	// 4b. ForceLogout non-existent user -> ErrUserNotFound
	if err := svc.ForceLogout(ctx, 1, 9999, "10.0.0.1"); !errors.Is(err, services.ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound, got: %v", err)
	}

	// 5. ListTenantSessions
	sessList, err := svc.ListTenantSessions(ctx)
	if err != nil {
		t.Fatalf("ListTenantSessions failed: %v", err)
	}
	if len(sessList) != 1 || sessList[0].ID != "sess-1" {
		t.Fatalf("unexpected tenant sessions: %+v", sessList)
	}

	// 6. Nil admin service coverage
	nilAdmin := services.NewAdminService(nil, nil, nil, nil, nil)
	_, _, _ = nilAdmin.ExportAuditLogs(ctx, "csv")
	_, _ = nilAdmin.ListTenantSessions(ctx)

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

func TestWebhookService_DeliverOne(t *testing.T) {
	ctx := context.Background()
	repo := newMockWebhookRepo()
	svc := services.NewWebhookService(repo)
	svc.SetAllowLocalhost(true)

	// Test 1: Successful delivery (200 OK)
	serverOK := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sig := r.Header.Get("X-Signature-256")
		if sig == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer serverOK.Close()

	dOK := &models.WebhookDelivery{
		ID:         "del-ok",
		EndpointID: "ep-1",
		Event:      "user.created",
		Payload:    `{"test":true}`,
	}
	repo.deliveries[dOK.ID] = dOK

	err := svc.DeliverOne(ctx, dOK, "secret123", serverOK.URL)
	if err != nil {
		t.Fatalf("DeliverOne failed on 200 OK: %v", err)
	}
	if repo.deliveries[dOK.ID].Status != "delivered" {
		t.Fatalf("expected status delivered, got %s", repo.deliveries[dOK.ID].Status)
	}

	// Test 2: Failed delivery (500 Internal Server Error)
	serverFail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer serverFail.Close()

	dFail := &models.WebhookDelivery{
		ID:         "del-fail",
		EndpointID: "ep-1",
		Event:      "user.created",
		Payload:    `{"test":true}`,
		Attempts:   5, // max attempts -> will mark failed
	}
	repo.deliveries[dFail.ID] = dFail

	err = svc.DeliverOne(ctx, dFail, "secret123", serverFail.URL)
	if err == nil {
		t.Fatal("expected error on 500 response")
	}
	if repo.deliveries[dFail.ID].Status != "failed" {
		t.Fatalf("expected status failed, got %s", repo.deliveries[dFail.ID].Status)
	}
}

func TestSMTPNotifier_AlertMethods(t *testing.T) {
	notifier := services.NewSMTPNotifier("", "", "", "", "")
	ctx := context.Background()
	if err := notifier.SendNewLoginAlert(ctx, "user@example.com", "192.168.1.1", "Chrome"); err == nil || !strings.Contains(err.Error(), "smtp notifier not configured") {
		t.Errorf("expected smtp notifier not configured, got %v", err)
	}
	if err := notifier.SendDuplicateRegisterAlert(ctx, "user@example.com"); err == nil || !strings.Contains(err.Error(), "smtp notifier not configured") {
		t.Errorf("expected smtp notifier not configured, got %v", err)
	}
	if err := notifier.SendSecurityAlert(ctx, "user@example.com", "Password changed", "IP: 1.2.3.4"); err == nil || !strings.Contains(err.Error(), "smtp notifier not configured") {
		t.Errorf("expected smtp notifier not configured, got %v", err)
	}
}

func TestWebhookService_DeliverOneBranches(t *testing.T) {
	ctx := context.Background()
	repo := newMockWebhookRepo()
	svc := services.NewWebhookService(repo)
	svc.SetAllowLocalhost(true)

	// 1. Invalid URL
	dBad := &models.WebhookDelivery{ID: "del-bad", Payload: "{}"}
	if err := svc.DeliverOne(ctx, dBad, "sec", "invalid://url"); err == nil {
		t.Fatal("expected error on invalid URL")
	}

	// 2. Network connection error with attempts < 5 -> pending
	dNet := &models.WebhookDelivery{ID: "del-net", EndpointID: "ep-1", Attempts: 1, Payload: "{}"}
	repo.deliveries[dNet.ID] = dNet
	_ = svc.DeliverOne(ctx, dNet, "sec", "http://127.0.0.1:54321/down")
	if repo.deliveries[dNet.ID].Status != "pending" {
		t.Fatalf("expected pending status, got %s", repo.deliveries[dNet.ID].Status)
	}

	// 3. HTTP 500 error with attempts < 5 -> pending retry
	server500 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server500.Close()

	dRetry := &models.WebhookDelivery{ID: "del-retry", EndpointID: "ep-1", Attempts: 1, Payload: "{}"}
	repo.deliveries[dRetry.ID] = dRetry
	_ = svc.DeliverOne(ctx, dRetry, "sec", server500.URL)
	if repo.deliveries[dRetry.ID].Status != "pending" {
		t.Fatalf("expected pending status, got %s", repo.deliveries[dRetry.ID].Status)
	}
}

func TestTrustedDeviceService_Comprehensive(t *testing.T) {
	ctx := context.Background()

	// 1. Nil repo branches
	nilSvc := services.NewTrustedDeviceService(nil)
	valid, _ := nilSvc.Validate(ctx, 1, "token")
	if valid {
		t.Fatal("expected false on nil repo")
	}
	devs, _ := nilSvc.ListByUser(ctx, 1)
	if devs != nil {
		t.Fatal("expected nil on nil repo")
	}
	if err := nilSvc.Revoke(ctx, 1, 1); err != nil {
		t.Fatalf("unexpected error on nil repo: %v", err)
	}

	// 2. Empty token validation
	repo := newMockTrustedDeviceRepo()
	svc := services.NewTrustedDeviceService(repo)
	valid, _ = svc.Validate(ctx, 1, "")
	if valid {
		t.Fatal("expected false on empty token")
	}

	// 3. Expired token validation
	tok, _, _ := svc.Issue(ctx, 1, "Safari", "1.2.3.4")
	for _, d := range repo.devices {
		d.ExpiresAt = time.Now().Add(-time.Hour)
	}
	valid, _ = svc.Validate(ctx, 1, tok)
	if valid {
		t.Fatal("expected false on expired token")
	}

	// 4. Revoked token validation
	for _, d := range repo.devices {
		d.ExpiresAt = time.Now().Add(time.Hour)
		d.Revoked = true
	}
	valid, _ = svc.Validate(ctx, 1, tok)
	if valid {
		t.Fatal("expected false on revoked token")
	}
}

func TestServiceConstructors_Options(t *testing.T) {
	// Exercise option closures to achieve 100% constructor statement coverage
	sAuth := &services.AuthService{}
	services.WithSessionRepo(nil)(sAuth)
	services.WithBreachedPasswordChecker(nil)(sAuth)
	services.WithMinPasswordScore(3)(sAuth)
	services.WithAuthPasskeys(nil)(sAuth)
	services.WithAuthOAuthIdents(nil)(sAuth)

	sTOTP := &services.TOTPService{}
	services.WithTOTPUserRepo(nil)(sTOTP)
	services.WithTOTPNotifier(nil)(sTOTP)
	services.WithTOTPPasskeys(nil)(sTOTP)
}

func TestAdminService_ExportAuditLogs(t *testing.T) {
	ctx := tenant.WithTenant(context.Background(), "tenant-export")
	userRepo := newMockAdminUserRepo()
	sessionRepo := &mockAdminSessionRepo{}
	auditRepo := &mockAdminAuditRepo{}

	svc := services.NewAdminService(userRepo, sessionRepo, nil, auditRepo, nil)

	// Seed audit entries
	uID := uint(42)
	auditRepo.logs = append(auditRepo.logs, &models.AuditLog{
		ID:        1,
		TenantID:  "tenant-export",
		UserID:    &uID,
		Email:     "admin@export.org",
		Event:     models.AuditEventLogin,
		IPAddress: "127.0.0.1",
		Success:   true,
		Detail:    "successful login",
		CreatedAt: time.Now(),
	})

	// 1. Export NDJSON
	data, mime, err := svc.ExportAuditLogs(ctx, "ndjson")
	if err != nil || mime != "application/x-ndjson" || len(data) == 0 {
		t.Fatalf("ExportAuditLogs ndjson failed: len=%d, mime=%s, err=%v", len(data), mime, err)
	}

	// 2. Export CSV
	data, mime, err = svc.ExportAuditLogs(ctx, "csv")
	if err != nil || mime != "text/csv" || len(data) == 0 {
		t.Fatalf("ExportAuditLogs csv failed: len=%d, mime=%s, err=%v", len(data), mime, err)
	}
}
