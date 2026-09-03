package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/finnapigo/finnapigo/internal/handlers"
	"github.com/finnapigo/finnapigo/internal/middleware"
	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/services"
	"github.com/gin-gonic/gin"
)

// mockAdminService implements handlers.AdminServiceInterface.
type mockAdminService struct {
	users    []services.UserProfile
	sessions []services.SessionInfo
	locked   map[uint]bool
	unlocked map[uint]bool
	forced   map[uint]bool
}

func newMockAdminService() *mockAdminService {
	return &mockAdminService{
		locked:   make(map[uint]bool),
		unlocked: make(map[uint]bool),
		forced:   make(map[uint]bool),
	}
}

func (m *mockAdminService) ListUsers(_ context.Context, _, _ int, _ string) ([]services.UserProfile, int64, error) {
	return m.users, int64(len(m.users)), nil
}

func (m *mockAdminService) LockUser(_ context.Context, _, targetUserID uint, _ time.Duration, _ string) error {
	m.locked[targetUserID] = true
	return nil
}

func (m *mockAdminService) UnlockUser(_ context.Context, _, targetUserID uint, _ string) error {
	m.unlocked[targetUserID] = true
	return nil
}

func (m *mockAdminService) ForceLogout(_ context.Context, _, targetUserID uint, _ string) error {
	m.forced[targetUserID] = true
	return nil
}

func (m *mockAdminService) ListTenantSessions(_ context.Context) ([]services.SessionInfo, error) {
	return m.sessions, nil
}

func (m *mockAdminService) ExportAuditLogs(_ context.Context, format string) ([]byte, string, error) {
	if format == "csv" {
		return []byte("id,event\n1,login\n"), "text/csv", nil
	}
	return []byte(`{"id":1,"event":"login"}` + "\n"), "application/x-ndjson", nil
}

// mockTrustedDeviceService implements handlers.TrustedDeviceServiceInterface.
type mockTrustedDeviceService struct {
	devices []services.TrustedDeviceInfo
	revoked map[uint]bool
}

func (m *mockTrustedDeviceService) ListByUser(_ context.Context, _ uint) ([]services.TrustedDeviceInfo, error) {
	return m.devices, nil
}

func (m *mockTrustedDeviceService) Revoke(_ context.Context, id, _ uint) error {
	if m.revoked == nil {
		m.revoked = make(map[uint]bool)
	}
	m.revoked[id] = true
	return nil
}

// mockWebhookService implements handlers.WebhookServiceInterface.
type mockWebhookService struct {
	created *models.WebhookEndpoint
}

func (m *mockWebhookService) RegisterEndpoint(_ context.Context, tenantID, targetURL, events string) (*models.WebhookEndpoint, error) {
	m.created = &models.WebhookEndpoint{
		ID:       "ep-123",
		TenantID: tenantID,
		URL:      targetURL,
		Events:   events,
		IsActive: true,
	}
	return m.created, nil
}

func TestPhase2_AdminHandlers(t *testing.T) {
	gin.SetMode(gin.TestMode)
	adminSvc := newMockAdminService()
	adminSvc.users = []services.UserProfile{
		{ID: 10, Username: "alice", Email: "alice@test.local", Role: "user", IsActive: true},
	}
	adminSvc.sessions = []services.SessionInfo{
		{ID: "sess-1", IPAddress: "127.0.0.1", DeviceName: "MacBook"},
	}
	h := handlers.NewAdminHandler(adminSvc)

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(middleware.CtxUserID, uint(1)) // Mock admin authentication
		c.Next()
	})

	r.GET("/admin/users", h.ListUsers)
	r.POST("/admin/users/:id/lock", h.LockUser)
	r.POST("/admin/users/:id/unlock", h.UnlockUser)
	r.POST("/admin/users/:id/force-logout", h.ForceLogout)
	r.GET("/admin/sessions", h.ListSessions)
	r.GET("/admin/audit-log/export", h.ExportAuditLog)

	// 1. ListUsers
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/admin/users", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("ListUsers status = %d", w.Code)
	}

	// 2. LockUser
	body, _ := json.Marshal(map[string]int64{"durationSeconds": 3600})
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/admin/users/10/lock", bytes.NewReader(body)))
	if w.Code != http.StatusOK || !adminSvc.locked[10] {
		t.Fatalf("LockUser failed: status=%d, locked=%v", w.Code, adminSvc.locked[10])
	}

	// 3. UnlockUser
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/admin/users/10/unlock", nil))
	if w.Code != http.StatusOK || !adminSvc.unlocked[10] {
		t.Fatalf("UnlockUser failed: status=%d, unlocked=%v", w.Code, adminSvc.unlocked[10])
	}

	// 4. ForceLogout
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/admin/users/10/force-logout", nil))
	if w.Code != http.StatusOK || !adminSvc.forced[10] {
		t.Fatalf("ForceLogout failed: status=%d, forced=%v", w.Code, adminSvc.forced[10])
	}

	// 5. ListSessions
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/admin/sessions", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("ListSessions status = %d", w.Code)
	}

	// 6. ExportAuditLog CSV
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/admin/audit-log/export?format=csv", nil))
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "text/csv" {
		t.Fatalf("ExportAuditLog CSV failed: code=%d, type=%s", w.Code, w.Header().Get("Content-Type"))
	}
}

func TestPhase2_TrustedDeviceAndWebhookHandlers(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// TrustedDeviceHandler
	tdSvc := &mockTrustedDeviceService{
		devices: []services.TrustedDeviceInfo{
			{ID: 5, DeviceName: "Home PC", IPAddress: "192.168.1.10"},
		},
	}
	tdH := handlers.NewTrustedDeviceHandler(tdSvc)

	// WebhookHandler
	whSvc := &mockWebhookService{}
	whH := handlers.NewWebhookHandler(whSvc)

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(middleware.CtxUserID, uint(42))
		c.Next()
	})

	r.GET("/auth/trusted-devices", tdH.ListDevices)
	r.DELETE("/auth/trusted-devices/:id", tdH.RevokeDevice)
	r.POST("/admin/webhooks", whH.CreateEndpoint)

	// 1. List trusted devices
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/trusted-devices", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("ListDevices status = %d", w.Code)
	}

	// 2. Revoke trusted device
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/auth/trusted-devices/5", nil))
	if w.Code != http.StatusOK || !tdSvc.revoked[5] {
		t.Fatalf("RevokeDevice failed: status=%d", w.Code)
	}

	// 3. Register webhook
	whBody, _ := json.Marshal(map[string]string{
		"url":    "https://partner.com/events",
		"events": "user.created,user.locked",
	})
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/admin/webhooks", bytes.NewReader(whBody)))
	if w.Code != http.StatusCreated || whSvc.created == nil || whSvc.created.URL != "https://partner.com/events" {
		t.Fatalf("CreateEndpoint failed: status=%d, created=%+v", w.Code, whSvc.created)
	}
}
