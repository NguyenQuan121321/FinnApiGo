package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/finnapigo/finnapigo/internal/middleware"
	"github.com/finnapigo/finnapigo/internal/services"
	"github.com/gin-gonic/gin"
)

type phase1MockAuthService struct {
	fakeAuthService
	reqChangeEmailErr error
	confirmEmailErr   error
	deactivateErr     error
	eraseErr          error
	auditLogs         []services.UserAuditLogItem
	auditTotal        int64
	auditErr          error
}

func (m phase1MockAuthService) RequestChangeEmail(ctx context.Context, userID uint, in services.ChangeEmailRequestInput, ip string) error {
	return m.reqChangeEmailErr
}

func (m phase1MockAuthService) ConfirmChangeEmail(ctx context.Context, token, ip string) error {
	return m.confirmEmailErr
}

func (m phase1MockAuthService) DeactivateAccount(ctx context.Context, userID uint, sudoToken, password, accessJTI, ip string) error {
	return m.deactivateErr
}

func (m phase1MockAuthService) EraseAccount(ctx context.Context, userID uint, sudoToken, password, accessJTI, ip string) error {
	return m.eraseErr
}

func (m phase1MockAuthService) GetUserAuditLog(ctx context.Context, userID uint, page, limit int) ([]services.UserAuditLogItem, int64, error) {
	return m.auditLogs, m.auditTotal, m.auditErr
}

type phase1MockOAuthService struct {
	unlinkErr error
}

func (m phase1MockOAuthService) BeginLogin(ctx context.Context) (string, string, error) {
	return "state", "https://accounts.google.com/o/oauth2/v2/auth", nil
}

func (m phase1MockOAuthService) HandleCallback(ctx context.Context, code, state, ip, ua string) (services.TokenPair, services.UserProfile, *services.MFAPendingResult, error) {
	return services.TokenPair{}, services.UserProfile{}, nil, nil
}

func (m phase1MockOAuthService) Unlink(ctx context.Context, userID uint, provider, ip string) error {
	return m.unlinkErr
}

func TestHandler_DisableTOTP_Scenarios(t *testing.T) {
	uid := uint(1)
	tests := []struct {
		name       string
		totpErr    error
		body       string
		sudoHeader string
		wantStatus int
	}{
		{"success with sudo token", nil, "{}", "valid-sudo", http.StatusOK},
		{"success with password and code", nil, `{"password":"Password123","code":"123456"}`, "", http.StatusOK},
		{"invalid credentials", services.ErrInvalidCredentials, `{"password":"Wrong","code":"123456"}`, "", http.StatusUnauthorized},
		{"invalid code", services.ErrInvalidCode, `{"password":"Password123","code":"000000"}`, "", http.StatusUnauthorized},
		{"sudo required", services.ErrSudoRequired, "{}", "", http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewMFAHandler(fakeTOTPService{err: tt.totpErr}, nil, 0)
			gin.SetMode(gin.TestMode)
			r := gin.New()
			r.POST("/disable", func(c *gin.Context) {
				c.Set("user_id", uid)
				h.DisableTOTP(c)
			})
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/disable", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			if tt.sudoHeader != "" {
				req.Header.Set(middleware.SudoHeader, tt.sudoHeader)
			}
			r.ServeHTTP(w, req)
			if w.Code != tt.wantStatus {
				t.Fatalf("status=%d, want=%d body=%s", w.Code, tt.wantStatus, w.Body.String())
			}
		})
	}
}

func TestHandler_RequestChangeEmail_Scenarios(t *testing.T) {
	uid := uint(1)
	tests := []struct {
		name       string
		svcErr     error
		body       string
		wantStatus int
	}{
		{"success", nil, `{"password":"Password123","newEmail":"new@example.com"}`, http.StatusOK},
		{"bad json", nil, `{malformed`, http.StatusBadRequest},
		{"wrong password", services.ErrInvalidCredentials, `{"password":"Bad","newEmail":"new@example.com"}`, http.StatusUnauthorized},
		{"disposable email", services.ErrDisposableEmail, `{"password":"Password123","newEmail":"bad@mailinator.com"}`, http.StatusUnprocessableEntity},
		{"email exists", services.ErrEmailExists, `{"password":"Password123","newEmail":"taken@example.com"}`, http.StatusConflict},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewAuthHandler(phase1MockAuthService{reqChangeEmailErr: tt.svcErr}, nil)
			w := serve(t, h.RequestChangeEmail, tt.body, &uid)
			if w.Code != tt.wantStatus {
				t.Fatalf("status=%d, want=%d body=%s", w.Code, tt.wantStatus, w.Body.String())
			}
		})
	}
}

func TestHandler_ConfirmChangeEmail_Scenarios(t *testing.T) {
	tests := []struct {
		name       string
		svcErr     error
		body       string
		wantStatus int
	}{
		{"success", nil, `{"token":"valid-token"}`, http.StatusOK},
		{"bad json", nil, `{`, http.StatusBadRequest},
		{"invalid token", services.ErrInvalidToken, `{"token":"bad-token"}`, http.StatusUnauthorized},
		{"email collision", services.ErrEmailExists, `{"token":"race-taken"}`, http.StatusConflict},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewAuthHandler(phase1MockAuthService{confirmEmailErr: tt.svcErr}, nil)
			w := serve(t, h.ConfirmChangeEmail, tt.body, nil)
			if w.Code != tt.wantStatus {
				t.Fatalf("status=%d, want=%d body=%s", w.Code, tt.wantStatus, w.Body.String())
			}
		})
	}
}

func TestHandler_DeactivateAndErase_Scenarios(t *testing.T) {
	uid := uint(1)

	// Deactivate
	t.Run("Deactivate success", func(t *testing.T) {
		h := NewAuthHandler(phase1MockAuthService{}, nil)
		w := serve(t, h.DeactivateAccount, `{"password":"Password123"}`, &uid)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("Deactivate bad password", func(t *testing.T) {
		h := NewAuthHandler(phase1MockAuthService{deactivateErr: services.ErrInvalidCredentials}, nil)
		w := serve(t, h.DeactivateAccount, `{"password":"Wrong"}`, &uid)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})

	t.Run("Deactivate sudo required", func(t *testing.T) {
		h := NewAuthHandler(phase1MockAuthService{deactivateErr: services.ErrSudoRequired}, nil)
		w := serve(t, h.DeactivateAccount, `{}`, &uid)
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", w.Code)
		}
	})

	// EraseMe
	t.Run("EraseMe success", func(t *testing.T) {
		h := NewAuthHandler(phase1MockAuthService{}, nil)
		gin.SetMode(gin.TestMode)
		r := gin.New()
		r.DELETE("/me", func(c *gin.Context) {
			c.Set("user_id", uid)
			h.EraseMe(c)
		})
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/me", nil))
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("EraseMe unauthorized without user", func(t *testing.T) {
		h := NewAuthHandler(phase1MockAuthService{}, nil)
		gin.SetMode(gin.TestMode)
		r := gin.New()
		r.DELETE("/me", func(c *gin.Context) {
			h.EraseMe(c)
		})
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/me", nil))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})
}

func TestHandler_OAuthUnlink_Scenarios(t *testing.T) {
	uid := uint(1)

	t.Run("Unlink success", func(t *testing.T) {
		h := NewOAuthHandler(phase1MockOAuthService{})
		gin.SetMode(gin.TestMode)
		r := gin.New()
		r.DELETE("/oauth/:provider", func(c *gin.Context) {
			c.Set("user_id", uid)
			h.Unlink(c)
		})
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/oauth/google", nil))
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("Unlink sole login method rejected (400)", func(t *testing.T) {
		h := NewOAuthHandler(phase1MockOAuthService{unlinkErr: services.ErrCannotUnlinkOnlyMethod})
		gin.SetMode(gin.TestMode)
		r := gin.New()
		r.DELETE("/oauth/:provider", func(c *gin.Context) {
			c.Set("user_id", uid)
			h.Unlink(c)
		})
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/oauth/google", nil))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: body=%s", w.Code, w.Body.String())
		}
	})

	t.Run("Unlink not found (404)", func(t *testing.T) {
		h := NewOAuthHandler(phase1MockOAuthService{unlinkErr: services.ErrUserNotFound})
		gin.SetMode(gin.TestMode)
		r := gin.New()
		r.DELETE("/oauth/:provider", func(c *gin.Context) {
			c.Set("user_id", uid)
			h.Unlink(c)
		})
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/oauth/github", nil))
		if w.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d", w.Code)
		}
	})
}

func TestHandler_MyAuditLog_PaginationAndSanitization(t *testing.T) {
	uid := uint(1)
	h := NewAuthHandler(phase1MockAuthService{
		auditLogs: []services.UserAuditLogItem{
			{ID: 1, Event: "login", IPAddress: "127.0.0.1", Success: true},
			{ID: 2, Event: "email_changed", IPAddress: "127.0.0.1", Success: true},
		},
		auditTotal: 2,
	}, nil)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/audit-log", func(c *gin.Context) {
		c.Set("user_id", uid)
		h.MyAuditLog(c)
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/audit-log?page=1&limit=20", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "email_changed") {
		t.Fatalf("expected event in response body: %s", w.Body.String())
	}
}

func TestHandler_MFA_GetMethods(t *testing.T) {
	uid := uint(1)
	h := NewMFAHandler(fakeTOTPService{}, nil, 0)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/methods", func(c *gin.Context) {
		c.Set("user_id", uid)
		h.GetMethods(c)
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/methods", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "totpEnabled") || !strings.Contains(w.Body.String(), "passkey") {
		t.Fatalf("expected methods payload in response: %s", w.Body.String())
	}
}
