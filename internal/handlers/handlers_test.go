package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/finnapigo/finnapigo/internal/services"
	"github.com/gin-gonic/gin"
)

type fakeAuthService struct {
	registerErr     error
	registerProfile services.UserProfile
	meErr           error
}

func (f fakeAuthService) Register(context.Context, services.RegisterInput) (services.UserProfile, error) {
	return f.registerProfile, f.registerErr
}
func (fakeAuthService) Login(context.Context, services.LoginInput, string, string) (services.TokenPair, services.UserProfile, *services.MFAPendingResult, error) {
	return services.TokenPair{}, services.UserProfile{}, nil, nil
}
func (fakeAuthService) Logout(context.Context, string, string) error  { return nil }
func (fakeAuthService) LogoutAll(context.Context, uint, string) error { return nil }
func (fakeAuthService) Refresh(context.Context, string, string, string) (services.TokenPair, error) {
	return services.TokenPair{}, nil
}
func (fakeAuthService) ForgotPassword(context.Context, string, string) error { return nil }
func (fakeAuthService) ResetPassword(context.Context, services.ResetPasswordInput, string) error {
	return nil
}
func (fakeAuthService) ChangePassword(context.Context, services.ChangePasswordInput, string) error {
	return nil
}
func (f fakeAuthService) Me(context.Context, uint) (services.UserProfile, error) {
	return services.UserProfile{}, f.meErr
}
func (fakeAuthService) VerifyEmail(context.Context, services.EmailVerifyInput) error { return nil }
func (fakeAuthService) ResendVerifyEmail(context.Context, string, string) error      { return nil }
func (fakeAuthService) CompleteMFALogin(context.Context, services.CompleteMFALoginInput) (services.TokenPair, services.UserProfile, error) {
	return services.TokenPair{}, services.UserProfile{}, nil
}

type fakeMFAService struct{ err error }

func (f fakeMFAService) SendOTP(context.Context, services.OTPSendInput, string) error { return f.err }
func (f fakeMFAService) VerifyOTP(context.Context, services.OTPVerifyInput, string) error {
	return f.err
}

type fakeTOTPService struct{ err error }

func (f fakeTOTPService) Enable(context.Context, uint, string) (string, string, error) {
	return "secret", "otpauth://test", f.err
}
func (f fakeTOTPService) VerifyEnable(context.Context, uint, string) ([]string, error) {
	return []string{"backup"}, f.err
}
func (f fakeTOTPService) Validate(context.Context, uint, string) error { return f.err }

func serve(t *testing.T, h gin.HandlerFunc, body string, userID *uint) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/", func(c *gin.Context) {
		if userID != nil {
			c.Set("user_id", *userID)
		}
		h(c)
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
	return w
}

func TestStatusForError(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
	}{
			{services.ErrInvalidCredentials, 401}, {services.ErrInvalidToken, 401}, {services.ErrInvalidOTP, 401},
			{services.ErrOTPMaxAttempts, 429}, {services.ErrAccountLocked, 403}, {services.ErrAccountDisabled, 403},
			{services.ErrEmailNotVerified, 403}, {services.ErrUserNotFound, 404}, {services.ErrSessionNotFound, 404},
			{services.ErrEmailExists, 409},
		{services.ErrUsernameExists, 409}, {services.ErrInvalidInput, 400}, {services.ErrPasswordTooWeak, 400},
		{services.ErrCaptchaRequired, 400}, {services.ErrDisposableEmail, 422}, {services.ErrRateLimited, 429}, {errors.New("unexpected"), 500},
	} {
		t.Run(tc.err.Error(), func(t *testing.T) {
			got, _ := statusForError(tc.err)
			if got != tc.status {
				t.Fatalf("status=%d want=%d", got, tc.status)
			}
		})
	}
}

func TestAuthHandlerBoundaryCases(t *testing.T) {
	valid := `{"username":"alice","email":"alice@example.com","password":"Password1!","fullName":"Alice"}`
	for _, tc := range []struct {
		name, body string
		svc        fakeAuthService
		want       int
	}{
		{"malformed JSON", `{`, fakeAuthService{}, 400},
		{"validation failure", `{}`, fakeAuthService{}, 400},
		{"service sentinel", valid, fakeAuthService{registerErr: services.ErrEmailExists}, 409},
		{"success", valid, fakeAuthService{registerProfile: services.UserProfile{ID: 1, Email: "alice@example.com"}}, 201},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := serve(t, NewAuthHandler(tc.svc, nil).Register, tc.body, nil)
			if w.Code != tc.want {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), `"code"`) {
				t.Fatalf("not response envelope: %s", w.Body.String())
			}
		})
	}
}

func TestProtectedHandlersRejectMissingIdentity(t *testing.T) {
	auth := NewAuthHandler(fakeAuthService{}, nil)
	mfa := NewMFAHandler(fakeMFAService{})
	for _, h := range []gin.HandlerFunc{auth.Me, auth.ChangePassword, auth.LogoutAll, mfa.SendOTP, mfa.VerifyOTP} {
		w := serve(t, h, `{}`, nil)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
	}
}

func TestMFAHandlerBoundaryCases(t *testing.T) {
	uid := uint(1)
	for _, tc := range []struct {
		name, body string
		err        error
		want       int
	}{
		{"malformed", `{`, nil, 400}, {"invalid purpose", `{"purpose":"bad"}`, nil, 400},
		{"rate limited", `{"purpose":"login"}`, services.ErrRateLimited, 429}, {"success", `{"purpose":"login"}`, nil, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := serve(t, NewMFAHandler(fakeMFAService{err: tc.err}).SendOTP, tc.body, &uid)
			if w.Code != tc.want {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
}

func TestTOTPHandlers(t *testing.T) {
	uid := uint(1)
	for _, tc := range []struct {
		name, body string
		err        error
		want       int
		handler    func(*MFAHandler) gin.HandlerFunc
	}{
		{"enable", "", nil, 200, func(h *MFAHandler) gin.HandlerFunc { return h.EnableTOTP }},
		{"verify malformed", "{", nil, 400, func(h *MFAHandler) gin.HandlerFunc { return h.VerifyTOTP }},
		{"verify invalid", `{"code":"123456"}`, services.ErrInvalidOTP, 401, func(h *MFAHandler) gin.HandlerFunc { return h.VerifyTOTP }},
		{"validate", `{"code":"123456"}`, nil, 200, func(h *MFAHandler) gin.HandlerFunc { return h.ValidateTOTP }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := NewMFAHandler(fakeMFAService{}, fakeTOTPService{err: tc.err})
			w := serve(t, tc.handler(h), tc.body, &uid)
			if w.Code != tc.want {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
}

func TestTOTPHandlers_BodySizeGuard(t *testing.T) {
	uid := uint(1)
	h := NewMFAHandler(fakeMFAService{}, fakeTOTPService{})

	// Body > 1 KiB should be rejected with 413.
	bigBody := `{"code":"` + strings.Repeat("A", 2048) + `"}`
	w := serve(t, h.ValidateTOTP, bigBody, &uid)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestTOTPHandlers_EmptyBody(t *testing.T) {
	uid := uint(1)
	h := NewMFAHandler(fakeMFAService{}, fakeTOTPService{})

	w := serve(t, h.ValidateTOTP, "", &uid)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("empty body: status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestTOTPHandlers_MissingAuth(t *testing.T) {
	h := NewMFAHandler(fakeMFAService{}, fakeTOTPService{})
	for _, handler := range []gin.HandlerFunc{h.EnableTOTP, h.VerifyTOTP, h.ValidateTOTP} {
		w := serve(t, handler, `{}`, nil)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d body=%s", w.Code, w.Body.String())
		}
	}
}

func TestTOTPHandlers_RateLimited(t *testing.T) {
	uid := uint(1)
	h := NewMFAHandler(fakeMFAService{}, fakeTOTPService{err: services.ErrRateLimited})
	w := serve(t, h.ValidateTOTP, `{"code":"123456"}`, &uid)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d body=%s", w.Code, w.Body.String())
	}
}

// ---- fake session service ----

type fakeSessionService struct {
	sessions []services.SessionInfo
	listErr  error
	revokeErr error
}

func (f *fakeSessionService) ListSessions(_ context.Context, _ uint) ([]services.SessionInfo, error) {
	return f.sessions, f.listErr
}
func (f *fakeSessionService) RevokeSession(_ context.Context, _, _ uint, _ string) error {
	return f.revokeErr
}

// ---- serve helper for GET/DELETE ----

func serveGET(t *testing.T, h gin.HandlerFunc, userID *uint) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/test", func(c *gin.Context) {
		if userID != nil {
			c.Set("user_id", *userID)
		}
		h(c)
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/test", nil))
	return w
}

func serveDELETE(t *testing.T, path string, h gin.HandlerFunc, userID *uint) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	// The route must declare the :id param (like the real router) so
	// c.Param("id") is populated; `path` is the requested URL.
	r.DELETE("/sessions/:id", func(c *gin.Context) {
		if userID != nil {
			c.Set("user_id", *userID)
		}
		h(c)
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, path, nil))
	return w
}

// ---- session handler tests ----

func TestSessionHandler_List(t *testing.T) {
	uid := uint(1)
	sessions := []services.SessionInfo{
		{ID: 1, DeviceName: "Chrome on Windows", IPAddress: "1.2.3.4"},
		{ID: 2, DeviceName: "Safari on iPhone", IPAddress: "5.6.7.8"},
	}
	h := NewSessionHandler(&fakeSessionService{sessions: sessions})
	w := serveGET(t, h.List, &uid)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"sessions"`) {
		t.Fatalf("expected 'sessions' key in body: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"code"`) {
		t.Fatalf("not response envelope: %s", w.Body.String())
	}
}

func TestSessionHandler_List_Unauthenticated(t *testing.T) {
	h := NewSessionHandler(&fakeSessionService{})
	w := serveGET(t, h.List, nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestSessionHandler_Revoke(t *testing.T) {
	uid := uint(1)
	h := NewSessionHandler(&fakeSessionService{})
	w := serveDELETE(t, "/sessions/42", h.Revoke, &uid)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "session revoked") {
		t.Fatalf("unexpected body: %s", w.Body.String())
	}
}

func TestSessionHandler_Revoke_Unauthenticated(t *testing.T) {
	h := NewSessionHandler(&fakeSessionService{})
	w := serveDELETE(t, "/sessions/42", h.Revoke, nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestSessionHandler_Revoke_InvalidID(t *testing.T) {
	uid := uint(1)
	h := NewSessionHandler(&fakeSessionService{})
	// Cases the real router can route to the handler with a bad :id value.
	for _, tc := range []struct {
		name, path string
	}{
		{"zero", "/sessions/0"},
		{"non-numeric", "/sessions/abc"},
		{"negative", "/sessions/-1"},
		{"overflow", "/sessions/99999999999999999999999"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := serveDELETE(t, tc.path, h.Revoke, &uid)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d body=%s", w.Code, w.Body.String())
			}
		})
	}
}

// TestParseSessionID covers the parser directly, including the empty-param
// branch that the router normally short-circuits before the handler runs.
func TestParseSessionID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cases := []struct {
		name string
		id   string
		want uint
		ok   bool
	}{
		{"valid", "42", 42, true},
		{"empty", "", 0, false},
		{"zero", "0", 0, false},
		{"alpha", "abc", 0, false},
		{"negative", "-1", 0, false},
		{"mixed", "4a2", 0, false},
		{"overflow", "99999999999999999999999", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := gin.New()
			var got uint
			var gotOK bool
			r.DELETE("/sessions/:id", func(c *gin.Context) {
				got, gotOK = parseSessionID(c)
			})
			w := httptest.NewRecorder()
			path := "/sessions/" + tc.id
			if tc.id == "" {
				path = "/sessions/%20" // reachable stand-in for an empty param
			}
			r.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, path, nil))
			// For the empty case the router may not invoke the handler at all;
			// parseSessionID("") is verified directly below.
			if tc.id != "" && (got != tc.want || gotOK != tc.ok) {
				t.Fatalf("parseSessionID(%q) = (%d,%v), want (%d,%v)", tc.id, got, gotOK, tc.want, tc.ok)
			}
		})
	}
	// Direct call for the truly-empty param (router normally blocks it).
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Params = gin.Params{{Key: "id", Value: ""}}
	if id, ok := parseSessionID(c); ok || id != 0 {
		t.Fatalf("parseSessionID(empty) = (%d,%v), want (0,false)", id, ok)
	}
}

func TestSessionHandler_Revoke_NotFound(t *testing.T) {
	uid := uint(1)
	h := NewSessionHandler(&fakeSessionService{revokeErr: services.ErrSessionNotFound})
	w := serveDELETE(t, "/sessions/999", h.Revoke, &uid)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestProtectedHandlersRejectMissingIdentity_IncludesSessions(t *testing.T) {
	auth := NewAuthHandler(fakeAuthService{}, nil)
	sess := NewSessionHandler(&fakeSessionService{})
	for _, h := range []gin.HandlerFunc{auth.Me, auth.ChangePassword, auth.LogoutAll, sess.List, sess.Revoke} {
		// List is GET, Revoke is DELETE — use a generic route.
		gin.SetMode(gin.TestMode)
		r := gin.New()
		r.Any("/test", func(c *gin.Context) {
			h(c)
		})
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/test", nil))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
	}
}
