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
func (fakeAuthService) Login(context.Context, services.LoginInput, string, string) (services.TokenPair, services.UserProfile, error) {
	return services.TokenPair{}, services.UserProfile{}, nil
}
func (fakeAuthService) Logout(context.Context, string, string) error  { return nil }
func (fakeAuthService) LogoutAll(context.Context, uint, string) error { return nil }
func (fakeAuthService) Refresh(context.Context, string, string) (services.TokenPair, error) {
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
		{services.ErrEmailNotVerified, 403}, {services.ErrUserNotFound, 404}, {services.ErrEmailExists, 409},
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
