package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/finnapigo/finnapigo/internal/jwt"
	"github.com/finnapigo/finnapigo/internal/middleware"
	"github.com/finnapigo/finnapigo/internal/services"
	"github.com/gin-gonic/gin"
)

type fakeAuthService struct {
	registerErr     error
	registerProfile services.UserProfile
	meErr           error
	setPasswordErr  error
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
func (f fakeAuthService) SetPassword(context.Context, uint, string, string) error {
	return f.setPasswordErr
}
func (f fakeAuthService) Me(context.Context, uint) (services.UserProfile, error) {
	return services.UserProfile{}, f.meErr
}
func (fakeAuthService) VerifyEmail(context.Context, services.EmailVerifyInput) error { return nil }
func (fakeAuthService) ResendVerifyEmail(context.Context, string, string) error      { return nil }
func (fakeAuthService) CompleteMFALogin(context.Context, services.CompleteMFALoginInput) (services.TokenPair, services.UserProfile, error) {
	return services.TokenPair{}, services.UserProfile{}, nil
}

type fakeTOTPService struct{ err error }

func (f fakeTOTPService) Enable(context.Context, uint, string, string) (string, string, error) {
	return "secret", "otpauth://test", f.err
}
func (f fakeTOTPService) VerifyEnable(context.Context, uint, string) ([]string, error) {
	return []string{"backup"}, f.err
}
func (f fakeTOTPService) Validate(context.Context, uint, string) error { return f.err }
func (f fakeTOTPService) ViewRecoveryCodes(context.Context, uint, string) ([]string, error) {
	return []string{"backup"}, f.err
}
func (f fakeTOTPService) RegenerateRecoveryCodes(context.Context, uint) ([]string, error) {
	return []string{"fresh"}, f.err
}

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
		{services.ErrInvalidCredentials, 401}, {services.ErrInvalidToken, 401}, {services.ErrInvalidCode, 401},
		{services.ErrAccountLocked, 403}, {services.ErrAccountDisabled, 403},
		{services.ErrEmailNotVerified, 403}, {services.ErrUserNotFound, 404}, {services.ErrSessionNotFound, 404},
		{services.ErrEmailExists, 409},
		{services.ErrUsernameExists, 409}, {services.ErrInvalidInput, 400}, {services.ErrPasswordTooWeak, 400},
		{services.ErrCaptchaRequired, 400}, {services.ErrDisposableEmail, 422}, {services.ErrRateLimited, 429}, {errors.New("unexpected"), 500},
		{services.ErrPasswordAlreadySet, 409},
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
	for _, h := range []gin.HandlerFunc{auth.Me, auth.ChangePassword, auth.SetPassword, auth.LogoutAll} {
		w := serve(t, h, `{}`, nil)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
	}
}

func TestSetPasswordHandler_BoundaryCases(t *testing.T) {
	uid := uint(1)
	for _, tc := range []struct {
		name, body string
		svc        fakeAuthService
		want       int
	}{
		{"malformed JSON", `{`, fakeAuthService{}, 400},
		{"weak password (binding)", `{"password":"short1"}`, fakeAuthService{}, 400},
		{"weak password (service)", `{"password":"Password123"}`, fakeAuthService{setPasswordErr: services.ErrPasswordTooWeak}, 400},
		{"already set (conflict)", `{"password":"Password123"}`, fakeAuthService{setPasswordErr: services.ErrPasswordAlreadySet}, 409},
		{"success", `{"password":"Password123"}`, fakeAuthService{}, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := serve(t, NewAuthHandler(tc.svc, nil).SetPassword, tc.body, &uid)
			if w.Code != tc.want {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), `"code"`) {
				t.Fatalf("not response envelope: %s", w.Body.String())
			}
		})
	}
}

// TestSetPassword_RequiresAccessToken proves the route is gated by the
// standard AuthMiddleware exactly like every other authenticated endpoint:
// a missing, invalid, or non-access token is rejected with 401 before the
// handler runs.
func TestSetPassword_RequiresAccessToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	jwtMgr := jwt.NewJWTManager("test-secret", "test-issuer")
	h := NewAuthHandler(fakeAuthService{}, nil)
	r := gin.New()
	r.POST("/set-password", middleware.AuthMiddleware(jwtMgr, nil), h.SetPassword)

	do := func(authHeader string) int {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/set-password",
			strings.NewReader(`{"password":"Password123"}`))
		if authHeader != "" {
			req.Header.Set("Authorization", authHeader)
		}
		r.ServeHTTP(w, req)
		return w.Code
	}

	if got := do(""); got != http.StatusUnauthorized {
		t.Fatalf("no token: status=%d", got)
	}
	if got := do("Bearer garbage"); got != http.StatusUnauthorized {
		t.Fatalf("invalid token: status=%d", got)
	}
	access, err := jwtMgr.Issue(7, "user", "gina@example.com", jwt.TokenTypeAccess, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if got := do("Bearer " + access); got != http.StatusOK {
		t.Fatalf("valid access token: status=%d body", got)
	}
	// A valid non-access token (e.g. reset) must still be refused.
	reset, err := jwtMgr.Issue(7, "user", "gina@example.com", jwt.TokenTypeReset, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if got := do("Bearer " + reset); got != http.StatusUnauthorized {
		t.Fatalf("reset token: status=%d", got)
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
		{"verify invalid", `{"code":"123456"}`, services.ErrInvalidCode, 401, func(h *MFAHandler) gin.HandlerFunc { return h.VerifyTOTP }},
		{"validate", `{"code":"123456"}`, nil, 200, func(h *MFAHandler) gin.HandlerFunc { return h.ValidateTOTP }},
		{"view malformed", "{", nil, 400, func(h *MFAHandler) gin.HandlerFunc { return h.ViewRecoveryCodes }},
		{"view invalid", `{"code":"123456"}`, services.ErrInvalidCode, 401, func(h *MFAHandler) gin.HandlerFunc { return h.ViewRecoveryCodes }},
		{"view", `{"code":"123456"}`, nil, 200, func(h *MFAHandler) gin.HandlerFunc { return h.ViewRecoveryCodes }},
		{"regenerate", "", nil, 200, func(h *MFAHandler) gin.HandlerFunc { return h.RegenerateRecoveryCodes }},
		{"regenerate invalid", "", services.ErrInvalidCode, 401, func(h *MFAHandler) gin.HandlerFunc { return h.RegenerateRecoveryCodes }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := NewMFAHandler(fakeTOTPService{err: tc.err}, nil, 0)
			w := serve(t, tc.handler(h), tc.body, &uid)
			if w.Code != tc.want {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
}

func TestTOTPHandlers_BodySizeGuard(t *testing.T) {
	uid := uint(1)
	h := NewMFAHandler(fakeTOTPService{}, nil, 0)

	// Body > 1 KiB should be rejected with 413.
	bigBody := `{"code":"` + strings.Repeat("A", 2048) + `"}`
	w := serve(t, h.ValidateTOTP, bigBody, &uid)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: status=%d body=%s", w.Code, w.Body.String())
	}
}

// TestTOTPHandlers_BodyExactlyAtLimit pins the off-by-one: a body of exactly
// maxTOTPBody bytes must NOT be rejected as oversized (only > the cap is).
// It fails validation later (code exceeds max=128), which still proves the
// size guard let it through.
func TestTOTPHandlers_BodyExactlyAtLimit(t *testing.T) {
	uid := uint(1)
	h := NewMFAHandler(fakeTOTPService{}, nil, 0)

	body := `{"code":"` + strings.Repeat("A", maxTOTPBody-len(`{"code":""}`)) + `"}`
	if len(body) != maxTOTPBody {
		t.Fatalf("test setup: body is %d bytes, want %d", len(body), maxTOTPBody)
	}
	w := serve(t, h.ValidateTOTP, body, &uid)
	if w.Code == http.StatusRequestEntityTooLarge {
		t.Fatalf("body exactly at the limit must not be 413: %s", w.Body.String())
	}
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 from validation, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestTOTPHandlers_EmptyBody(t *testing.T) {
	uid := uint(1)
	h := NewMFAHandler(fakeTOTPService{}, nil, 0)

	w := serve(t, h.ValidateTOTP, "", &uid)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("empty body: status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestTOTPHandlers_MissingAuth(t *testing.T) {
	h := NewMFAHandler(fakeTOTPService{}, nil, 0)
	for _, handler := range []gin.HandlerFunc{h.EnableTOTP, h.VerifyTOTP, h.ValidateTOTP, h.ViewRecoveryCodes, h.RegenerateRecoveryCodes} {
		w := serve(t, handler, `{}`, nil)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d body=%s", w.Code, w.Body.String())
		}
	}
}

func TestTOTPHandlers_RateLimited(t *testing.T) {
	uid := uint(1)
	h := NewMFAHandler(fakeTOTPService{err: services.ErrRateLimited}, nil, 0)
	w := serve(t, h.ValidateTOTP, `{"code":"123456"}`, &uid)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d body=%s", w.Code, w.Body.String())
	}
}

// ---------- Recovery-code endpoints (view + sudo, regenerate) ----------

func TestViewRecoveryCodes_HandlerIssuesSudoToken(t *testing.T) {
	uid := uint(1)
	jwtMgr := jwt.NewJWTManager("test-secret", "test-issuer")
	h := NewMFAHandler(fakeTOTPService{}, jwtMgr, 15*time.Minute)

	w := serve(t, h.ViewRecoveryCodes, `{"code":"123456"}`, &uid)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Data struct {
			RecoveryCodes    []string `json:"recoveryCodes"`
			SudoToken        string   `json:"sudoToken"`
			SudoExpiresInSec int      `json:"sudoExpiresInSec"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v (%s)", err, w.Body.String())
	}
	if len(resp.Data.RecoveryCodes) != 1 || resp.Data.RecoveryCodes[0] != "backup" {
		t.Fatalf("unexpected recovery codes: %v", resp.Data.RecoveryCodes)
	}
	if resp.Data.SudoExpiresInSec != 900 {
		t.Fatalf("sudoExpiresInSec = %d, want 900", resp.Data.SudoExpiresInSec)
	}
	claims, err := jwtMgr.Verify(resp.Data.SudoToken)
	if err != nil {
		t.Fatalf("minted sudo token should verify: %v", err)
	}
	if claims.Type != jwt.TokenTypeSudo {
		t.Fatalf("token type = %q, want %q", claims.Type, jwt.TokenTypeSudo)
	}
	if claims.UserID != uid {
		t.Fatalf("sudo token uid = %d, want %d", claims.UserID, uid)
	}
}

func TestViewRecoveryCodes_NoJWTManager_OmitsSudoToken(t *testing.T) {
	uid := uint(1)
	h := NewMFAHandler(fakeTOTPService{}, nil, 0)

	w := serve(t, h.ViewRecoveryCodes, `{"code":"123456"}`, &uid)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "sudoToken") {
		t.Fatalf("degraded mode should omit sudo token: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "recoveryCodes") {
		t.Fatalf("codes missing from response: %s", w.Body.String())
	}
}

func TestRegenerateRecoveryCodes_HandlerReturnsFreshSet(t *testing.T) {
	uid := uint(1)
	h := NewMFAHandler(fakeTOTPService{}, nil, 0)

	w := serve(t, h.RegenerateRecoveryCodes, "", &uid)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Data struct {
			RecoveryCodes []string `json:"recoveryCodes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v (%s)", err, w.Body.String())
	}
	if len(resp.Data.RecoveryCodes) != 1 || resp.Data.RecoveryCodes[0] != "fresh" {
		t.Fatalf("unexpected regenerated codes: %v", resp.Data.RecoveryCodes)
	}
}

// ---- fake session service ----

type fakeSessionService struct {
	sessions  []services.SessionInfo
	listErr   error
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
