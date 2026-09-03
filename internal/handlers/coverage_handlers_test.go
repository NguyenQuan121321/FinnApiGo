package handlers

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
	"github.com/gin-gonic/gin"
)

// mockFullAuthService extends fakeAuthService for detailed branch coverage
type mockFullAuthService struct {
	fakeAuthService
	loginTokens  services.TokenPair
	loginProfile services.UserProfile
	loginPending *services.MFAPendingResult
	loginErr     error

	mfaTokens  services.TokenPair
	mfaProfile services.UserProfile
	mfaErr     error

	logoutErr      error
	logoutAllErr   error
	refreshTokens  services.TokenPair
	refreshErr     error
	forgotErr      error
	resetErr       error
	changePwdErr   error
	verifyEmailErr error
	resendEmailErr error
	reqEmailErr    error
	confEmailErr   error
	deactErr       error
	eraseErr       error
}

func (m mockFullAuthService) Login(context.Context, services.LoginInput, string, string) (services.TokenPair, services.UserProfile, *services.MFAPendingResult, error) {
	return m.loginTokens, m.loginProfile, m.loginPending, m.loginErr
}
func (m mockFullAuthService) CompleteMFALogin(context.Context, services.CompleteMFALoginInput) (services.TokenPair, services.UserProfile, error) {
	return m.mfaTokens, m.mfaProfile, m.mfaErr
}
func (m mockFullAuthService) Logout(context.Context, string, string, string) error {
	return m.logoutErr
}
func (m mockFullAuthService) LogoutAll(context.Context, uint, string) error {
	return m.logoutAllErr
}
func (m mockFullAuthService) Refresh(context.Context, string, string, string) (services.TokenPair, error) {
	return m.refreshTokens, m.refreshErr
}
func (m mockFullAuthService) ForgotPassword(context.Context, string, string) error {
	return m.forgotErr
}
func (m mockFullAuthService) ResetPassword(context.Context, services.ResetPasswordInput, string) error {
	return m.resetErr
}
func (m mockFullAuthService) ChangePassword(context.Context, services.ChangePasswordInput, string) error {
	return m.changePwdErr
}
func (m mockFullAuthService) VerifyEmail(context.Context, services.EmailVerifyInput) error {
	return m.verifyEmailErr
}
func (m mockFullAuthService) ResendVerifyEmail(context.Context, string, string) error {
	return m.resendEmailErr
}
func (m mockFullAuthService) RequestChangeEmail(context.Context, uint, services.ChangeEmailRequestInput, string) error {
	return m.reqEmailErr
}
func (m mockFullAuthService) ConfirmChangeEmail(context.Context, string, string) error {
	return m.confEmailErr
}
func (m mockFullAuthService) DeactivateAccount(context.Context, uint, string, string, string, string) error {
	return m.deactErr
}
func (m mockFullAuthService) EraseAccount(context.Context, uint, string, string, string, string) error {
	return m.eraseErr
}

// mockPasskeyService implements services.PasskeyService for handlers unit testing
type mockPasskeyService struct {
	beginRegResult  any
	beginRegErr     error
	finishRegResult *models.PasskeyCredential
	finishRegErr    error
	beginAuthResult any
	beginAuthErr    error
	finishAuthRes   *services.PasskeyAuthResult
	finishAuthErr   error
	listResult      []models.PasskeyCredential
	listErr         error
	revokeErr       error
}

func (m mockPasskeyService) BeginRegistration(context.Context, uint, services.PasskeyBeginInput) (any, error) {
	return m.beginRegResult, m.beginRegErr
}
func (m mockPasskeyService) FinishRegistration(context.Context, uint, *http.Request) (*models.PasskeyCredential, error) {
	return m.finishRegResult, m.finishRegErr
}
func (m mockPasskeyService) BeginAuthentication(context.Context, uint) (any, error) {
	return m.beginAuthResult, m.beginAuthErr
}
func (m mockPasskeyService) FinishAuthentication(context.Context, uint, *http.Request) (*services.PasskeyAuthResult, error) {
	return m.finishAuthRes, m.finishAuthErr
}
func (m mockPasskeyService) List(context.Context, uint) ([]models.PasskeyCredential, error) {
	return m.listResult, m.listErr
}
func (m mockPasskeyService) Revoke(context.Context, uint, uint) error {
	return m.revokeErr
}

// mockOAuthService implements OAuthService for unit testing
type mockOAuthService struct {
	beginState string
	beginURL   string
	beginErr   error

	cbTokens  services.TokenPair
	cbProfile services.UserProfile
	cbPending *services.MFAPendingResult
	cbErr     error

	unlinkErr error
}

func (m mockOAuthService) BeginLogin(context.Context) (string, string, error) {
	return m.beginState, m.beginURL, m.beginErr
}
func (m mockOAuthService) HandleCallback(context.Context, string, string, string, string) (services.TokenPair, services.UserProfile, *services.MFAPendingResult, error) {
	return m.cbTokens, m.cbProfile, m.cbPending, m.cbErr
}
func (m mockOAuthService) Unlink(context.Context, uint, string, string) error {
	return m.unlinkErr
}

// Helper to execute GET requests
func serveGetHelper(t *testing.T, h gin.HandlerFunc, query string, userID *uint) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/", func(c *gin.Context) {
		if userID != nil {
			c.Set("user_id", *userID)
		}
		h(c)
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/"+query, nil))
	return w
}

// Helper to execute DELETE requests
func serveDeleteHelper(t *testing.T, h gin.HandlerFunc, pathPattern, reqPath string, userID *uint) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.DELETE(pathPattern, func(c *gin.Context) {
		if userID != nil {
			c.Set("user_id", *userID)
		}
		h(c)
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, reqPath, nil))
	return w
}

func TestAuthHandler_CoreFlows(t *testing.T) {
	uid := uint(42)

	// 1. Login
	t.Run("Login branches", func(t *testing.T) {
		// Bad JSON
		w := serve(t, NewAuthHandler(mockFullAuthService{}, nil).Login, "{bad", nil)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}

		// Validation error
		w = serve(t, NewAuthHandler(mockFullAuthService{}, nil).Login, `{"email":""}`, nil)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}

		// Service error
		svcErr := mockFullAuthService{loginErr: services.ErrInvalidCredentials}
		w = serve(t, NewAuthHandler(svcErr, nil).Login, `{"email":"a@b.com","password":"pwd"}`, nil)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}

		// MFA Pending
		svcMFA := mockFullAuthService{loginPending: &services.MFAPendingResult{MFARequired: true, MFAToken: "mfa-tok"}}
		w = serve(t, NewAuthHandler(svcMFA, nil).Login, `{"email":"a@b.com","password":"pwd"}`, nil)
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "mfa-tok") {
			t.Fatalf("expected 200 mfa-tok, got %d: %s", w.Code, w.Body.String())
		}

		// Success login
		svcOK := mockFullAuthService{loginTokens: services.TokenPair{AccessToken: "acc", RefreshToken: "ref"}}
		w = serve(t, NewAuthHandler(svcOK, nil).Login, `{"email":"a@b.com","password":"pwd"}`, nil)
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "acc") {
			t.Fatalf("expected 200 ok, got %d: %s", w.Code, w.Body.String())
		}
	})

	// 2. CompleteMFALogin
	t.Run("CompleteMFALogin branches", func(t *testing.T) {
		w := serve(t, NewAuthHandler(mockFullAuthService{}, nil).CompleteMFALogin, "{}", nil)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}

		w = serve(t, NewAuthHandler(mockFullAuthService{}, nil).CompleteMFALogin, "{bad", &uid)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}

		w = serve(t, NewAuthHandler(mockFullAuthService{}, nil).CompleteMFALogin, `{"code":""}`, &uid)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}

		svcOK := mockFullAuthService{mfaTokens: services.TokenPair{AccessToken: "mfa-acc"}}
		w = serve(t, NewAuthHandler(svcOK, nil).CompleteMFALogin, `{"code":"123456"}`, &uid)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	// 3. Logout & LogoutAll
	t.Run("Logout branches", func(t *testing.T) {
		w := serve(t, NewAuthHandler(mockFullAuthService{}, nil).Logout, "{bad", nil)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}

		w = serve(t, NewAuthHandler(mockFullAuthService{}, nil).Logout, `{"refreshToken":"ref"}`, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}

		// LogoutAll
		w = serve(t, NewAuthHandler(mockFullAuthService{}, nil).LogoutAll, `{}`, nil)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for no user_id, got %d", w.Code)
		}

		w = serve(t, NewAuthHandler(mockFullAuthService{}, nil).LogoutAll, `{}`, &uid)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	// 4. Refresh
	t.Run("Refresh branches", func(t *testing.T) {
		w := serve(t, NewAuthHandler(mockFullAuthService{}, nil).Refresh, "{bad", nil)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}

		w = serve(t, NewAuthHandler(mockFullAuthService{}, nil).Refresh, `{"refreshToken":""}`, nil)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}

		svcErr := mockFullAuthService{refreshErr: services.ErrInvalidToken}
		w = serve(t, NewAuthHandler(svcErr, nil).Refresh, `{"refreshToken":"tok"}`, nil)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}

		svcOK := mockFullAuthService{refreshTokens: services.TokenPair{AccessToken: "new-acc"}}
		w = serve(t, NewAuthHandler(svcOK, nil).Refresh, `{"refreshToken":"tok"}`, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	// 5. Password recovery & verification
	t.Run("Forgot, Reset, VerifyEmail, Resend", func(t *testing.T) {
		// ForgotPassword
		w := serve(t, NewAuthHandler(mockFullAuthService{}, nil).ForgotPassword, "{bad", nil)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
		w = serve(t, NewAuthHandler(mockFullAuthService{}, nil).ForgotPassword, `{"email":"a@b.com"}`, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}

		// ResetPassword
		w = serve(t, NewAuthHandler(mockFullAuthService{}, nil).ResetPassword, "{bad", nil)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
		w = serve(t, NewAuthHandler(mockFullAuthService{}, nil).ResetPassword, `{"token":"tok","newPassword":"Password1!"}`, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}

		// VerifyEmail
		w = serve(t, NewAuthHandler(mockFullAuthService{}, nil).VerifyEmail, "{bad", nil)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
		w = serve(t, NewAuthHandler(mockFullAuthService{}, nil).VerifyEmail, `{"token":"tok"}`, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}

		// ResendVerifyEmail
		w = serve(t, NewAuthHandler(mockFullAuthService{}, nil).ResendVerifyEmail, "{bad", nil)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
		w = serve(t, NewAuthHandler(mockFullAuthService{}, nil).ResendVerifyEmail, `{"email":"a@b.com"}`, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})
}

func TestOAuthHandler_Coverage(t *testing.T) {
	uid := uint(42)

	// 1. GoogleLogin
	t.Run("GoogleLogin", func(t *testing.T) {
		// Service error
		sErr := mockOAuthService{beginErr: errors.New("fail")}
		w := serveGetHelper(t, NewOAuthHandler(sErr).GoogleLogin, "", nil)
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d", w.Code)
		}

		// Not configured
		sNotCfg := mockOAuthService{beginURL: ""}
		w = serveGetHelper(t, NewOAuthHandler(sNotCfg).GoogleLogin, "", nil)
		if w.Code != http.StatusNotImplemented {
			t.Fatalf("expected 501, got %d", w.Code)
		}

		// Success 302 redirect
		sOK := mockOAuthService{beginState: "state123", beginURL: "https://accounts.google.com/o/oauth2"}
		w = serveGetHelper(t, NewOAuthHandler(sOK).GoogleLogin, "", nil)
		if w.Code != http.StatusFound {
			t.Fatalf("expected 302, got %d", w.Code)
		}
	})

	// 2. GoogleCallback
	t.Run("GoogleCallback", func(t *testing.T) {
		h := NewOAuthHandler(mockOAuthService{})

		// Missing code/state
		w := serveGetHelper(t, h.GoogleCallback, "?code=c", nil)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 on missing state, got %d", w.Code)
		}

		// Cookie mismatch
		r := gin.New()
		r.GET("/callback", h.GoogleCallback)
		w = httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/callback?code=c&state=stateX", nil)
		req.AddCookie(&http.Cookie{Name: OAuthStateCookie, Value: "stateY"})
		r.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 on cookie mismatch, got %d", w.Code)
		}

		// Success callback
		sOK := mockOAuthService{cbTokens: services.TokenPair{AccessToken: "oauth-acc"}}
		hOK := NewOAuthHandler(sOK)
		r = gin.New()
		r.GET("/callback", hOK.GoogleCallback)
		w = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodGet, "/callback?code=c&state=stateX", nil)
		req.AddCookie(&http.Cookie{Name: OAuthStateCookie, Value: "stateX"})
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	// 3. Unlink
	t.Run("Unlink", func(t *testing.T) {
		h := NewOAuthHandler(mockOAuthService{})
		w := serveDeleteHelper(t, h.Unlink, "/:provider", "/google", nil)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}

		w = serveDeleteHelper(t, h.Unlink, "/:provider", "/google", &uid)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})
}

func TestPasskeyHandler_Coverage(t *testing.T) {
	uid := uint(42)

	// 1. BeginRegistration
	t.Run("BeginRegistration", func(t *testing.T) {
		h := NewPasskeyHandler(mockPasskeyService{beginRegResult: map[string]any{"challenge": "c"}})
		w := serve(t, h.BeginRegistration, `{}`, nil)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}

		w = serve(t, h.BeginRegistration, `{}`, &uid)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	// 2. FinishRegistration
	t.Run("FinishRegistration", func(t *testing.T) {
		h := NewPasskeyHandler(mockPasskeyService{finishRegResult: &models.PasskeyCredential{ID: 1}})
		w := serve(t, h.FinishRegistration, `{}`, nil)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}

		w = serve(t, h.FinishRegistration, `{}`, &uid)
		if w.Code != http.StatusCreated {
			t.Fatalf("expected 201, got %d", w.Code)
		}
	})

	// 3. BeginAuthentication
	t.Run("BeginAuthentication", func(t *testing.T) {
		h := NewPasskeyHandler(mockPasskeyService{beginAuthResult: map[string]any{"challenge": "c"}})
		w := serve(t, h.BeginAuthentication, `{}`, nil)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}

		w = serve(t, h.BeginAuthentication, `{}`, &uid)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	// 4. FinishAuthentication
	t.Run("FinishAuthentication", func(t *testing.T) {
		h := NewPasskeyHandler(mockPasskeyService{finishAuthRes: &services.PasskeyAuthResult{TokenPair: services.TokenPair{AccessToken: "pk-acc"}}})
		w := serve(t, h.FinishAuthentication, `{}`, nil)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}

		w = serve(t, h.FinishAuthentication, `{}`, &uid)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	// 5. List
	t.Run("List", func(t *testing.T) {
		h := NewPasskeyHandler(mockPasskeyService{listResult: []models.PasskeyCredential{}})
		w := serveGetHelper(t, h.List, "", nil)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}

		w = serveGetHelper(t, h.List, "", &uid)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	// 6. Revoke
	t.Run("Revoke", func(t *testing.T) {
		h := NewPasskeyHandler(mockPasskeyService{})
		w := serveDeleteHelper(t, h.Revoke, "/:id", "/invalid-id", &uid)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 on bad id, got %d", w.Code)
		}

		w = serveDeleteHelper(t, h.Revoke, "/:id", "/123", nil)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}

		w = serveDeleteHelper(t, h.Revoke, "/:id", "/123", &uid)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})
}

func TestAuthHandler_ChangePassword_And_Me(t *testing.T) {
	uid := uint(42)

	// ChangePassword
	// 1. Bad JSON
	w := serve(t, NewAuthHandler(mockFullAuthService{}, nil).ChangePassword, "{bad", &uid)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	// 2. Service error
	svcErr := mockFullAuthService{changePwdErr: services.ErrInvalidCredentials}
	w = serve(t, NewAuthHandler(svcErr, nil).ChangePassword, `{"oldPassword":"old","newPassword":"NewPassword1!"}`, &uid)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}

	// 3. Success
	w = serve(t, NewAuthHandler(mockFullAuthService{}, nil).ChangePassword, `{"oldPassword":"old","newPassword":"NewPassword1!"}`, &uid)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// Me
	// 1. Service error
	svcMeErr := mockFullAuthService{fakeAuthService: fakeAuthService{meErr: services.ErrUserNotFound}}
	w = serveGetHelper(t, NewAuthHandler(svcMeErr, nil).Me, "", &uid)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}

	// 2. Success
	w = serveGetHelper(t, NewAuthHandler(mockFullAuthService{}, nil).Me, "", &uid)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

type mockAdminServiceForHandlers struct {
	listUsersErr   error
	lockUserErr    error
	unlockUserErr  error
	forceLogoutErr error
	listSessErr    error
	exportAuditErr error
}

func (m mockAdminServiceForHandlers) ListUsers(context.Context, int, int, string) ([]services.UserProfile, int64, error) {
	return []services.UserProfile{{ID: 1}}, 1, m.listUsersErr
}
func (m mockAdminServiceForHandlers) LockUser(context.Context, uint, uint, time.Duration, string) error {
	return m.lockUserErr
}
func (m mockAdminServiceForHandlers) UnlockUser(context.Context, uint, uint, string) error {
	return m.unlockUserErr
}
func (m mockAdminServiceForHandlers) ForceLogout(context.Context, uint, uint, string) error {
	return m.forceLogoutErr
}
func (m mockAdminServiceForHandlers) ListTenantSessions(context.Context) ([]services.SessionInfo, error) {
	return []services.SessionInfo{{ID: "sess"}}, m.listSessErr
}
func (m mockAdminServiceForHandlers) ExportAuditLogs(context.Context, string) ([]byte, string, error) {
	if m.exportAuditErr != nil {
		return nil, "", m.exportAuditErr
	}
	return []byte("id,user\n1,alice"), "text/csv", nil
}

func TestAdminHandler_Branches(t *testing.T) {
	uid := uint(1)
	adm := NewAdminHandler(mockAdminServiceForHandlers{})

	// 1. ListUsers
	w := serveGetHelper(t, adm.ListUsers, "?page=2&limit=50&search=test", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// 2. LockUser
	// Unauthorized
	r := gin.New()
	r.POST("/lock/:id", adm.LockUser)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/lock/10", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}

	// Bad ID
	r = gin.New()
	r.POST("/lock/:id", func(c *gin.Context) { c.Set("user_id", uid); adm.LockUser(c) })
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/lock/invalid-id", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	// Success Lock
	w = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/lock/10", strings.NewReader(`{"durationSeconds":3600}`))
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// 3. UnlockUser
	r = gin.New()
	r.POST("/unlock/:id", func(c *gin.Context) { c.Set("user_id", uid); adm.UnlockUser(c) })
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/unlock/invalid-id", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/unlock/10", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// 4. ForceLogout
	r = gin.New()
	r.POST("/logout/:id", func(c *gin.Context) { c.Set("user_id", uid); adm.ForceLogout(c) })
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/logout/invalid-id", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/logout/10", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// 5. ListSessions
	w = serveGetHelper(t, adm.ListSessions, "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// 6. ExportAuditLog
	w = serveGetHelper(t, adm.ExportAuditLog, "?format=csv", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

type mockTrustedDeviceServiceForHandlers struct {
	listErr   error
	revokeErr error
}

func (m mockTrustedDeviceServiceForHandlers) Issue(context.Context, uint, string, string) (string, *models.TrustedDevice, error) {
	return "", nil, nil
}
func (m mockTrustedDeviceServiceForHandlers) Validate(context.Context, uint, string) (bool, error) {
	return true, nil
}
func (m mockTrustedDeviceServiceForHandlers) ListByUser(context.Context, uint) ([]services.TrustedDeviceInfo, error) {
	return []services.TrustedDeviceInfo{{ID: 1}}, m.listErr
}
func (m mockTrustedDeviceServiceForHandlers) Revoke(context.Context, uint, uint) error {
	return m.revokeErr
}

func TestTrustedDeviceHandler_Branches(t *testing.T) {
	uid := uint(42)
	h := NewTrustedDeviceHandler(mockTrustedDeviceServiceForHandlers{})

	// ListDevices unauthorized
	w := serveGetHelper(t, h.ListDevices, "", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}

	// ListDevices success
	w = serveGetHelper(t, h.ListDevices, "", &uid)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// RevokeDevice unauthorized
	w = serveDeleteHelper(t, h.RevokeDevice, "/:id", "/1", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}

	// RevokeDevice bad id
	w = serveDeleteHelper(t, h.RevokeDevice, "/:id", "/bad-id", &uid)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	// RevokeDevice success
	w = serveDeleteHelper(t, h.RevokeDevice, "/:id", "/1", &uid)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

type mockWebhookServiceForHandlers struct {
	registerErr error
}

func (m mockWebhookServiceForHandlers) ValidateURL(string) error { return nil }
func (m mockWebhookServiceForHandlers) RegisterEndpoint(context.Context, string, string, string) (*models.WebhookEndpoint, error) {
	if m.registerErr != nil {
		return nil, m.registerErr
	}
	return &models.WebhookEndpoint{ID: "ep-1"}, nil
}
func (m mockWebhookServiceForHandlers) EnqueueEvent(context.Context, string, string, any) error {
	return nil
}

func TestWebhookHandler_Branches(t *testing.T) {
	h := NewWebhookHandler(mockWebhookServiceForHandlers{})

	// Bad JSON
	w := serve(t, h.CreateEndpoint, "{bad", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	// Service error
	hErr := NewWebhookHandler(mockWebhookServiceForHandlers{registerErr: services.ErrWebhookSSRFBlocked})
	w = serve(t, hErr.CreateEndpoint, `{"url":"http://restricted.local","events":"user.created"}`, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid url, got %d", w.Code)
	}

	// Success
	w = serve(t, h.CreateEndpoint, `{"url":"https://example.com/webhook","events":"user.created"}`, nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}
}

func TestExhaustiveBranchCoverage(t *testing.T) {
	uid := uint(42)

	// 1. AdminHandler error paths
	admErr := NewAdminHandler(mockAdminServiceForHandlers{
		unlockUserErr:  errors.New("db fail"),
		forceLogoutErr: errors.New("db fail"),
		listSessErr:    errors.New("db fail"),
		exportAuditErr: errors.New("db fail"),
	})

	// UnlockUser unauthorized
	w := serve(t, admErr.UnlockUser, "", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	// UnlockUser service error
	r := gin.New()
	r.POST("/unlock/:id", func(c *gin.Context) { c.Set("user_id", uid); admErr.UnlockUser(c) })
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/unlock/10", nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}

	// ForceLogout unauthorized
	w = serve(t, admErr.ForceLogout, "", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	// ForceLogout service error
	r = gin.New()
	r.POST("/logout/:id", func(c *gin.Context) { c.Set("user_id", uid); admErr.ForceLogout(c) })
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/logout/10", nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}

	// ListSessions error
	w = serveGetHelper(t, admErr.ListSessions, "", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}

	// ExportAuditLog ndjson format + error
	w = serveGetHelper(t, NewAdminHandler(mockAdminServiceForHandlers{}).ExportAuditLog, "?format=ndjson", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	w = serveGetHelper(t, admErr.ExportAuditLog, "?format=csv", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}

	// 2. TrustedDeviceHandler error paths
	tdErr := NewTrustedDeviceHandler(mockTrustedDeviceServiceForHandlers{
		listErr:   errors.New("db error"),
		revokeErr: errors.New("db error"),
	})
	w = serveGetHelper(t, tdErr.ListDevices, "", &uid)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
	w = serveDeleteHelper(t, tdErr.RevokeDevice, "/:id", "/1", &uid)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}

	// 3. PasskeyHandler error paths
	pkBeginErr := NewPasskeyHandler(mockPasskeyService{beginRegErr: errors.New("fail")})
	w = serve(t, pkBeginErr.BeginRegistration, `{}`, &uid)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}

	pkFinErr := NewPasskeyHandler(mockPasskeyService{finishRegErr: errors.New("fail")})
	w = serve(t, pkFinErr.FinishRegistration, `{}`, &uid)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}

	pkAuthChallengeErr := NewPasskeyHandler(mockPasskeyService{finishAuthErr: services.ErrPasskeyChallenge})
	w = serve(t, pkAuthChallengeErr.FinishAuthentication, `{}`, &uid)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}

	pkAuthRevokedErr := NewPasskeyHandler(mockPasskeyService{finishAuthErr: services.ErrPasskeyCredentialRevoked})
	w = serve(t, pkAuthRevokedErr.FinishAuthentication, `{}`, &uid)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}

	pkListErr := NewPasskeyHandler(mockPasskeyService{listErr: errors.New("fail")})
	w = serveGetHelper(t, pkListErr.List, "", &uid)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}

	pkRevokeErr := NewPasskeyHandler(mockPasskeyService{revokeErr: errors.New("fail")})
	w = serveDeleteHelper(t, pkRevokeErr.Revoke, "/:id", "/123", &uid)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}

	// 4. AuthHandler error paths
	authErrSvc := mockFullAuthService{
		logoutErr:      errors.New("db error"),
		logoutAllErr:   errors.New("db error"),
		resetErr:       services.ErrInvalidToken,
		verifyEmailErr: services.ErrInvalidToken,
		resendEmailErr: services.ErrRateLimited,
		reqEmailErr:    errors.New("db error"),
		deactErr:       errors.New("db error"),
		eraseErr:       errors.New("db error"),
	}
	authErr := NewAuthHandler(authErrSvc, nil)

	w = serve(t, authErr.Logout, `{"refreshToken":"tok"}`, nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}

	w = serve(t, authErr.LogoutAll, `{}`, &uid)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}

	w = serve(t, authErr.ResetPassword, `{"token":"tok","newPassword":"Password1!"}`, nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}

	w = serve(t, authErr.VerifyEmail, `{"token":"tok"}`, nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}

	w = serve(t, authErr.ResendVerifyEmail, `{"email":"a@b.com"}`, nil)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", w.Code)
	}

	// RequestChangeEmail unauthorized + error
	w = serve(t, authErr.RequestChangeEmail, `{"newEmail":"new@b.com"}`, nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	w = serve(t, authErr.RequestChangeEmail, `{"newEmail":"new@b.com","password":"pwd"}`, &uid)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}

	// DeactivateAccount unauthorized + error
	w = serve(t, authErr.DeactivateAccount, `{"password":"pwd"}`, nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	w = serve(t, authErr.DeactivateAccount, `{"password":"pwd"}`, &uid)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}

	// EraseMe unauthorized + error
	w = serveDeleteHelper(t, authErr.EraseMe, "/me", "/me", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	w = serveDeleteHelper(t, authErr.EraseMe, "/me", "/me", &uid)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}

	// MyAuditLog unauthorized
	w = serveGetHelper(t, authErr.MyAuditLog, "", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

type mockSessionServiceForHandlers struct {
	listErr   error
	revokeErr error
}

func (m mockSessionServiceForHandlers) ListSessions(context.Context, uint, string) ([]services.SessionInfo, error) {
	return []services.SessionInfo{{ID: "sess-1"}}, m.listErr
}
func (m mockSessionServiceForHandlers) RevokeSession(context.Context, string, uint, string) error {
	return m.revokeErr
}

func TestSessionHandler_Branches(t *testing.T) {
	uid := uint(42)
	sOK := NewSessionHandler(mockSessionServiceForHandlers{})
	sErr := NewSessionHandler(mockSessionServiceForHandlers{listErr: errors.New("fail"), revokeErr: errors.New("fail")})

	// List unauthorized
	w := serveGetHelper(t, sOK.List, "", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	// List service error
	w = serveGetHelper(t, sErr.List, "", &uid)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
	// List success
	w = serveGetHelper(t, sOK.List, "", &uid)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// Revoke unauthorized
	w = serveDeleteHelper(t, sOK.Revoke, "/:id", "/sess-1", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	// Revoke bad ID (>64 chars)
	badID := strings.Repeat("x", 65)
	w = serveDeleteHelper(t, sOK.Revoke, "/:id", "/"+badID, &uid)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on long id, got %d", w.Code)
	}
	// Revoke service error
	w = serveDeleteHelper(t, sErr.Revoke, "/:id", "/sess-1", &uid)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
	// Revoke success
	w = serveDeleteHelper(t, sOK.Revoke, "/:id", "/sess-1", &uid)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestMFAHandler_ErrorBranches(t *testing.T) {
	uid := uint(42)
	totpErr := fakeTOTPService{err: errors.New("mfa fail")}
	hOK := NewMFAHandler(fakeTOTPService{}, nil, 0)
	hErr := NewMFAHandler(totpErr, nil, 0)
	hNil := NewMFAHandler(nil, nil, 0)

	// GetMethods unauthorized
	w := serveGetHelper(t, hOK.GetMethods, "", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	// GetMethods success
	w = serveGetHelper(t, hOK.GetMethods, "", &uid)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// EnableTOTP nil/unauthorized
	w = serve(t, hNil.EnableTOTP, `{}`, &uid)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	// EnableTOTP service error
	w = serve(t, hErr.EnableTOTP, `{}`, &uid)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}

	// VerifyTOTP unauthorized
	w = serve(t, hOK.VerifyTOTP, `{"code":"123456"}`, nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	// VerifyTOTP bad json
	w = serve(t, hOK.VerifyTOTP, `{bad`, &uid)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	// VerifyTOTP service error
	w = serve(t, hErr.VerifyTOTP, `{"code":"123456"}`, &uid)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}

	// ViewRecoveryCodes unauthorized
	w = serve(t, hOK.ViewRecoveryCodes, `{"code":"123456"}`, nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	// ViewRecoveryCodes service error
	w = serve(t, hErr.ViewRecoveryCodes, `{"code":"123456"}`, &uid)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}

	// RegenerateRecoveryCodes unauthorized
	w = serve(t, hOK.RegenerateRecoveryCodes, `{}`, nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	// RegenerateRecoveryCodes service error
	w = serve(t, hErr.RegenerateRecoveryCodes, `{}`, &uid)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}

	// DisableTOTP unauthorized
	w = serve(t, hOK.DisableTOTP, `{}`, nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	// DisableTOTP service error
	w = serve(t, hErr.DisableTOTP, `{"totpCode":"123456"}`, &uid)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}
