package handlers

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/finnapigo/finnapigo/internal/middleware"
	"github.com/finnapigo/finnapigo/internal/response"
	"github.com/finnapigo/finnapigo/internal/services"
)

// AuthHandler exposes the core-auth endpoints under /api/v1/auth.
type AuthService interface {
	Register(context.Context, services.RegisterInput) (services.UserProfile, error)
	Login(context.Context, services.LoginInput, string, string) (services.TokenPair, services.UserProfile, *services.MFAPendingResult, error)
	Logout(ctx context.Context, refreshToken, accessJTI, ip string) error
	LogoutAll(context.Context, uint, string) error
	Refresh(context.Context, string, string, string) (services.TokenPair, error)
	ForgotPassword(context.Context, string, string) error
	ResetPassword(context.Context, services.ResetPasswordInput, string) error
	ChangePassword(context.Context, services.ChangePasswordInput, string) error
	SetPassword(context.Context, uint, string, string) error
	Me(context.Context, uint) (services.UserProfile, error)
	VerifyEmail(context.Context, services.EmailVerifyInput) error
	ResendVerifyEmail(context.Context, string, string) error
	CompleteMFALogin(context.Context, services.CompleteMFALoginInput) (services.TokenPair, services.UserProfile, error)
	GetUserAuditLog(context.Context, uint, int, int) ([]services.UserAuditLogItem, int64, error)
	RequestChangeEmail(ctx context.Context, userID uint, in services.ChangeEmailRequestInput, ip string) error
	ConfirmChangeEmail(ctx context.Context, token, ip string) error
	DeactivateAccount(ctx context.Context, userID uint, sudoToken, password, accessJTI, ip string) error
	EraseAccount(ctx context.Context, userID uint, sudoToken, password, accessJTI, ip string) error
}

type AuthHandler struct {
	svc     AuthService
	captcha services.CaptchaVerifier // §2 — nil-safe (NoOpVerifier when off)
}

func NewAuthHandler(svc AuthService, captcha services.CaptchaVerifier) *AuthHandler {
	if captcha == nil {
		captcha = noOpCaptcha{}
	}
	return &AuthHandler{svc: svc, captcha: captcha}
}

type noOpCaptcha struct{}

func (noOpCaptcha) Verify(ctx context.Context, token string) error { return nil }

// Register godoc
//
//	@Summary      Create a new account
//	@Description  Creates a new account. A verification email is sent when SMTP is configured. CAPTCHA may be required depending on server settings. The honeypot field 'website' must stay empty — non-empty values silently succeed without creating an account.
//	@Tags         Auth
//	@Accept       json
//	@Produce      json
//	@Param        request body handlers.RegisterRequest true "Registration payload"
//	@Success      201 {object} swagger.RegisterEnvelope
//	@Failure      400 {object} swagger.ErrorEnvelope
//	@Failure      409 {object} swagger.ErrorEnvelope
//	@Failure      422 {object} swagger.ErrorEnvelope
//	@Failure      429 {object} swagger.ErrorEnvelope
//	@Router       /api/v1/auth/register [post]
func (h *AuthHandler) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Respond(c, http.StatusBadRequest, err.Error(), nil)
		return
	}

	// §2 — Honeypot: real users never fill this hidden field. If non-empty,
	// silently report success WITHOUT creating an account, so a naive bot gets
	// no signal that it was detected.
	if req.Website != "" {
		response.Respond(c, http.StatusCreated, "account created", nil)
		return
	}

	// §2 — CAPTCHA (Turnstile/hCaptcha). When configured, verify the token
	// server-side before doing any work.
	if err := h.captcha.Verify(c.Request.Context(), req.CaptchaToken); err != nil {
		response.Respond(c, http.StatusBadRequest, "captcha verification failed", nil)
		return
	}

	profile, err := h.svc.Register(c.Request.Context(), services.RegisterInput{
		Username: req.Username, Email: req.Email, Password: req.Password, FullName: req.FullName,
		IP: clientIP(c),
	})
	if err != nil {
		respondError(c, err)
		return
	}
	// §1.1 — verification token is NO LONGER in the response; it is emailed.
	response.Respond(c, http.StatusCreated, "account created", RegisterResponse{Profile: profile})
}

// Login godoc
//
//	@Summary      Log in with email and password
//	@Description  Authenticates with email and password. When the account has TOTP MFA active the response is HTTP 200 with message "mfa required" and data {mfaRequired: true, mfaToken: "<mfa_pending JWT>"} — complete the login with POST /auth/mfa/login-verify carrying that token in the Authorization header. Otherwise the response is HTTP 200 with message "login successful" and the standard token pair next to the profile.
//	@Tags         Auth
//	@Accept       json
//	@Produce      json
//	@Param        request body handlers.LoginRequest true "Login credentials"
//	@Success      200 {object} swagger.LoginEnvelope "Standard token pair, or the MFA-pending payload when TOTP is enabled (see description)"
//	@Failure      400 {object} swagger.ErrorEnvelope
//	@Failure      401 {object} swagger.ErrorEnvelope
//	@Failure      403 {object} swagger.ErrorEnvelope
//	@Failure      429 {object} swagger.ErrorEnvelope
//	@Router       /api/v1/auth/login [post]
func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Respond(c, http.StatusBadRequest, err.Error(), nil)
		return
	}
	pair, profile, mfaPending, err := h.svc.Login(c.Request.Context(), services.LoginInput{
		Email: req.Email, Password: req.Password, CaptchaToken: req.CaptchaToken,
	}, clientIP(c), c.Request.UserAgent())
	if err != nil {
		respondError(c, err)
		return
	}
	if mfaPending != nil {
		response.Respond(c, http.StatusOK, "mfa required", mfaPending)
		return
	}
	response.Respond(c, http.StatusOK, "login successful", LoginResponse{Profile: profile, TokenPair: pair})
}

// CompleteMFALogin godoc
//
//	@Summary      Complete an MFA-pending login
//	@Description  Completes a login that returned "mfa required". The Authorization header must carry the short-lived mfa_pending JWT issued by POST /auth/login — a standard access token is rejected. On success a standard token pair is issued.
//	@Tags         Auth
//	@Accept       json
//	@Produce      json
//	@Security     BearerAuth
//	@Param        request body handlers.MFALoginVerifyRequest true "TOTP or recovery code"
//	@Success      200 {object} swagger.LoginEnvelope
//	@Failure      400 {object} swagger.ErrorEnvelope
//	@Failure      401 {object} swagger.ErrorEnvelope
//	@Failure      429 {object} swagger.ErrorEnvelope
//	@Router       /api/v1/auth/mfa/login-verify [post]
func (h *AuthHandler) CompleteMFALogin(c *gin.Context) {
	uid, ok := ctxUserID(c)
	if !ok {
		response.Respond(c, http.StatusUnauthorized, "authentication required", nil)
		return
	}
	var req MFALoginVerifyRequest
	if !bindJSON(c, &req) {
		return
	}
	pair, profile, err := h.svc.CompleteMFALogin(c.Request.Context(), services.CompleteMFALoginInput{
		UserID: uid, Code: req.Code, IP: clientIP(c), UA: c.Request.UserAgent(),
	})
	if err != nil {
		respondError(c, err)
		return
	}
	response.Respond(c, http.StatusOK, "login successful", LoginResponse{Profile: profile, TokenPair: pair})
}

// Logout godoc
//
//	@Summary      Log out one device
//	@Description  Revokes the given refresh token. Requires a valid access token for the same account.
//	@Tags         Auth
//	@Accept       json
//	@Produce      json
//	@Security     BearerAuth
//	@Param        request body handlers.LogoutRequest true "Refresh token to revoke"
//	@Success      200 {object} swagger.NullDataEnvelope "logged out"
//	@Failure      400 {object} swagger.ErrorEnvelope
//	@Failure      401 {object} swagger.ErrorEnvelope
//	@Router       /api/v1/auth/logout [post]
func (h *AuthHandler) Logout(c *gin.Context) {
	var req LogoutRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Respond(c, http.StatusBadRequest, err.Error(), nil)
		return
	}
	accessJTI := c.GetString(middleware.CtxJTI)
	if err := h.svc.Logout(c.Request.Context(), req.RefreshToken, accessJTI, clientIP(c)); err != nil {
		respondError(c, err)
		return
	}
	response.Respond(c, http.StatusOK, "logged out", nil)
}

// LogoutAll godoc
//
//	@Summary      Log out everywhere
//	@Description  Revokes every active session of the caller — all devices must log in again.
//	@Tags         Auth
//	@Produce      json
//	@Security     BearerAuth
//	@Success      200 {object} swagger.NullDataEnvelope "signed out everywhere"
//	@Failure      401 {object} swagger.ErrorEnvelope
//	@Router       /api/v1/auth/logout-all [post]
func (h *AuthHandler) LogoutAll(c *gin.Context) {
	uid, ok := ctxUserID(c)
	if !ok {
		response.Respond(c, http.StatusUnauthorized, "authentication required", nil)
		return
	}
	if err := h.svc.LogoutAll(c.Request.Context(), uid, clientIP(c)); err != nil {
		respondError(c, err)
		return
	}
	response.Respond(c, http.StatusOK, "signed out everywhere", nil)
}

// Refresh godoc
//
//	@Summary      Rotate a refresh token
//	@Description  Exchanges a valid refresh token for a new token pair. The presented token is revoked (single-use rotation).
//	@Tags         Auth
//	@Accept       json
//	@Produce      json
//	@Param        request body handlers.RefreshRequest true "Current refresh token"
//	@Success      200 {object} swagger.TokenPairEnvelope
//	@Failure      400 {object} swagger.ErrorEnvelope
//	@Failure      401 {object} swagger.ErrorEnvelope
//	@Failure      429 {object} swagger.ErrorEnvelope
//	@Router       /api/v1/auth/refresh-token [post]
func (h *AuthHandler) Refresh(c *gin.Context) {
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Respond(c, http.StatusBadRequest, err.Error(), nil)
		return
	}
	pair, err := h.svc.Refresh(c.Request.Context(), req.RefreshToken, clientIP(c), c.Request.UserAgent())
	if err != nil {
		respondError(c, err)
		return
	}
	response.Respond(c, http.StatusOK, "token refreshed", pair)
}

// ForgotPassword godoc
//
//	@Summary      Request a password-reset email
//	@Description  Always responds 200 with the same message regardless of whether the email exists (anti-enumeration). A reset link is emailed only when the account exists.
//	@Tags         Auth
//	@Accept       json
//	@Produce      json
//	@Param        request body handlers.ForgotPasswordRequest true "Account email"
//	@Success      200 {object} swagger.NullDataEnvelope
//	@Failure      400 {object} swagger.ErrorEnvelope
//	@Failure      429 {object} swagger.ErrorEnvelope
//	@Router       /api/v1/auth/forgot-password [post]
func (h *AuthHandler) ForgotPassword(c *gin.Context) {
	var req ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Respond(c, http.StatusBadRequest, err.Error(), nil)
		return
	}
	_ = h.svc.ForgotPassword(c.Request.Context(), req.Email, clientIP(c))

	response.Respond(c, http.StatusOK, "if the email exists, a reset link has been sent", nil)
}

// ResetPassword godoc
//
//	@Summary      Reset the password with a single-use token
//	@Description  Consumes the single-use reset token from the email link and sets the new password. The token cannot be reused.
//	@Tags         Auth
//	@Accept       json
//	@Produce      json
//	@Param        request body handlers.ResetPasswordRequest true "Reset token and new password"
//	@Success      200 {object} swagger.NullDataEnvelope
//	@Failure      400 {object} swagger.ErrorEnvelope
//	@Failure      401 {object} swagger.ErrorEnvelope
//	@Failure      422 {object} swagger.ErrorEnvelope
//	@Failure      429 {object} swagger.ErrorEnvelope
//	@Router       /api/v1/auth/reset-password [post]
func (h *AuthHandler) ResetPassword(c *gin.Context) {
	var req ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Respond(c, http.StatusBadRequest, err.Error(), nil)
		return
	}
	if err := h.svc.ResetPassword(c.Request.Context(), services.ResetPasswordInput{
		Token: req.Token, NewPassword: req.NewPassword,
	}, clientIP(c)); err != nil {
		respondError(c, err)
		return
	}
	response.Respond(c, http.StatusOK, "password has been reset", nil)
}

// ChangePassword godoc
//
//	@Summary      Change the caller's password
//	@Description  Verifies the old password, sets the new one, and revokes ALL sessions — every device must log in again.
//	@Tags         Auth
//	@Accept       json
//	@Produce      json
//	@Security     BearerAuth
//	@Param        request body handlers.ChangePasswordRequest true "Old and new password"
//	@Success      200 {object} swagger.NullDataEnvelope
//	@Failure      400 {object} swagger.ErrorEnvelope
//	@Failure      401 {object} swagger.ErrorEnvelope
//	@Failure      422 {object} swagger.ErrorEnvelope
//	@Router       /api/v1/auth/change-password [post]
func (h *AuthHandler) ChangePassword(c *gin.Context) {
	uid, ok := ctxUserID(c)
	if !ok {
		response.Respond(c, http.StatusUnauthorized, "authentication required", nil)
		return
	}
	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Respond(c, http.StatusBadRequest, err.Error(), nil)
		return
	}
	if err := h.svc.ChangePassword(c.Request.Context(), services.ChangePasswordInput{
		UserID: uid, OldPassword: req.OldPassword, NewPassword: req.NewPassword,
	}, clientIP(c)); err != nil {
		respondError(c, err)
		return
	}
	response.Respond(c, http.StatusOK, "password changed; all sessions signed out", nil)
}

// SetPassword lets a Google-OAuth-only account establish a first password.
// Unlike ChangePassword there is no oldPassword to verify — but the service
// layer independently re-checks that no password exists yet and rejects with
// 409 otherwise, so this can never act as a change-password bypass.
// SetPassword godoc
//
//	@Summary      Set a first password (Google-OAuth-only accounts)
//	@Description  Establishes the first password for an account that has never had one (Google OAuth sign-up). Returns 409 when a password already exists — use change-password instead.
//	@Tags         Auth
//	@Accept       json
//	@Produce      json
//	@Security     BearerAuth
//	@Param        request body handlers.SetPasswordRequest true "New password"
//	@Success      200 {object} swagger.NullDataEnvelope
//	@Failure      400 {object} swagger.ErrorEnvelope
//	@Failure      401 {object} swagger.ErrorEnvelope
//	@Failure      409 {object} swagger.ErrorEnvelope
//	@Failure      422 {object} swagger.ErrorEnvelope
//	@Router       /api/v1/auth/set-password [post]
func (h *AuthHandler) SetPassword(c *gin.Context) {
	uid, ok := ctxUserID(c)
	if !ok {
		response.Respond(c, http.StatusUnauthorized, "authentication required", nil)
		return
	}
	var req SetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Respond(c, http.StatusBadRequest, err.Error(), nil)
		return
	}
	if err := h.svc.SetPassword(c.Request.Context(), uid, req.Password, clientIP(c)); err != nil {
		respondError(c, err)
		return
	}
	response.Respond(c, http.StatusOK, "password has been set", nil)
}

// Me godoc
//
//	@Summary      Get the caller's profile
//	@Description  Returns the authenticated user's sanitized profile.
//	@Tags         Auth
//	@Produce      json
//	@Security     BearerAuth
//	@Success      200 {object} swagger.UserProfileEnvelope
//	@Failure      401 {object} swagger.ErrorEnvelope
//	@Failure      404 {object} swagger.ErrorEnvelope
//	@Router       /api/v1/auth/me [get]
func (h *AuthHandler) Me(c *gin.Context) {
	uid, ok := ctxUserID(c)
	if !ok {
		response.Respond(c, http.StatusUnauthorized, "authentication required", nil)
		return
	}
	profile, err := h.svc.Me(c.Request.Context(), uid)
	if err != nil {
		respondError(c, err)
		return
	}
	response.Respond(c, http.StatusOK, "profile fetched", profile)
}

// VerifyEmail godoc
//
//	@Summary      Verify the account email
//	@Description  Consumes the single-use verification token from the email link and marks the account verified. The token cannot be reused.
//	@Tags         Auth
//	@Accept       json
//	@Produce      json
//	@Param        request body handlers.VerifyEmailRequest true "Verification token"
//	@Success      200 {object} swagger.NullDataEnvelope
//	@Failure      400 {object} swagger.ErrorEnvelope
//	@Failure      401 {object} swagger.ErrorEnvelope
//	@Failure      404 {object} swagger.ErrorEnvelope
//	@Failure      429 {object} swagger.ErrorEnvelope
//	@Router       /api/v1/auth/verify-email [post]
func (h *AuthHandler) VerifyEmail(c *gin.Context) {
	var req VerifyEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Respond(c, http.StatusBadRequest, err.Error(), nil)
		return
	}
	if err := h.svc.VerifyEmail(c.Request.Context(), services.EmailVerifyInput{Token: req.Token}); err != nil {
		respondError(c, err)
		return
	}
	response.Respond(c, http.StatusOK, "email verified", nil)
}

// ResendVerifyEmail godoc
//
//	@Summary      Resend the verification email
//	@Description  Responds 200 with the same message whether or not the email exists and whether it is already verified (anti-enumeration); a link is sent only to unverified existing accounts. Exceeding the resend rate limit surfaces a 429 so legitimate clients can back off.
//	@Tags         Auth
//	@Accept       json
//	@Produce      json
//	@Param        request body handlers.ResendVerifyEmailRequest true "Account email"
//	@Success      200 {object} swagger.NullDataEnvelope
//	@Failure      400 {object} swagger.ErrorEnvelope
//	@Failure      429 {object} swagger.ErrorEnvelope
//	@Router       /api/v1/auth/resend-verification [post]
func (h *AuthHandler) ResendVerifyEmail(c *gin.Context) {
	var req ResendVerifyEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Respond(c, http.StatusBadRequest, err.Error(), nil)
		return
	}
	err := h.svc.ResendVerifyEmail(c.Request.Context(), req.Email, clientIP(c))
	// Any resend rate limit is surfaced (lets a legitimate client back off).
	// Every other outcome — unknown email, already verified, transient
	// notifier failure — returns the identical message so the endpoint never
	// reveals whether the email exists (OWASP ASVS V3.2 anti-enumeration).
	if err != nil && errors.Is(err, services.ErrRateLimited) {
		respondError(c, err)
		return
	}
	response.Respond(c, http.StatusOK, "if the email exists, a verification link has been sent", nil)
}

// MyAuditLog godoc
//
//	@Summary      Get personal audit log
//	@Description  Returns paginated security event log for the authenticated user.
//	@Tags         Auth
//	@Produce      json
//	@Security     BearerAuth
//	@Param        page   query     int  false  "Page number (default 1)"
//	@Param        limit  query     int  false  "Items per page (default 20, max 100)"
//	@Success      200    {object}  swagger.UserAuditLogEnvelope
//	@Failure      401    {object}  swagger.ErrorEnvelope
//	@Router       /api/v1/auth/me/audit-log [get]
func (h *AuthHandler) MyAuditLog(c *gin.Context) {
	uid, ok := ctxUserID(c)
	if !ok {
		response.Respond(c, http.StatusUnauthorized, "authentication required", nil)
		return
	}
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 20
	}
	items, total, err := h.svc.GetUserAuditLog(c.Request.Context(), uid, page, limit)
	if err != nil {
		respondError(c, err)
		return
	}
	response.Respond(c, http.StatusOK, "audit log", gin.H{
		"items": items,
		"total": total,
		"page":  page,
		"limit": limit,
	})
}

// DeactivateRequest is the optional body for POST /api/v1/auth/deactivate (P1.3).
type DeactivateRequest struct {
	Password string `json:"password"`
}

// EraseMeRequest is the optional body for DELETE /api/v1/auth/me (P1.3).
type EraseMeRequest struct {
	Password string `json:"password"`
}

// RequestChangeEmail godoc
//
//	@Summary      Request email change
//	@Description  Stages an email change request. Verifies password, checks disposable and colliding domains, sends verification to the new email and security alert to current email.
//	@Tags         Auth
//	@Accept       json
//	@Produce      json
//	@Security     BearerAuth
//	@Param        request body services.ChangeEmailRequestInput true "Current password and new email"
//	@Success      200 {object} swagger.NullDataEnvelope
//	@Failure      400 {object} swagger.ErrorEnvelope
//	@Failure      401 {object} swagger.ErrorEnvelope
//	@Failure      409 {object} swagger.ErrorEnvelope
//	@Failure      422 {object} swagger.ErrorEnvelope
//	@Router       /api/v1/auth/change-email/request [post]
func (h *AuthHandler) RequestChangeEmail(c *gin.Context) {
	uid, ok := ctxUserID(c)
	if !ok {
		response.Respond(c, http.StatusUnauthorized, "authentication required", nil)
		return
	}
	var req services.ChangeEmailRequestInput
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Respond(c, http.StatusBadRequest, err.Error(), nil)
		return
	}
	if err := h.svc.RequestChangeEmail(c.Request.Context(), uid, req, clientIP(c)); err != nil {
		respondError(c, err)
		return
	}
	response.Respond(c, http.StatusOK, "verification email sent to new address", nil)
}

// ConfirmChangeEmail godoc
//
//	@Summary      Confirm email change
//	@Description  Confirms email change using the single-use token from the verification email. Inactive sessions are revoked and password version bumped.
//	@Tags         Auth
//	@Accept       json
//	@Produce      json
//	@Param        request body services.ChangeEmailConfirmInput true "Confirmation token"
//	@Success      200 {object} swagger.NullDataEnvelope
//	@Failure      400 {object} swagger.ErrorEnvelope
//	@Failure      401 {object} swagger.ErrorEnvelope
//	@Failure      409 {object} swagger.ErrorEnvelope
//	@Router       /api/v1/auth/change-email/confirm [post]
func (h *AuthHandler) ConfirmChangeEmail(c *gin.Context) {
	var req services.ChangeEmailConfirmInput
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Respond(c, http.StatusBadRequest, err.Error(), nil)
		return
	}
	if err := h.svc.ConfirmChangeEmail(c.Request.Context(), req.Token, clientIP(c)); err != nil {
		respondError(c, err)
		return
	}
	response.Respond(c, http.StatusOK, "email successfully changed", nil)
}

// DeactivateAccount godoc
//
//	@Summary      Deactivate account
//	@Description  Deactivates caller account (is_active=false), revokes all sessions and denylists caller's access token. Requires either X-Sudo-Token header or password.
//	@Tags         Auth
//	@Accept       json
//	@Produce      json
//	@Security     BearerAuth
//	@Param        request body handlers.DeactivateRequest false "Account password (optional if X-Sudo-Token provided)"
//	@Success      200 {object} swagger.NullDataEnvelope
//	@Failure      401 {object} swagger.ErrorEnvelope
//	@Failure      403 {object} swagger.ErrorEnvelope
//	@Router       /api/v1/auth/deactivate [post]
func (h *AuthHandler) DeactivateAccount(c *gin.Context) {
	uid, ok := ctxUserID(c)
	if !ok {
		response.Respond(c, http.StatusUnauthorized, "authentication required", nil)
		return
	}
	var req DeactivateRequest
	_ = c.ShouldBindJSON(&req)
	sudoToken := c.GetHeader(middleware.SudoHeader)
	accessJTI := c.GetString(middleware.CtxJTI)
	if err := h.svc.DeactivateAccount(c.Request.Context(), uid, sudoToken, req.Password, accessJTI, clientIP(c)); err != nil {
		respondError(c, err)
		return
	}
	response.Respond(c, http.StatusOK, "account deactivated", nil)
}

// EraseMe godoc
//
//	@Summary      Permanently erase account (GDPR)
//	@Description  Scrambles user credentials, deletes credentials (TOTP, passkeys, OAuth), anonymizes audit records, revokes all sessions. Requires either X-Sudo-Token header or password.
//	@Tags         Auth
//	@Accept       json
//	@Produce      json
//	@Security     BearerAuth
//	@Param        request body handlers.EraseMeRequest false "Account password (optional if X-Sudo-Token provided)"
//	@Success      200 {object} swagger.NullDataEnvelope
//	@Failure      401 {object} swagger.ErrorEnvelope
//	@Failure      403 {object} swagger.ErrorEnvelope
//	@Router       /api/v1/auth/me [delete]
func (h *AuthHandler) EraseMe(c *gin.Context) {
	uid, ok := ctxUserID(c)
	if !ok {
		response.Respond(c, http.StatusUnauthorized, "authentication required", nil)
		return
	}
	var req EraseMeRequest
	_ = c.ShouldBindJSON(&req)
	sudoToken := c.GetHeader(middleware.SudoHeader)
	accessJTI := c.GetString(middleware.CtxJTI)
	if err := h.svc.EraseAccount(c.Request.Context(), uid, sudoToken, req.Password, accessJTI, clientIP(c)); err != nil {
		respondError(c, err)
		return
	}
	response.Respond(c, http.StatusOK, "account erased", nil)
}
