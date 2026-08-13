package handlers

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/finnapigo/finnapigo/internal/response"
	"github.com/finnapigo/finnapigo/internal/services"
)

// AuthHandler exposes the core-auth endpoints under /api/v1/auth.
type AuthService interface {
	Register(context.Context, services.RegisterInput) (services.UserProfile, error)
	Login(context.Context, services.LoginInput, string, string) (services.TokenPair, services.UserProfile, error)
	Logout(context.Context, string, string) error
	LogoutAll(context.Context, uint, string) error
	Refresh(context.Context, string, string, string) (services.TokenPair, error)
	ForgotPassword(context.Context, string, string) error
	ResetPassword(context.Context, services.ResetPasswordInput, string) error
	ChangePassword(context.Context, services.ChangePasswordInput, string) error
	Me(context.Context, uint) (services.UserProfile, error)
	VerifyEmail(context.Context, services.EmailVerifyInput) error
	ResendVerifyEmail(context.Context, string, string) error
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

func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Respond(c, http.StatusBadRequest, err.Error(), nil)
		return
	}
	pair, profile, err := h.svc.Login(c.Request.Context(), services.LoginInput{
		Email: req.Email, Password: req.Password, CaptchaToken: req.CaptchaToken,
	}, clientIP(c), c.Request.UserAgent())
	if err != nil {
		respondError(c, err)
		return
	}
	response.Respond(c, http.StatusOK, "login successful", LoginResponse{Profile: profile, TokenPair: pair})
}

func (h *AuthHandler) Logout(c *gin.Context) {
	var req LogoutRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Respond(c, http.StatusBadRequest, err.Error(), nil)
		return
	}
	if err := h.svc.Logout(c.Request.Context(), req.RefreshToken, clientIP(c)); err != nil {
		respondError(c, err)
		return
	}
	response.Respond(c, http.StatusOK, "logged out", nil)
}

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

func (h *AuthHandler) ForgotPassword(c *gin.Context) {
	var req ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Respond(c, http.StatusBadRequest, err.Error(), nil)
		return
	}
	_ = h.svc.ForgotPassword(c.Request.Context(), req.Email, clientIP(c))

	response.Respond(c, http.StatusOK, "if the email exists, a reset link has been sent", nil)
}

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
