package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/finnapigo/finnapigo/internal/services"
	"github.com/finnapigo/finnapigo/internal/utils"
)

// AuthHandler exposes the core-auth endpoints under /api/v1/auth.
type AuthHandler struct {
	svc *services.AuthService
}

func NewAuthHandler(svc *services.AuthService) *AuthHandler {
	return &AuthHandler{svc: svc}
}

// Register godoc
// @Summary      Register a new account
// @Description  Create account, hash password, reject duplicate email/username
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body  body      RegisterRequest  true  "Registration payload"
// @Success      201   {object}  utils.APIResponse
// @Failure      400,409  {object}  utils.APIResponse
// @Router       /auth/register [post]
func (h *AuthHandler) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.Respond(c, http.StatusBadRequest, err.Error(), nil)
		return
	}
	profile, verifyToken, err := h.svc.Register(c.Request.Context(), services.RegisterInput{
		Username: req.Username, Email: req.Email, Password: req.Password, FullName: req.FullName,
	})
	if err != nil {
		respondError(c, err)
		return
	}
	utils.Respond(c, http.StatusCreated, "account created", RegisterResponse{
		Profile:          profile,
		VerifyEmailToken: verifyToken,
	})
}

// Login godoc
// @Summary      Log in
// @Description  Authenticate credentials, return access + refresh tokens
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body  body      LoginRequest  true  "Credentials"
// @Success      200   {object}  utils.APIResponse
// @Failure      401,403  {object}  utils.APIResponse
// @Router       /auth/login [post]
func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.Respond(c, http.StatusBadRequest, err.Error(), nil)
		return
	}
	pair, profile, err := h.svc.Login(c.Request.Context(), services.LoginInput{
		Email: req.Email, Password: req.Password,
	}, clientIP(c))
	if err != nil {
		respondError(c, err)
		return
	}
	utils.Respond(c, http.StatusOK, "login successful", LoginResponse{Profile: profile, TokenPair: pair})
}

// Logout godoc
// @Summary      Log out
// @Description  Revoke the supplied refresh token
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body  body      LogoutRequest  true  "Refresh token to revoke"
// @Success      200   {object}  utils.APIResponse
// @Router       /auth/logout [post]
func (h *AuthHandler) Logout(c *gin.Context) {
	var req LogoutRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.Respond(c, http.StatusBadRequest, err.Error(), nil)
		return
	}
	if err := h.svc.Logout(c.Request.Context(), req.RefreshToken, clientIP(c)); err != nil {
		respondError(c, err)
		return
	}
	utils.Respond(c, http.StatusOK, "logged out", nil)
}

// Refresh godoc
// @Summary      Refresh access token
// @Description  Rotate refresh token, issue new access + refresh pair
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body  body      RefreshRequest  true  "Refresh token"
// @Success      200   {object}  utils.APIResponse
// @Failure      401   {object}  utils.APIResponse
// @Router       /auth/refresh-token [post]
func (h *AuthHandler) Refresh(c *gin.Context) {
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.Respond(c, http.StatusBadRequest, err.Error(), nil)
		return
	}
	pair, err := h.svc.Refresh(c.Request.Context(), req.RefreshToken, clientIP(c))
	if err != nil {
		respondError(c, err)
		return
	}
	utils.Respond(c, http.StatusOK, "token refreshed", pair)
}

// ForgotPassword godoc
// @Summary      Request a password reset
// @Description  Accept email, send reset token. Always returns the same message.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body  body      ForgotPasswordRequest  true  "Email"
// @Success      200   {object}  utils.APIResponse
// @Router       /auth/forgot-password [post]
func (h *AuthHandler) ForgotPassword(c *gin.Context) {
	var req ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// Even on malformed input, do not reveal whether the email exists — but
		// a binding error is a client problem, so 400 is safe here.
		utils.Respond(c, http.StatusBadRequest, err.Error(), nil)
		return
	}
	_ = h.svc.ForgotPassword(c.Request.Context(), req.Email, clientIP(c))
	// ALWAYS return the same generic message regardless of whether the email
	// was found — prevents account enumeration.
	utils.Respond(c, http.StatusOK, "if the email exists, a reset link has been sent", nil)
}

// ResetPassword godoc
// @Summary      Reset password
// @Description  Accept reset token + new password, update the password
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body  body      ResetPasswordRequest  true  "Reset payload"
// @Success      200   {object}  utils.APIResponse
// @Failure      400,401  {object}  utils.APIResponse
// @Router       /auth/reset-password [post]
func (h *AuthHandler) ResetPassword(c *gin.Context) {
	var req ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.Respond(c, http.StatusBadRequest, err.Error(), nil)
		return
	}
	if err := h.svc.ResetPassword(c.Request.Context(), services.ResetPasswordInput{
		Token: req.Token, NewPassword: req.NewPassword,
	}, clientIP(c)); err != nil {
		respondError(c, err)
		return
	}
	utils.Respond(c, http.StatusOK, "password has been reset", nil)
}

// ChangePassword godoc
// @Summary      Change password (authenticated)
// @Description  Verify old password, set new one, revoke all refresh tokens
// @Tags         auth
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        body  body      ChangePasswordRequest  true  "Change payload"
// @Success      200   {object}  utils.APIResponse
// @Failure      400,401,404  {object}  utils.APIResponse
// @Router       /auth/change-password [post]
func (h *AuthHandler) ChangePassword(c *gin.Context) {
	uid, ok := ctxUserID(c)
	if !ok {
		utils.Respond(c, http.StatusUnauthorized, "authentication required", nil)
		return
	}
	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.Respond(c, http.StatusBadRequest, err.Error(), nil)
		return
	}
	if err := h.svc.ChangePassword(c.Request.Context(), services.ChangePasswordInput{
		UserID: uid, OldPassword: req.OldPassword, NewPassword: req.NewPassword,
	}, clientIP(c)); err != nil {
		respondError(c, err)
		return
	}
	utils.Respond(c, http.StatusOK, "password changed; all sessions signed out", nil)
}

// Me godoc
// @Summary      Get current user profile
// @Description  Decode access token, return the current user's profile
// @Tags         auth
// @Security     BearerAuth
// @Produce      json
// @Success      200   {object}  utils.APIResponse
// @Failure      401,404  {object}  utils.APIResponse
// @Router       /auth/me [get]
func (h *AuthHandler) Me(c *gin.Context) {
	uid, ok := ctxUserID(c)
	if !ok {
		utils.Respond(c, http.StatusUnauthorized, "authentication required", nil)
		return
	}
	profile, err := h.svc.Me(c.Request.Context(), uid)
	if err != nil {
		respondError(c, err)
		return
	}
	utils.Respond(c, http.StatusOK, "profile fetched", profile)
}

// VerifyEmail godoc
// @Summary      Verify email address
// @Description  Mark the account's email as verified using the verification token
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body  body      VerifyEmailRequest  true  "Verification token"
// @Success      200   {object}  utils.APIResponse
// @Failure      400,401,404  {object}  utils.APIResponse
// @Router       /auth/verify-email [post]
func (h *AuthHandler) VerifyEmail(c *gin.Context) {
	var req VerifyEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.Respond(c, http.StatusBadRequest, err.Error(), nil)
		return
	}
	if err := h.svc.VerifyEmail(c.Request.Context(), services.EmailVerifyInput{Token: req.Token}); err != nil {
		respondError(c, err)
		return
	}
	utils.Respond(c, http.StatusOK, "email verified", nil)
}
