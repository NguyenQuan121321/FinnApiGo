// Package handlers is the HTTP/transport layer. Handlers ONLY: parse the
// request, call a service, and format the standardized response. They never
// touch GORM directly and never contain business logic.
package handlers

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/finnapigo/finnapigo/internal/middleware"
	"github.com/finnapigo/finnapigo/internal/response"
	"github.com/finnapigo/finnapigo/internal/services"
)

// statusForError maps a service-level sentinel error to its HTTP status code.
// Anything not matched defaults to 500 — surfacing unexpected errors loudly
// is preferable to silently returning 400.
func statusForError(err error) (int, string) {
	switch {
	case errors.Is(err, services.ErrInvalidCredentials):
		return http.StatusUnauthorized, err.Error()
	case errors.Is(err, services.ErrInvalidToken):
		return http.StatusUnauthorized, err.Error()
	case errors.Is(err, services.ErrInvalidOTP):
		return http.StatusUnauthorized, err.Error()
	case errors.Is(err, services.ErrOTPMaxAttempts):
		return http.StatusTooManyRequests, err.Error()
	case errors.Is(err, services.ErrAccountLocked):
		return http.StatusForbidden, err.Error()
	case errors.Is(err, services.ErrAccountDisabled):
		return http.StatusForbidden, err.Error()
	case errors.Is(err, services.ErrEmailNotVerified):
		return http.StatusForbidden, err.Error()
	case errors.Is(err, services.ErrUserNotFound), errors.Is(err, services.ErrSessionNotFound):
		return http.StatusNotFound, err.Error()
	case errors.Is(err, services.ErrEmailExists), errors.Is(err, services.ErrUsernameExists),
		errors.Is(err, services.ErrPasswordAlreadySet):
		return http.StatusConflict, err.Error()
	case errors.Is(err, services.ErrInvalidInput), errors.Is(err, services.ErrPasswordTooWeak),
		errors.Is(err, services.ErrCaptchaRequired):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, services.ErrDisposableEmail):
		return http.StatusUnprocessableEntity, err.Error()
	case errors.Is(err, services.ErrOAuthNotConfigured):
		return http.StatusNotImplemented, err.Error()
	case errors.Is(err, services.ErrOAuthStateInvalid):
		return http.StatusUnauthorized, err.Error()
	case errors.Is(err, services.ErrOAuthEmailNotVerified):
		return http.StatusForbidden, err.Error()
	case errors.Is(err, services.ErrOAuthCodeExchangeFailed), errors.Is(err, services.ErrOAuthTokenVerificationFailed):
		return http.StatusBadGateway, err.Error()
	case errors.Is(err, services.ErrRateLimited):
		return http.StatusTooManyRequests, err.Error()
	}
	return http.StatusInternalServerError, "internal server error"
}

// respondError centralizes error → standardized-response translation so every
// handler returns the canonical {code,message,data} envelope.
func respondError(c *gin.Context, err error) {
	// Validation errors from gin binding are 400s.
	status, msg := statusForError(err)
	if status == http.StatusInternalServerError {
		// Log full error server-side; return generic message to client.
		_ = c.Error(err) // attaches to gin context for the logger middleware
	}
	response.Respond(c, status, msg, nil)
}

// clientIP is a thin wrapper to keep handler code readable.
func clientIP(c *gin.Context) string { return c.ClientIP() }

// ctxUserID pulls the authenticated user's id set by AuthMiddleware. Returns
// 0,false if missing — handlers should treat that as unauthorized.
func ctxUserID(c *gin.Context) (uint, bool) {
	v, ok := c.Get(middleware.CtxUserID)
	if !ok {
		return 0, false
	}
	id, ok := v.(uint)
	return id, ok
}
