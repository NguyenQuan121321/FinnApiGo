package handlers

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/response"
	"github.com/finnapigo/finnapigo/internal/services"
)

// PasskeyHandler exposes the WebAuthn ceremonies (W4). The verify endpoints
// forward the raw request: the WebAuthn attestation/assertion JSON IS the
// library's parser input (the global body-size cap still applies).
type PasskeyHandler struct {
	svc services.PasskeyService
}

func NewPasskeyHandler(svc services.PasskeyService) *PasskeyHandler {
	return &PasskeyHandler{svc: svc}
}

// PasskeyBeginRequest labels the credential at challenge time (the verify
// body must remain the verbatim attestation response).
type PasskeyBeginRequest struct {
	DisplayName string `json:"displayName" binding:"max=255"`
}

// BeginRegistration issues the PKC creation options for a signed-in user.
func (h *PasskeyHandler) BeginRegistration(c *gin.Context) {
	uid, ok := ctxUserID(c)
	if !ok {
		response.Respond(c, http.StatusUnauthorized, "authentication required", nil)
		return
	}
	var req PasskeyBeginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Respond(c, http.StatusBadRequest, err.Error(), nil)
		return
	}
	options, err := h.svc.BeginRegistration(c.Request.Context(), uid,
		services.PasskeyBeginInput{DisplayName: strings.TrimSpace(req.DisplayName)})
	if err != nil {
		respondError(c, err)
		return
	}
	response.Respond(c, http.StatusOK, "passkey registration challenge", options)
}

// FinishRegistration verifies the attestation and persists the credential.
func (h *PasskeyHandler) FinishRegistration(c *gin.Context) {
	uid, ok := ctxUserID(c)
	if !ok {
		response.Respond(c, http.StatusUnauthorized, "authentication required", nil)
		return
	}
	row, err := h.svc.FinishRegistration(c.Request.Context(), uid, c.Request)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrPasskeyChallenge):
			response.Respond(c, http.StatusBadRequest, err.Error(), nil)
		case errors.Is(err, services.ErrUserNotFound):
			response.Respond(c, http.StatusUnauthorized, "authentication required", nil)
		default:
			respondError(c, err)
		}
		return
	}
	response.Respond(c, http.StatusCreated, "passkey registered", gin.H{
		"id":          row.ID,
		"displayName": row.DisplayName,
		"transports":  row.Transports,
		"createdAt":   row.CreatedAt,
	})
}

// BeginAuthentication issues the PKC assertion options (step-up login with a
// registered passkey on an active session).
func (h *PasskeyHandler) BeginAuthentication(c *gin.Context) {
	uid, ok := ctxUserID(c)
	if !ok {
		response.Respond(c, http.StatusUnauthorized, "authentication required", nil)
		return
	}
	options, err := h.svc.BeginAuthentication(c.Request.Context(), uid)
	if err != nil {
		respondError(c, err)
		return
	}
	response.Respond(c, http.StatusOK, "passkey authentication challenge", options)
}

// FinishAuthentication verifies the assertion, enforces clone detection, and
// issues a standard token pair (W5).
func (h *PasskeyHandler) FinishAuthentication(c *gin.Context) {
	uid, ok := ctxUserID(c)
	if !ok {
		response.Respond(c, http.StatusUnauthorized, "authentication required", nil)
		return
	}
	result, err := h.svc.FinishAuthentication(c.Request.Context(), uid, c.Request)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrPasskeyChallenge),
			errors.Is(err, services.ErrPasskeyCredentialRevoked):
			response.Respond(c, http.StatusUnauthorized, err.Error(), nil)
		case errors.Is(err, services.ErrUserNotFound):
			response.Respond(c, http.StatusUnauthorized, "authentication required", nil)
		default:
			respondError(c, err)
		}
		return
	}
	response.Respond(c, http.StatusOK, "login successful", LoginResponse{
		Profile:   result.Profile,
		TokenPair: result.TokenPair,
	})
}

// List returns the caller's registered passkeys (device management, W6).
func (h *PasskeyHandler) List(c *gin.Context) {
	uid, ok := ctxUserID(c)
	if !ok {
		response.Respond(c, http.StatusUnauthorized, "authentication required", nil)
		return
	}
	rows, err := h.svc.List(c.Request.Context(), uid)
	if err != nil {
		respondError(c, err)
		return
	}
	if rows == nil {
		rows = []models.PasskeyCredential{}
	}
	response.Respond(c, http.StatusOK, "passkeys fetched", gin.H{"passkeys": rows})
}

// Revoke removes one passkey. The route mounts SudoMiddleware: a stolen
// access token alone cannot strip a user's credentials (W6).
func (h *PasskeyHandler) Revoke(c *gin.Context) {
	uid, ok := ctxUserID(c)
	if !ok {
		response.Respond(c, http.StatusUnauthorized, "authentication required", nil)
		return
	}
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.Respond(c, http.StatusBadRequest, "invalid passkey id", nil)
		return
	}
	if err := h.svc.Revoke(c.Request.Context(), uint(id), uid); err != nil {
		respondError(c, err)
		return
	}
	response.Respond(c, http.StatusOK, "passkey revoked", nil)
}
