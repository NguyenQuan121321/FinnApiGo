package handlers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

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
