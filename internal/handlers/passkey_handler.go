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

// BeginRegistration godoc
//
//	@Summary      Begin passkey registration
//	@Description  Issues the PublicKeyCredentialCreationOptions for a signed-in user.
//	@Description  Stages the ceremony challenge in the shared store (60s TTL, single use).
//	@Description  Requires WEBAUTHN_RP_ID to be configured.
//	@Tags         MFA
//	@Accept       json
//	@Produce      json
//	@Param        body  body      handlers.PasskeyBeginRequest  true  "Optional display name for the credential"
//	@Success      200   {object}  swagger.PasskeyOptionsEnvelope  "PKC creation options (pass to navigator.credentials.create)"
//	@Failure      400   {object}  swagger.ErrorEnvelope
//	@Failure      401   {object}  swagger.ErrorEnvelope
//	@Failure      403   {object}  swagger.ErrorEnvelope
//	@Failure      429   {object}  swagger.ErrorEnvelope
//	@Security     BearerAuth
//	@Router       /api/v1/auth/mfa/passkey/register/challenge [post]
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

// FinishRegistration godoc
//
//	@Summary      Finish passkey registration
//	@Description  Completes passkey registration by verifying the attestation and persisting the credential.
//	@Description  The request body is the verbatim WebAuthn attestation response (PublicKeyCredential JSON) — do not wrap or rebind it.
//	@Tags         MFA
//	@Produce      json
//	@Success      201  {object}  swagger.PasskeyRegisteredEnvelope
//	@Failure      400  {object}  swagger.ErrorEnvelope
//	@Failure      401  {object}  swagger.ErrorEnvelope
//	@Failure      403  {object}  swagger.ErrorEnvelope
//	@Failure      429  {object}  swagger.ErrorEnvelope
//	@Security     BearerAuth
//	@Router       /api/v1/auth/mfa/passkey/register/verify [post]
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

// BeginAuthentication godoc
//
//	@Summary      Begin passkey authentication
//	@Description  Issues the PublicKeyCredentialRequestOptions for step-up login with a registered passkey on an active session.
//	@Tags         MFA
//	@Produce      json
//	@Success      200  {object}  swagger.PasskeyOptionsEnvelope  "PKC assertion options (pass to navigator.credentials.get)"
//	@Failure      401  {object}  swagger.ErrorEnvelope
//	@Failure      403  {object}  swagger.ErrorEnvelope
//	@Failure      429  {object}  swagger.ErrorEnvelope
//	@Security     BearerAuth
//	@Router       /api/v1/auth/mfa/passkey/authenticate/challenge [post]
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

// FinishAuthentication godoc
//
//	@Summary      Finish passkey authentication
//	@Description  Verifies the WebAuthn assertion. A sign-count regression (cloned credential) revokes the credential,
//	@Description  records a passkey.clone_detected audit event, and refuses the login.
//	@Description  On success a standard token pair is issued.
//	@Tags         MFA
//	@Produce      json
//	@Success      200  {object}  swagger.LoginEnvelope
//	@Failure      401  {object}  swagger.ErrorEnvelope
//	@Failure      403  {object}  swagger.ErrorEnvelope
//	@Failure      429  {object}  swagger.ErrorEnvelope
//	@Security     BearerAuth
//	@Router       /api/v1/auth/mfa/passkey/authenticate/verify [post]
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

// List godoc
//
//	@Summary      List passkeys
//	@Description  Lists the caller's registered passkeys for device management.
//	@Tags         MFA
//	@Produce      json
//	@Success      200  {object}  swagger.PasskeysListEnvelope
//	@Failure      401  {object}  swagger.ErrorEnvelope
//	@Security     BearerAuth
//	@Router       /api/v1/auth/mfa/passkeys [get]
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

// Revoke godoc
//
//	@Summary      Revoke a passkey
//	@Description  Revokes one passkey. Requires X-Sudo-Token header (sudo-gated) —
//	@Description  a stolen access token alone cannot strip a user's credentials.
//	@Tags         MFA
//	@Produce      json
//	@Param        id   path      int  true  "Passkey ID"
//	@Success      200  {object}  swagger.NullDataEnvelope
//	@Failure      400  {object}  swagger.ErrorEnvelope
//	@Failure      401  {object}  swagger.ErrorEnvelope
//	@Failure      403  {object}  swagger.ErrorEnvelope
//	@Failure      404  {object}  swagger.ErrorEnvelope
//	@Security     BearerAuth
//	@Security     SudoAuth
//	@Router       /api/v1/auth/mfa/passkeys/{id} [delete]
func (h *PasskeyHandler) Revoke(c *gin.Context) {
	uid, ok := ctxUserID(c)
	if !ok {
		response.Respond(c, http.StatusUnauthorized, "authentication required", nil)
		return
	}
	// Limit parsing to the platform's uint width so converting to uint cannot
	// truncate a valid 64-bit value on 32-bit builds.
	id, err := strconv.ParseUint(c.Param("id"), 10, strconv.IntSize)
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
