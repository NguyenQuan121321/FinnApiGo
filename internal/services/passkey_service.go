package services

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/store"
)

// Passkey ceremony sentinels (W3–W5).
var (
	// ErrPasskeyChallenge means the challenge is missing, expired (60s TTL),
	// or already consumed — the ceremony must restart from the challenge.
	ErrPasskeyChallenge = errors.New("passkey challenge missing, expired, or already used")
	// ErrPasskeyCredentialRevoked means a known credential was presented that
	// had been revoked (clone detection re-presentation or user removal).
	ErrPasskeyCredentialRevoked = errors.New("passkey credential is revoked")
	// ErrPasskeyNotConfigured means the WebAuthn RP is not configured.
	ErrPasskeyNotConfigured = errors.New("passkey authentication is not configured")
)

// PasskeyRepo is the persistence seam for WebAuthn credentials.
type PasskeyRepo interface {
	Create(ctx context.Context, pc *models.PasskeyCredential) error
	FindByCredentialID(ctx context.Context, credentialID []byte) (*models.PasskeyCredential, error)
	ListByUser(ctx context.Context, userID uint, includeRevoked bool) ([]models.PasskeyCredential, error)
	TouchUsage(ctx context.Context, id uint, signCount uint32, usedAt time.Time) error
	RevokeByID(ctx context.Context, id, userID uint) error
}

// PasskeyConfig carries the WebAuthn relying-party identity (W7).
type PasskeyConfig struct {
	RPDisplayName string
	RPID          string
	RPOrigins     []string
	// AttestationPreference is one of none|indirect|direct (default none).
	AttestationPreference string
}

// PasskeyService drives the WebAuthn ceremonies (W3). Challenges and session
// state live in store.Store with a 60s TTL so a multi-instance deployment
// (shared store, S1's seam) validates the verify call on ANY replica.
// (Authentication + device management methods join in sub-phases 9C/9D.)
type PasskeyService interface {
	BeginRegistration(ctx context.Context, userID uint, in PasskeyBeginInput) (any, error)
	FinishRegistration(ctx context.Context, userID uint, r *http.Request) (*models.PasskeyCredential, error)
}

type passkeyService struct {
	web          *webauthn.WebAuthn
	repo         PasskeyRepo
	users        UserRepo
	audits       AuditRepo
	kv           store.Store
	challengeTTL time.Duration
}

// NewPasskeyService builds the WebAuthn core. RP ID must be the registrable
// domain suffix of every origin in RPOrigins; HTTPS origin enforcement is the
// browser's to apply (documented in README).
func NewPasskeyService(repo PasskeyRepo, users UserRepo, audits AuditRepo, kv store.Store, cfg PasskeyConfig) (PasskeyService, error) {
	pref := protocol.PreferNoAttestation
	switch cfg.AttestationPreference {
	case "indirect":
		pref = protocol.PreferIndirectAttestation
	case "direct":
		pref = protocol.PreferDirectAttestation
	}
	w, err := webauthn.New(&webauthn.Config{
		RPDisplayName:         cfg.RPDisplayName,
		RPID:                  cfg.RPID,
		RPOrigins:             cfg.RPOrigins,
		AttestationPreference: pref,
	})
	if err != nil {
		return nil, fmt.Errorf("passkey: webauthn config: %w", err)
	}
	return &passkeyService{
		web: w, repo: repo, users: users, audits: audits, kv: kv,
		challengeTTL: 60 * time.Second, // W3: challenge/session TTL
	}, nil
}

// PasskeyBeginInput carries the human-readable label for the new credential.
type PasskeyBeginInput struct {
	DisplayName string
}

// regSession is what gets staged in the store between challenge and verify:
// the library session state plus the client-chosen display name.
type regSession struct {
	Session     webauthn.SessionData `json:"session"`
	DisplayName string               `json:"displayName"`
}

func (s *passkeyService) BeginRegistration(ctx context.Context, userID uint, in PasskeyBeginInput) (any, error) {
	user, _, err := s.loadUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	options, session, err := s.web.BeginRegistration(user,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			UserVerification: protocol.VerificationPreferred,
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
		}),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
	)
	if err != nil {
		return nil, fmt.Errorf("passkey: begin registration: %w", err)
	}
	if err := s.stageJSON(ctx, regSessionKey(userID), regSession{Session: *session, DisplayName: in.DisplayName}); err != nil {
		return nil, err
	}
	return options, nil
}

// FinishRegistration verifies the attestation (signature, RP ID/origin via
// the library) and persists the credential. The raw request body IS the
// WebAuthn attestation response — the library is its parser, so the handler
// forwards c.Request unbound (the global body-size cap still applies).
func (s *passkeyService) FinishRegistration(ctx context.Context, userID uint, r *http.Request) (*models.PasskeyCredential, error) {
	var staged regSession
	if err := s.takeJSON(ctx, regSessionKey(userID), &staged); err != nil {
		return nil, err
	}
	user, _, err := s.loadUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	cred, err := s.web.FinishRegistration(user, staged.Session, r)
	if err != nil {
		return nil, fmt.Errorf("passkey: finish registration: %w", err)
	}
	row := &models.PasskeyCredential{
		UserID:          userID,
		CredentialID:    cred.ID,
		PublicKey:       cred.PublicKey,
		SignCount:       cred.Authenticator.SignCount,
		DisplayName:     staged.DisplayName,
		Transports:      transportsJSON(cred.Transport),
		AttestationType: cred.AttestationType,
	}
	if err := s.repo.Create(ctx, row); err != nil {
		return nil, err
	}
	s.audits.Record(ctx, &models.AuditLog{
		UserID: &userID, Event: models.AuditEventPasskeyRegistered,
		IPAddress: clientIPFrom(r), Success: true, Detail: row.DisplayName,
	})
	return row, nil
}

// loadUser builds the webauthn.User adapter for a user plus their stored
// credentials.
func (s *passkeyService) loadUser(ctx context.Context, userID uint) (webauthnUser, []webauthn.Credential, error) {
	u, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return webauthnUser{}, nil, err
	}
	if u == nil {
		return webauthnUser{}, nil, ErrUserNotFound
	}
	rows, err := s.repo.ListByUser(ctx, userID, false)
	if err != nil {
		return webauthnUser{}, nil, err
	}
	creds := make([]webauthn.Credential, 0, len(rows))
	for i := range rows {
		creds = append(creds, credentialFromRow(&rows[i]))
	}
	return webauthnUser{u: u, creds: creds}, creds, nil
}

func (s *passkeyService) stageJSON(ctx context.Context, key string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("passkey: stage session: %w", err)
	}
	s.kv.Set(key, string(raw), s.challengeTTL)
	return nil
}

// takeJSON fetches and deletes the staged value — challenges are single-use.
func (s *passkeyService) takeJSON(ctx context.Context, key string, dst any) error {
	rawAny, ok := s.kv.Get(key)
	if !ok {
		return ErrPasskeyChallenge
	}
	s.kv.Delete(key)
	raw, isStr := rawAny.(string)
	if !isStr {
		return ErrPasskeyChallenge
	}
	if err := json.Unmarshal([]byte(raw), dst); err != nil {
		return fmt.Errorf("%w: %w", ErrPasskeyChallenge, err)
	}
	return nil
}

// ----- webauthn.User adapter -----

type webauthnUser struct {
	u     *models.User
	creds []webauthn.Credential
}

// WebAuthnID is the stable, non-PII user handle: the 8-byte big-endian user
// id (scoped to this RP; sufficient for a second-factor passkey).
func (w webauthnUser) WebAuthnID() []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(w.u.ID))
	return buf
}

func (w webauthnUser) WebAuthnName() string           { return w.u.Username }
func (w webauthnUser) WebAuthnDisplayName() string     { return w.u.FullName }
func (w webauthnUser) WebAuthnCredentials() []webauthn.Credential { return w.creds }

// credentialFromRow maps a stored row into the library credential.
func credentialFromRow(row *models.PasskeyCredential) webauthn.Credential {
	var transports []protocol.AuthenticatorTransport
	_ = json.Unmarshal([]byte(row.Transports), &transports)
	return webauthn.Credential{
		ID:               row.CredentialID,
		PublicKey:        row.PublicKey,
		AttestationType:  row.AttestationType,
		Transport:        transports,
		Authenticator:    webauthn.Authenticator{SignCount: row.SignCount},
	}
}

// transportsJSON serializes transports into the row's JSON column.
func transportsJSON(t []protocol.AuthenticatorTransport) string {
	if len(t) == 0 {
		return "[]"
	}
	raw, err := json.Marshal(t)
	if err != nil {
		return "[]"
	}
	return string(raw)
}

// clientIPFrom extracts the peer address for audit rows on raw-request
// ceremony endpoints (the request logger records the full picture too).
func clientIPFrom(r *http.Request) string {
	if r == nil {
		return ""
	}
	host := r.RemoteAddr
	if i := len(host) - 1; i >= 0 {
		if idx := lastIndexByte(host, ':'); idx > 0 {
			host = host[:idx]
		}
	}
	return host
}

func lastIndexByte(s string, b byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func regSessionKey(userID uint) string { return fmt.Sprintf("passkey:reg:%d", userID) }
