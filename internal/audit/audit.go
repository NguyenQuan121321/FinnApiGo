// Package audit defines the versioned security trail and trusted process context.
// HTTP headers never supply actor or tenant authority to this package.
package audit

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/tenant"
	"github.com/google/uuid"
)

var (
	ErrUnavailable = errors.New("durable audit unavailable")
	ErrIntegrity   = errors.New("audit integrity verification failed")
	ErrLegacy      = errors.New("legacy audit history is unverifiable")
	ErrPolicy      = errors.New("approved archive/retention policy and trusted reference required")
)

type contextKey uint8

const (
	actorKey contextKey = iota
	correlationKey
	systemKey
)

// WithActor is called only after credential/factor validation or authenticated
// middleware. An event's UserID is a subject hint, never proof of its actor.
func WithActor(ctx context.Context, id uint) context.Context {
	return context.WithValue(ctx, actorKey, id)
}
func WithCorrelation(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, correlationKey, id)
}
func WithSystem(ctx context.Context) context.Context { return context.WithValue(ctx, systemKey, true) }

// Capture makes a deep, bounded copy before admission/cancellation. New history
// excludes free text, emails and IPs; those are neither an identity authority nor
// necessary to verify security transitions. Legacy rows remain explicitly v0.
func Capture(ctx context.Context, in *models.AuditLog) (*models.AuditLog, error) {
	if in == nil || in.Event == "" || len(in.Event) > 40 || len(in.Action) > 40 {
		return nil, ErrIntegrity
	}
	tid := tenant.FromContext(ctx)
	if len(tid) > 36 || (in.TenantID != "" && in.TenantID != tid) {
		return nil, ErrIntegrity
	}
	e := *in
	e.ID = 0
	e.TenantID = tid
	e.Version = 1
	if e.EventID == "" {
		e.EventID = uuid.NewString()
	}
	if _, err := uuid.Parse(e.EventID); err != nil {
		return nil, ErrIntegrity
	}
	e.CreatedAt = time.Now().UTC().Truncate(time.Millisecond)
	e.ActorKind = "unauthenticated"
	e.ActorID = 0
	if id, ok := ctx.Value(actorKey).(uint); ok && id > 0 {
		e.ActorKind = "authenticated"
		e.ActorID = id
	} else if system, _ := ctx.Value(systemKey).(bool); system {
		e.ActorKind = "system"
	}
	e.RequestID, _ = ctx.Value(correlationKey).(string)
	if _, err := uuid.Parse(e.RequestID); err != nil {
		e.RequestID = uuid.NewString()
	}
	if in.UserID != nil {
		id := *in.UserID
		e.UserID = &id
	}
	e.Email = ""
	e.IPAddress = ""
	e.Detail = ""
	e.PrevHash = ""
	e.RecordHash = ""
	e.Sequence = nil
	e.KeyID = ""
	return &e, nil
}

// Keys is immutable after construction. Never persist key material beside rows.
type Keys struct {
	current           string
	signing           map[string][]byte
	checkpoints       map[string][]byte
	checkpointCurrent string
}

func NewKeys(current string, encoded map[string]string, checkpoint string) (*Keys, error) {
	return NewKeyRing(current, encoded, "checkpoint-v1", map[string]string{"checkpoint-v1": checkpoint})
}

// NewKeyRing supports independent signing and checkpoint key rotation. Retained
// keys verify only; Current selects the sole active signing key in each domain.
func NewKeyRing(current string, encoded map[string]string, checkpointID string, checkpoints map[string]string) (*Keys, error) {
	k := &Keys{current: current, signing: make(map[string][]byte), checkpoints: make(map[string][]byte), checkpointCurrent: checkpointID}
	if current == "" || len(current) > 64 || len(encoded) > 8 {
		return nil, ErrUnavailable
	}
	for id, value := range encoded {
		key, err := decodeKey(value)
		if id == "" || len(id) > 64 || err != nil {
			return nil, fmt.Errorf("invalid audit signing key configuration: %w", ErrUnavailable)
		}
		k.signing[id] = key
	}
	if _, ok := k.signing[current]; !ok {
		return nil, ErrUnavailable
	}
	if checkpointID == "" || len(checkpoints) > 8 {
		return nil, ErrUnavailable
	}
	for id, value := range checkpoints {
		cp, err := decodeKey(value)
		if id == "" || len(id) > 64 || err != nil {
			return nil, ErrUnavailable
		}
		for _, key := range k.signing {
			if bytes.Equal(key, cp) {
				return nil, errors.New("audit checkpoint key must be separate")
			}
		}
		k.checkpoints[id] = cp
	}
	if _, ok := k.checkpoints[checkpointID]; !ok {
		return nil, ErrUnavailable
	}

	return k, nil
}

func decodeKey(encoded string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(b) < 32 || len(b) > 128 || bytes.Equal(b, bytes.Repeat(b[:min(1, len(b))], len(b))) || strings.Contains(strings.ToLower(string(b)), "default") || strings.Contains(strings.ToLower(string(b)), "secret") {
		return nil, ErrUnavailable
	}
	return b, nil
}

// EphemeralKeys is for development/tests only. Production always calls NewKeys
// with external configuration; restart verification requires retained keys.
func EphemeralKeys() *Keys {
	a, b := make([]byte, 32), make([]byte, 32)
	if _, err := rand.Read(a); err != nil {
		panic(err)
	}
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	k, err := NewKeys("ephemeral-dev", map[string]string{"ephemeral-dev": base64.StdEncoding.EncodeToString(a)}, base64.StdEncoding.EncodeToString(b))
	if err != nil {
		panic(err)
	}
	return k
}

// Canonical is an ordered JSON array, with Unix milliseconds and integer IDs.
// This schema and the domain prefix are frozen by a golden fixture.
func Canonical(e *models.AuditLog) []byte {
	var seq uint64
	if e.Sequence != nil {
		seq = *e.Sequence
	}
	var subject uint
	if e.UserID != nil {
		subject = *e.UserID
	}
	b, _ := json.Marshal([]any{"finn.audit.event.v1", e.Version, e.EventID, e.TenantID, seq, e.PrevHash, e.KeyID, e.CreatedAt.UTC().UnixMilli(), e.ActorKind, e.ActorID, subject, e.RequestID, e.Event, e.Action, e.Success})
	return b
}

func mac(key, payload []byte) string {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write(payload)
	return hex.EncodeToString(h.Sum(nil))
}
func (k *Keys) Sign(e *models.AuditLog) {
	e.KeyID = k.current
	e.RecordHash = mac(k.signing[k.current], Canonical(e))
}
func (k *Keys) Verify(e *models.AuditLog) error {
	key, ok := k.signing[e.KeyID]
	if !ok || e.Version != 1 || e.Sequence == nil || *e.Sequence == 0 || !hmac.Equal([]byte(mac(key, Canonical(e))), []byte(e.RecordHash)) {
		return ErrIntegrity
	}
	return nil
}

// Checkpoint must be kept in a separately trusted store. A DB-only copy cannot
// prove truncation. It anchors all admitted events through Sequence.
type Checkpoint struct {
	Tenant   string `json:"tenant"`
	Sequence uint64 `json:"sequence"`
	Hash     string `json:"hash"`
	KeyID    string `json:"keyId"`
	MAC      string `json:"mac"`
}

func checkpointBytes(c Checkpoint) []byte {
	b, _ := json.Marshal([]any{"finn.audit.checkpoint.v1", c.Tenant, c.Sequence, c.Hash, c.KeyID})
	return b
}
func (k *Keys) Checkpoint(tid string, seq uint64, hash string) Checkpoint {
	c := Checkpoint{Tenant: tid, Sequence: seq, Hash: hash, KeyID: k.checkpointCurrent}
	c.MAC = mac(k.checkpoints[k.checkpointCurrent], checkpointBytes(c))
	return c
}
func (k *Keys) VerifyCheckpoint(c Checkpoint) error {
	key, ok := k.checkpoints[c.KeyID]
	if !ok || !hmac.Equal([]byte(mac(key, checkpointBytes(c))), []byte(c.MAC)) {
		return ErrIntegrity
	}
	return nil
}

func (k *Keys) HasKey(id string) bool { _, ok := k.signing[id]; return ok }
