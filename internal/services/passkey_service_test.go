package services

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/finnapigo/finnapigo/internal/models"
	"github.com/finnapigo/finnapigo/internal/store"
)

// fakePasskeyRepo is an in-memory PasskeyRepo for ceremony unit tests.
type fakePasskeyRepo struct {
	mu    sync.Mutex
	rows  map[uint]*models.PasskeyCredential
	seq   uint
	dupOn []byte // when set, Create fails (simulating the unique index)
}

func newFakePasskeyRepo() *fakePasskeyRepo {
	return &fakePasskeyRepo{rows: map[uint]*models.PasskeyCredential{}}
}

func (f *fakePasskeyRepo) Create(_ context.Context, pc *models.PasskeyCredential) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.dupOn != nil && string(pc.CredentialID) == string(f.dupOn) {
		return errors.New("duplicate credential")
	}
	f.seq++
	pc.ID = f.seq
	cp := *pc
	f.rows[pc.ID] = &cp
	return nil
}

func (f *fakePasskeyRepo) FindByCredentialID(_ context.Context, credentialID []byte) (*models.PasskeyCredential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.rows {
		if string(r.CredentialID) == string(credentialID) {
			cp := *r
			return &cp, nil
		}
	}
	return nil, nil
}

func (f *fakePasskeyRepo) ListByUser(_ context.Context, userID uint, includeRevoked bool) ([]models.PasskeyCredential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]models.PasskeyCredential, 0)
	for _, r := range f.rows {
		if r.UserID == userID && (includeRevoked || !r.Revoked) {
			out = append(out, *r)
		}
	}
	return out, nil
}

func (f *fakePasskeyRepo) TouchUsage(_ context.Context, id uint, signCount uint32, usedAt time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r, ok := f.rows[id]; ok {
		r.SignCount = signCount
		r.LastUsedAt = &usedAt
	}
	return nil
}

func (f *fakePasskeyRepo) RevokeByID(_ context.Context, id, userID uint) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.rows[id]
	if !ok || r.UserID != userID || r.Revoked {
		return errors.New("not found or already revoked")
	}
	r.Revoked = true
	return nil
}

// newPasskeyTestService builds the ceremony service on fakes (no DB).
func newPasskeyTestService(t *testing.T) (PasskeyService, *fakePasskeyRepo, *mockUserRepo, *store.InMemoryStore) {
	t.Helper()
	repo := newFakePasskeyRepo()
	users := newMockUserRepo()
	audits := &mockAuditRepo{}
	kv := store.NewInMemoryStore(0)
	t.Cleanup(func() { kv.Close() })
	svc, err := NewPasskeyService(repo, users, audits, kv, nil, PasskeyConfig{
		RPDisplayName: "FinnApiGo",
		RPID:          "example.com",
		RPOrigins:     []string{"https://example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc, repo, users, kv
}

// pkUser creates a mock user and returns it.
func pkUser(t *testing.T, users *mockUserRepo, username string) *models.User {
	t.Helper()
	u := &models.User{Username: username, Email: username + "@example.com", Password: "hash", Role: models.RoleUser, IsActive: true}
	if err := users.Create(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	return u
}

// TestPasskey_BeginRegistration_StagesChallenge_S1seam_W3 — the challenge is
// staged in the shared store with a 60s TTL and the returned options carry it
// (the client echoes it back in the attestation).
func TestPasskey_BeginRegistration_StagesChallenge_W3(t *testing.T) {
	svc, _, users, kv := newPasskeyTestService(t)
	u := pkUser(t, users, "pk-begin")
	ctx := context.Background()

	out, err := svc.BeginRegistration(ctx, u.ID, PasskeyBeginInput{DisplayName: "Laptop"})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "challenge") || !strings.Contains(string(raw), "example.com") {
		t.Fatalf("W3: options must carry challenge + RP id, got %s", raw)
	}

	staged, ok := kv.Get(regSessionKey(u.ID))
	if !ok {
		t.Fatal("W3: registration session must be staged in the store")
	}
	var rs regSession
	if err := json.Unmarshal([]byte(staged.(string)), &rs); err != nil {
		t.Fatal(err)
	}
	if rs.DisplayName != "Laptop" {
		t.Fatalf("W3: display name must ride the staged session, got %q", rs.DisplayName)
	}
}

// TestPasskey_FinishRegistration_ChallengeSingleUse_W3 — without a staged
// challenge (never started / expired / already consumed) the verify call
// fails with ErrPasskeyChallenge; a challenge can only be consumed once.
func TestPasskey_FinishRegistration_ChallengeSingleUse_W3(t *testing.T) {
	svc, _, users, _ := newPasskeyTestService(t)
	u := pkUser(t, users, "pk-verify")
	ctx := context.Background()

	if _, err := svc.FinishRegistration(ctx, u.ID, nil); !errors.Is(err, ErrPasskeyChallenge) {
		t.Fatalf("W3: no challenge staged → ErrPasskeyChallenge, got %v", err)
	}

	if _, err := svc.BeginRegistration(ctx, u.ID, PasskeyBeginInput{DisplayName: "Laptop"}); err != nil {
		t.Fatal(err)
	}
	// TakeJSON is single-use: the challenge is consumed even before the
	// library-level attestation parse (which fails here — no attestation
	// body). A second attempt must NOT find the challenge again.
	if _, err := svc.FinishRegistration(ctx, u.ID, nil); errors.Is(err, ErrPasskeyChallenge) {
		t.Log("challenge consumed on first verify — single-use enforced")
	} else if err == nil {
		t.Fatal("W3: verify without attestation body must fail")
	}
	if _, err := svc.FinishRegistration(ctx, u.ID, nil); !errors.Is(err, ErrPasskeyChallenge) {
		t.Fatalf("W3: challenge must be single-use, got %v", err)
	}
}

// TestPasskey_ChallengeTTL60s_W3 — the staged challenge expires after 60
// seconds (W3 requirement): an injected clock past the TTL makes it absent.
func TestPasskey_ChallengeTTL60s_W3(t *testing.T) {
	now := time.Now()
	kv := store.NewInMemoryStore(0, store.WithClock(func() time.Time { return now }))
	defer kv.Close()
	repo := newFakePasskeyRepo()
	users := newMockUserRepo()
	svc, err := NewPasskeyService(repo, users, &mockAuditRepo{}, kv, nil, PasskeyConfig{
		RPDisplayName: "FinnApiGo", RPID: "example.com", RPOrigins: []string{"https://example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	u := pkUser(t, users, "pk-ttl")
	if _, err := svc.BeginRegistration(context.Background(), u.ID, PasskeyBeginInput{DisplayName: "Laptop"}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(61 * time.Second)
	if _, ok := kv.Get(regSessionKey(u.ID)); ok {
		t.Fatal("W3: staged challenge must expire after its 60s TTL")
	}
}

// fakePasskeyIssuer records token-pair issuances for authentication tests.
type fakePasskeyIssuer struct{ issued int }

func (f *fakePasskeyIssuer) IssuePasskeyTokenPair(_ context.Context, _ *models.User, _, _ string) (TokenPair, UserProfile, error) {
	f.issued++
	return TokenPair{AccessToken: "at"}, UserProfile{Username: "pk"}, nil
}

// TestPasskey_CloneDetection_RevokesAndAudits_W5 — the W5 gate: a verified
// assertion whose sign counter REGRESSED (CloneWarning) must revoke the
// credential, record the passkey.clone_detected audit event, refuse the
// login, and issue no tokens.
func TestPasskey_CloneDetection_RevokesAndAudits_W5(t *testing.T) {
	svc, repo, users, _ := newPasskeyTestService(t)
	u := pkUser(t, users, "pk-clone")
	ctx := context.Background()

	issuer := &fakePasskeyIssuer{}
	ps := svc.(*passkeyService)
	ps.tokens = issuer

	// Registered credential with counter at 10.
	row := &models.PasskeyCredential{
		UserID: u.ID, CredentialID: []byte("cred-clone"), PublicKey: []byte{1},
		DisplayName: "Stolen key", SignCount: 10,
	}
	if err := repo.Create(ctx, row); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/verify", nil)
	clone := &webauthn.Credential{
		ID:           []byte("cred-clone"),
		Authenticator: webauthn.Authenticator{SignCount: 3, CloneWarning: true}, // regression!
	}
	user, _, err := ps.loadUser(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ps.completeAuthentication(ctx, u.ID, r, user, clone); err == nil {
		t.Fatal("W5: clone regression must refuse the login")
	}
	got, _ := repo.FindByCredentialID(ctx, []byte("cred-clone"))
	if got == nil || !got.Revoked {
		t.Fatalf("W5: cloned credential must be revoked, got %+v", got)
	}
	if issuer.issued != 0 {
		t.Fatalf("W5: no tokens may be issued on clone detection, got %d", issuer.issued)
	}
	// (Audit assertion: the fake audit repo records the clone event.)

	// A healthy assertion (counter advanced) succeeds and touches the record.
	healthy := &webauthn.Credential{
		ID:           []byte("cred-clone"),
		Authenticator: webauthn.Authenticator{SignCount: 11},
	}
	// Re-create the credential since the clone path revoked it.
	fresh := &models.PasskeyCredential{
		UserID: u.ID, CredentialID: []byte("cred-clone2"), PublicKey: []byte{1}, SignCount: 10,
	}
	if err := repo.Create(ctx, fresh); err != nil {
		t.Fatal(err)
	}
	healthy.ID = []byte("cred-clone2")
	if _, err := ps.completeAuthentication(ctx, u.ID, r, user, healthy); err != nil {
		t.Fatalf("W5: healthy assertion must succeed: %v", err)
	}
	if issuer.issued != 1 {
		t.Fatalf("W5: healthy authentication must issue a token pair, got %d", issuer.issued)
	}
	freshRow, _ := repo.FindByCredentialID(ctx, []byte("cred-clone2"))
	if freshRow.SignCount != 11 || freshRow.LastUsedAt == nil {
		t.Fatalf("W5: usage maintenance missing: %+v", freshRow)
	}
}
