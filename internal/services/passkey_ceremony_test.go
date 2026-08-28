package services

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/gin-gonic/gin"

)

// softAuthenticator is a minimal software WebAuthn authenticator (9E's
// full-ceremony harness): it holds one ES256 key pair and produces valid
// attestation and assertion responses against the configured RP.
type softAuthenticator struct {
	priv       *ecdsa.PrivateKey
	credID     []byte
	rpID       string
	origin     string
	signCount  uint32
	userHandle []byte // the WebAuthn user handle the RP expects
}

func newSoftAuthenticator(rpID, origin string) (*softAuthenticator, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &softAuthenticator{priv: priv, credID: randomBytes(32), rpID: rpID, origin: origin}, nil
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// clientDataJSON builds the origin/challenge-bound client data.
func (a *softAuthenticator) clientDataJSON(typ, challengeB64 string) []byte {
	raw, _ := json.Marshal(map[string]any{"type": typ, "challenge": challengeB64, "origin": a.origin})
	return raw
}

// authData builds the authenticator data: rpIdHash || flags || signCount
// (+ attested credential data when attested).
func (a *softAuthenticator) authData(flags byte, counter uint32, attested bool) []byte {
	rpHash := sha256.Sum256([]byte(a.rpID))
	buf := bytes.NewBuffer(rpHash[:])
	buf.WriteByte(flags)
	_ = binary.Write(buf, binary.BigEndian, counter)
	if attested {
		buf.Write(bytes.Repeat([]byte{0}, 16)) // AAGUID (all zeros)
		credLen := len(a.credID)
		if credLen > 1023 {
			panic("credential id too long for L2 encoding")
		}
		_ = binary.Write(buf, binary.BigEndian, uint16(credLen)) // #nosec G115 -- bounded above
		buf.Write(a.credID)
		// COSE EC2 P-256 public key (algorithm -7).
		pub := a.priv.PublicKey
		cose := map[int64]any{
			1:  int64(2), // kty: EC2
			3:  int64(-7), // alg: ES256
			-1: int64(1),  // crv: P-256
			-2: pad32(pub.X.Bytes()),
			-3: pad32(pub.Y.Bytes()),
		}
		coseBytes, err := webauthncbor.Marshal(cose)
		if err != nil {
			panic(err)
		}
		buf.Write(coseBytes)
	}
	return buf.Bytes()
}

func pad32(b []byte) []byte {
	if len(b) == 32 {
		return b
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

func (a *softAuthenticator) attestationObject(authData []byte) []byte {
	obj, err := webauthncbor.Marshal(map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": authData,
	})
	if err != nil {
		panic(err)
	}
	return obj
}

func (a *softAuthenticator) sign(authData, clientDataHash []byte) []byte {
	joined := append(append([]byte{}, authData...), clientDataHash...)
	digest := sha256.Sum256(joined)
	sig, err := ecdsa.SignASN1(rand.Reader, a.priv, digest[:])
	if err != nil {
		panic(err)
	}
	return sig
}

// registrationResponse builds the JSON body FinishRegistration parses.
func (a *softAuthenticator) registrationResponse(challengeB64 string) []byte {
	ad := a.authData(0x45, a.signCount, true) // UP|UV|AT
	body := map[string]any{
		"id":    b64u(a.credID),
		"rawId": b64u(a.credID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64u(a.clientDataJSON("webauthn.create", challengeB64)),
			"attestationObject": b64u(a.attestationObject(ad)),
		},
	}
	raw, _ := json.Marshal(body)
	return raw
}

func cdHash(cd []byte) []byte {
	h := sha256.Sum256(cd)
	return h[:]
}

// assertionResponse builds the JSON body FinishLogin parses. When forceCount
// is set the authenticator reports that (possibly regressed) counter — the
// clone-detection scenario.
func (a *softAuthenticator) assertionResponse(challengeB64 string, forceCount *uint32) []byte {
	count := a.signCount + 1
	if forceCount != nil {
		count = *forceCount
	} else {
		a.signCount = count
	}
	ad := a.authData(0x05, count, false) // UP|UV
	cd := a.clientDataJSON("webauthn.get", challengeB64)
	body := map[string]any{
		"id":    b64u(a.credID),
		"rawId": b64u(a.credID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64u(cd),
			"authenticatorData": b64u(ad),
			"signature":         b64u(a.sign(ad, cdHash(cd))),
			"userHandle":        b64u(a.userHandle),
		},
	}
	raw, _ := json.Marshal(body)
	return raw
}

// ceremonyRequest wraps a raw body into the httptest request the service
// verifies against.
func ceremonyRequest(t *testing.T, body []byte) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

// extractChallenge pulls the challenge from the creation/assertion options.
func extractChallenge(t *testing.T, options any) string {
	t.Helper()
	raw, err := json.Marshal(options)
	if err != nil {
		t.Fatal(err)
	}
	var probe struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		t.Fatal(err)
	}
	if probe.PublicKey.Challenge == "" {
		t.Fatalf("no challenge in options: %s", raw)
	}
	return probe.PublicKey.Challenge
}

// userHandleFor mirrors the service's WebAuthnID derivation.
func userHandleFor(id uint) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(id))
	return buf
}

// TestPasskey_FullCeremonies_RegisterAndLogin_W4W5 — 9E's full-ceremony
// coverage: a software authenticator completes registration (attestation
// verified against RP ID + origin, credential persisted) and then
// authentication (assertion verified, sign counter advanced, token pair
// issued, device record touched).
func TestPasskey_FullCeremonies_RegisterAndLogin_W4W5(t *testing.T) {
	svc, repo, users, kv := newPasskeyTestService(t)
	u := pkUser(t, users, "pk-ceremony")
	ctx := context.Background()
	issuer := &fakePasskeyIssuer{}
	ps := svc.(*passkeyService)
	ps.tokens = issuer

	auth, err := newSoftAuthenticator("example.com", "https://example.com")
	if err != nil {
		t.Fatal(err)
	}

	// ---- registration ceremony (W4) ----
	options, err := svc.BeginRegistration(ctx, u.ID, PasskeyBeginInput{DisplayName: "Ceremony key"})
	if err != nil {
		t.Fatal(err)
	}
	reg := ceremonyRequest(t, auth.registrationResponse(extractChallenge(t, options)))
	row, err := svc.FinishRegistration(ctx, u.ID, reg)
	if err != nil {
		t.Fatalf("W4: registration ceremony failed: %v", err)
	}
	if row.DisplayName != "Ceremony key" || len(row.CredentialID) == 0 {
		t.Fatalf("W4: unexpected stored row: %+v", row)
	}
	stored, _ := repo.FindByCredentialID(ctx, auth.credID)
	if stored == nil || stored.SignCount != 0 {
		t.Fatalf("W4: credential not persisted correctly: %+v", stored)
	}

	// ---- authentication ceremony (W5) ----
	auth.userHandle = userHandleFor(u.ID)
	assert, err := svc.BeginAuthentication(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	login := ceremonyRequest(t, auth.assertionResponse(extractChallenge(t, assert), nil))
	result, err := svc.FinishAuthentication(ctx, u.ID, login)
	if err != nil {
		t.Fatalf("W5: authentication ceremony failed: %v", err)
	}
	if result.TokenPair.AccessToken == "" {
		t.Fatal("W5: standard token pair must be issued on success")
	}
	if issuer.issued != 1 {
		t.Fatalf("W5: token issuer called %d times, want 1", issuer.issued)
	}
	verified, _ := repo.FindByCredentialID(ctx, auth.credID)
	if verified.SignCount != 1 || verified.LastUsedAt == nil {
		t.Fatalf("W5: sign counter / last_used_at not maintained: %+v", verified)
	}
	_ = kv
}

// TestPasskey_FullCeremony_CloneDetectedEndToEnd_W5 — replaying an assertion
// (same sign counter) through the real library verification triggers the
// clone path: credential revoked, clone audit recorded, login refused.
func TestPasskey_FullCeremony_CloneDetectedEndToEnd_W5(t *testing.T) {
	svc, repo, users, _ := newPasskeyTestService(t)
	u := pkUser(t, users, "pk-clone-e2e")
	ctx := context.Background()
	issuer := &fakePasskeyIssuer{}
	ps := svc.(*passkeyService)
	ps.tokens = issuer

	auth, err := newSoftAuthenticator("example.com", "https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	options, err := svc.BeginRegistration(ctx, u.ID, PasskeyBeginInput{DisplayName: "Clone target"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.FinishRegistration(ctx, u.ID, ceremonyRequest(t, auth.registrationResponse(extractChallenge(t, options)))); err != nil {
		t.Fatal(err)
	}

	// First (honest) login advances the counter to 1.
	assert, err := svc.BeginAuthentication(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.FinishAuthentication(ctx, u.ID, ceremonyRequest(t, auth.assertionResponse(extractChallenge(t, assert), nil))); err != nil {
		t.Fatal(err)
	}

	auth.userHandle = userHandleFor(u.ID)
	// A cloned copy replays with a LOWER counter (2 < 3 after honest use).
	stale := uint32(1)
	assert2, err := svc.BeginAuthentication(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	cloneLogin := ceremonyRequest(t, auth.assertionResponse(extractChallenge(t, assert2), &stale))
	if _, err := svc.FinishAuthentication(ctx, u.ID, cloneLogin); err == nil {
		t.Fatal("W5: replayed/regressed assertion must be refused")
	} else if !strings.Contains(err.Error(), "sign counter") {
		t.Fatalf("W5: expected clone-detection error, got %v", err)
	}

	got, _ := repo.FindByCredentialID(ctx, auth.credID)
	if got == nil || !got.Revoked {
		t.Fatalf("W5: cloned credential must be revoked, got %+v", got)
	}
	if issuer.issued != 1 {
		t.Fatalf("W5: clone replay must not issue tokens (issuer=%d)", issuer.issued)
	}
	_ = gin.SetMode // keep gin import if ceremony helpers stop using it
	_ = protocol.VerificationPreferred
	_ = time.Now
}
