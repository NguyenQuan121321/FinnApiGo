package services

import (
	"context"
	"crypto/rand" //nolint:gosec // CSPRNG for PKCE verifiers
	"crypto/sha1" //nolint:gosec // HIBP's k-anonymity protocol is defined over SHA-1 — not a security decision
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultHIBPEndpoint is the Pwned Passwords k-anonymity range endpoint.
const DefaultHIBPEndpoint = "https://api.pwnedpasswords.com/range/"

// BreachedPasswordChecker screens passwords against the Have I Been Pwned
// corpus (NIST SP 800-63B: verifiers SHALL check prospective passwords
// against compromised-credential lists). The protocol is k-anonymity safe:
// only the first 5 hex chars of the SHA-1 digest leave the process.
//
// FAILURE SEMANTICS — deliberately fail OPEN: any upstream error, timeout, or
// malformed response counts as "not breached". The screener is
// defense-in-depth; availability of the primary auth flows always wins, and
// H2-level hard failures must not gate registration/reset on a third-party
// API. The caller treats a nil checker the same way.
type BreachedPasswordChecker struct {
	endpoint string
	client   *http.Client
}

// NewBreachedPasswordChecker builds the screener. An empty endpoint selects
// the default HIBP range API. timeout bounds each check (recommended: a few
// seconds — the check runs inline on register/reset/set/change password).
func NewBreachedPasswordChecker(endpoint string, timeout time.Duration) *BreachedPasswordChecker {
	if endpoint == "" {
		endpoint = DefaultHIBPEndpoint
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &BreachedPasswordChecker{
		endpoint: endpoint,
		client:   &http.Client{Timeout: timeout},
	}
}

// Breached reports whether the plaintext password appears in the breach
// corpus. False on any failure (fail open) — never on a confirmed hit.
func (c *BreachedPasswordChecker) Breached(ctx context.Context, password string) bool {
	if c == nil || password == "" {
		return false
	}
	sum := sha1.Sum([]byte(password)) //nolint:gosec // protocol-defined digest
	digest := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix, suffix := digest[:5], digest[5:]

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint+prefix, nil)
	if err != nil {
		return false
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return false // fail open
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return false // fail open
	}
	// Bound the read: the range response is a few KB; refuse to buffer more.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToUpper(string(body)), suffix+":")
}

// pkceVerifier generates a fresh PKCE code verifier (S256): 64 CSPRNG bytes
// base64url-encoded — 86 chars, inside the RFC 7636 43..128 range, with the
// unreserved-character guarantee base64url provides.
func pkceVerifier() (string, error) {
	b := make([]byte, 64)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("pkce verifier: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
