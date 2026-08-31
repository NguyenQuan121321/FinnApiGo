package services

import (
	"context"
	"crypto/sha1" // #nosec G505 -- the HIBP k-anonymity protocol is defined over SHA-1; the digest never protects anything
	"encoding/hex"
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

// calculateHIBPSHA1Prefix returns the digest portions required by the HIBP
// Pwned Passwords k-anonymity range API. SHA-1 is mandated by that external
// protocol; it is never used for password storage, authentication, or
// password verification in this application.
func calculateHIBPSHA1Prefix(pwd string) (prefix, suffix string) {
	sum := sha1.Sum([]byte(pwd)) // #nosec G401 -- HIBP protocol-defined k-anonymity lookup digest
	digest := strings.ToUpper(hex.EncodeToString(sum[:]))
	return digest[:5], digest[5:]
}

// Breached reports whether the plaintext password appears in the breach
// corpus. False on any failure (fail open) — never on a confirmed hit.
func (c *BreachedPasswordChecker) Breached(ctx context.Context, password string) bool {
	if c == nil || password == "" {
		return false
	}
	// k-anonymity: only the first 5 hex chars of the protocol-defined digest
	// leave the process; the digest is never a protection mechanism.
	prefix, suffix := calculateHIBPSHA1Prefix(password)

	// The endpoint is operator configuration, never request input (no SSRF
	// surface); the suffix-only query leaks at most a 5-hex-char prefix.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint+prefix, nil) // #nosec G107 -- fixed operator-configured endpoint
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
