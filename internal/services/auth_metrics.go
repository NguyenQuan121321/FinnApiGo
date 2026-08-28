package services

import "sync/atomic"

// Fine-grained auth outcome counters (O3). Exported atomics wrapped as
// Prometheus counter funcs by internal/metrics — the v2 P2 pattern (no
// labels, so no user-identifying data can attach; G2).
//
// Semantics:
//   - LoginSuccesses: credentials verified (full token pair OR mfa_pending
//     issued). Rate-limited / CAPTCHA-gated / locked attempts do NOT count
//     here or in failures — those are policy throttles, not credential checks.
//   - LoginFailures: credential checks that rejected (unknown user, bad
//     password, disabled account).
//   - RefreshRotations: successful refresh-token rotations.
//   - TokenReuseDetections: presented refresh tokens refused because their
//     row was already revoked (theft response, also audited).
//   - TOTPFailures: failed TOTP code/recovery-code validations (bad code,
//     replay, brute-force lockout guard).
var (
	LoginSuccesses       atomic.Int64
	LoginFailures        atomic.Int64
	RefreshRotations     atomic.Int64
	TokenReuseDetections atomic.Int64
	TOTPFailures         atomic.Int64
)
