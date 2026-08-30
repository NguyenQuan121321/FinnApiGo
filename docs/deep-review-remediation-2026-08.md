# Deep-Review Remediation — 2026-08-31

The 2026-08-31 deep review (five independent review streams: auth core,
MFA/passkey/OAuth ceremonies, infrastructure concurrency, CI/CD audit,
consistency sweep) found real logic bugs that automated tooling cannot see.
This document maps every finding to its fix. Severity reflects the reviewer
consensus at discovery time.

## High-severity fixes

| # | Finding | Fix |
|---|---------|-----|
| H1 | **Passkey login bypassed account deactivation.** `IssuePasskeyTokenPair` and the WebAuthn ceremonies never checked `IsActive`, so a disabled account could still mint sessions via a registered passkey — the only issuance path missing the gate password login, OAuth, and refresh all enforce. | `IsActive` enforced in `passkeyService.loadUser` (covers every ceremony) AND in `AuthService.IssuePasskeyTokenPair` (defense in depth). Pinned by `TestPasskeyIssuanceDisabledAccountRejected`. |
| H2 | **Adaptive CAPTCHA gate silently dead under Redis.** The per-IP failure counter was read with a bare `v.(int64)` assertion; Redis hands counters back as strings, so the gate evaluated `0 >= 5` forever and never fired in multi-instance mode. | The read goes through `storeCounterValue` (the existing Redis-parity helper), and the key is built by `ipCounterKey`. Pinned by `TestLoginAdaptiveCaptchaReadsRedisCounters` (string-encoded counter shape). |

## Security-semantics fixes (review Medium severity)

### OAuth / Google sign-in

1. **Unverified-email auto-linking (takeover pattern)** — a Google identity
   matching an existing local account promoted `is_email_verified` and linked
   unconditionally. Now: the persisted identity row `(provider, sub)` is the
   source of truth for returning users (a Google-side email change cannot fork
   or hijack the login); email-match linking is allowed ONLY when the local
   account's email was already verified; otherwise the flow refuses with
   `ErrOAuthEmailTaken` (409). Pinned by
   `TestOAuthCallbackUnverifiedEmailConflict` and
   `TestOAuthCallbackResolvesByIdentityRow`.
2. **Login CSRF / no PKCE / no nonce** — the state parameter was unbound to
   the browser, and the flow had no PKCE or nonce. Now: `/google/login` sets
   an HttpOnly, SameSite=Lax state cookie (double-submit check at the
   callback), the exchange carries a PKCE S256 verifier stored with the
   challenge, and the ID token's `nonce` claim is verified against the
   challenge. State consumption is atomic (`Store.Take`) — replay-proof on
   every backend.
3. **`/auth/google/login` was the only unauthenticated endpoint without the
   rate limiter** — a cheap unauthenticated store-flooding vector. The route
   now carries `RateLimit.Handler()`.

### WebAuthn / passkey

4. **Challenge double-spend** — `takeJSON` did Get-then-Delete; two
   concurrent finishes could both complete one ceremony. `Store.Take` makes
   consumption atomic on both backends (Redis via Lua GETDEL-equivalent).
5. **User Verification not required** — passkey success issues a full session
   (bypassing TOTP), so presence-only assertions (security key without PIN)
   are not enough. Both ceremonies now request `VerificationRequired`; the
   library enforces the session's request at finish.

### Password flows

6. **Non-transactional credential changes** — `ChangePassword`/`ResetPassword`
   ran password update, lockout reset, pwd-version bump, and refresh-token
   revocation as four auto-commit statements; a crash mid-sequence left the
   password changed while attacker refresh tokens survived. New
   `UserRepository.CredentialChangeTx` applies the whole sequence in ONE
   transaction (capability interfaces keep test mocks working; fallback path
   preserved and tested).
7. **`SetPassword` check-then-act** — the first-password guard is now a
   conditional `UPDATE ... WHERE password = ''` (`UserRepository.SetFirstPassword`),
   closing the two-concurrent-setters race.
8. **Swallowed `MarkUsed` errors + hardcoded 24h jti TTL** — the durable
   single-use backstop's failure was silently ignored, and the volatile jti
   window could lapse below a long-lived token's validity. Errors now fail
   the flow (fail-closed) and the TTL derives from the token's own expiry.

### Account enumeration

9. **Timing oracle on OAuth-only accounts** — they hold `Password == ""` and a
   direct bcrypt call failed in microseconds. The dummy-hash equalization now
   covers the empty-password shape. `ForgotPassword` runs the same equalization
   for unknown emails instead of returning immediately.

### Background jobs & shutdown

10. **Leader election TOCTOU** — `Get`→`Renew`/`Delete` carried no ownership
    proof; a lapsed lock could be extended by its former owner while a new
    leader held it (two leaders). `store.OwnerLockManager` adds atomic
    compare-and-renew / compare-and-delete (Lua on Redis, mutex-guarded in
    memory) keyed by the owner value.
11. **`LeaderRunner.Stop` never canceled the job context** (contract violation)
    and jobs could start after the DB pool closed. Stop now cancels a
    runner-scoped job context; `main.go` stops jobs explicitly BEFORE the
    audit writer and pool close instead of via a last-running defer.
12. **Audit writer failure modes** — a wedged MySQL could hang shutdown
    forever (unbounded flush context), a worker panic died silently, and
    `Record` after `Close` panicked on a closed channel. The flush is bounded
    (10s), panics are recovered, Close is bounded (10s) with a loud log, and
    post-Close `Record` falls back to a synchronous write. The buffer channel
    is never closed, eliminating the send-on-closed race.

### Resource exhaustion

13. **Unbounded per-IP key cardinality** — three unauthenticated counters
    minted attacker-keyed state with hour TTLs; IPv6 /64 rotation could evict
    `jti:`/replay keys or OOM the in-memory store. `ipCounterKey` collapses
    IPv6 sources to their /64 prefix (IPv4 verbatim).
14. **SMTP delivery unbounded in total** — per-command deadlines allowed a
    stalled relay to pin a request goroutine ~80s. One overall 45s cap bounds
    every send.

### TOTP

15. **`VerifyEnable` double-submit** — two concurrent verifications both
    activated and the last writer replaced the first client's fresh recovery
    codes. A per-user rotation lock (shared store, 10s TTL) serializes
    `Enable`/`VerifyEnable` critical sections.

## Consistency & completeness fixes

- **`TouchLastActive` removed** (interface, repo, mocks, tests): rotation
  creates a fresh row stamped "now" — the bump method was dead code implying
  a feature that did not exist. The sessions list ordering is untouched.
- **`.env.example` rewritten**: 5 dead `OTP_*` variables removed, 9 missing
  variables added (`DB_TLS`, `MIGRATE_AUTO`, `JWT_SECRET_PREVIOUS`,
  `TRUSTED_PROXIES`, `CORS_ALLOWED_ORIGINS`, `HSTS_SECONDS`, `PPROF_ADDR`,
  `TOTP_MAX_CONCURRENT`, `AUDIT_RETENTION_DAYS`), placeholders made real,
  Redis critical-path caveat documented, "not yet wired" audit comment
  corrected. The file now documents exactly what `internal/config` reads.
- **Log redaction list extended** (`secret_key`, `private_key`, `credentials`,
  `dsn`).
- **README** refreshed (toolchain row, config table rows for the new
  variables, Bruno base-URL note).
- **Bruno collection refreshed**: dead `send-otp`/`verify-otp` requests and
  the misnamed `OAuth-google.yml` (a duplicate of login) removed; missing
  requests added (`logout-all`, `session-revoke`, `google-login`,
  `google-callback`, `metrics`, and a full Passkey folder). The collection
  now covers every route the router registers.
- **Context seams closed**: geo resolution and passkey repo lookups thread
  the request context instead of `context.Background()`.

## New security capabilities (deliberate product decisions)

1. **Breached-password screening** (`BREACHED_PASSWORD_CHECK`, default on) —
   NIST SP 800-63B requires checking prospective passwords against
   compromised-credential corpora. Implemented via the Pwned Passwords
   k-anonymity range API: only a 5-hex-char SHA-1 prefix leaves the process,
   the check fails OPEN on outage, and hits are refused with `ErrPasswordBreached`
   (422) on register/reset/set/change.
2. **New-IP login notification** (`LOGIN_NOTIFY_NEW_IP`, default on) — a
   TRANSPARENT email on the first login from a previously unseen IP
   (30-day lookback per user+IP, fire-and-forget, no secrets in the message).
   **Deliberately NOT risk-based authentication**: no step-up, no blocking,
   no extra prompts — the login flow is one-shot and identical everywhere.
   The email is the user-visible audit trail; operators who want silence set
   the flag to `false`.

## CI/CD hardening (theater audit follow-ups)

- **Scanners pinned**: `govulncheck@v1.7.0`, `gosec@v2.29.0` (were `@latest` —
  non-reproducible and a supply-chain hole in the very job that preaches
  pinning).
- **The container image is now BUILT in CI** and scanned with Trivy
  (`image` job) — previously the Dockerfile was never executed before Render.
- **Integration skip-proof**: a guard test in each integration package fails
  the job in CI when `TEST_MYSQL_DSN`/`TEST_REDIS_URL` are missing instead of
  letting every test silently skip to green.
- **Coverage floors extended** from 2 to 14 packages (ratchet semantics
  unchanged: raise, never lower).
- **Fuzz honesty**: the JWT fuzzer's cross-keyset assertion was unreachable
  (both managers shared the same current secret → same kid); the fixture now
  uses a genuinely different keyset. The recovery-code fuzzer drives the same
  `hash.MatchRecoveryCode` function the service uses — it can no longer drift
  from the system it guards.
- **New `security.yml` workflow**: CodeQL (Go dataflow SAST beyond gosec) and
  a PR `dependency-review` gate (blocks PRs introducing HIGH+ vulnerabilities).
- **Workflow hygiene**: stale `feat/enterprise-readiness` trigger removed,
  `concurrency` group cancels superseded runs, `timeout-minutes` on every
  job, top-level `permissions: contents: read` (artifact upload scoped where
  needed).

## Verification

- `go build ./...`, `go vet ./...` (also with `-tags=integration`) — clean.
- `go test ./...` — 19/19 packages pass, including the new regression tests
  in `review_remediation_test.go` and the rewritten OAuth ceremony tests.
- `golangci-lint run` (v2.12.2) — 0 issues.
- `govulncheck ./...` — 0 reachable vulnerabilities.
- Workflow YAML parse-checked.

## Known remaining trade-offs (documented, not forgotten)

- **Sudo tokens are multi-use within their TTL** — single-use consumption
  would force a TOTP re-entry per sensitive action, which is worse UX; the
  token is minted only after a fresh TOTP proof and every sudo route requires
  a live access token, so the residual risk is bounded by session theft.
- **Redis outage blast radius** — with `REDIS_URL` set, single-use guards
  fail CLOSED: refresh rotation, MFA replay, and OAuth state pause during a
  Redis outage (documented in `.env.example`). Counters fail OPEN. The split
  is deliberate: replay prevention outranks availability.
- **apidrift certifies the fully-configured router** — the OpenAPI contract
  includes OAuth/passkey routes that are absent when the features are
  unconfigured. This is intentional (the contract of record); deployments
  see only their configured subset.
- **Geo location is a stub** (`location_estimate` = "Unknown") — the resolver
  seam is ready for a provider; none is wired to avoid third-party IP-data
  dependencies.
