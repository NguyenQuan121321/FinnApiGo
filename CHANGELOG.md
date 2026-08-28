# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] — enterprise readiness (branch `feat/enterprise-readiness`)

Execution of the enterprise-readiness program. Catalog items K3, X1–X2,
S1–S3, O1–O3 and W1–W8 (key-provider seam, internal metrics listener, leader
election, distributed tracing, passkeys/WebAuthn) are scoped and pending —
see `docs/enterprise-review-reconciliation.md` for the full OPEN/DONE table.

### Added
- **JWT key rotation (K2)** — issued tokens carry a `kid` header (SHA-256
  fingerprint of the signing secret); `JWT_SECRET_PREVIOUS` enables a
  versioned keyset so rotation no longer invalidates every live session.
  HS256-only verification (C5) preserved; kid-less legacy tokens are accepted
  during the grace window. (`internal/jwt`)
- **Release-mode key policy (K1)** — booting with `GIN_MODE=release` without
  an explicit `RECOVERY_CODE_KEY` now refuses to start; dev mode keeps the
  JWT-secret derivation with a loud warning. Silent derivation is gone.
- **Log redaction (G2)** — a redacting `slog.Handler` wrapper
  (`internal/logging`) replaces values of known secret-shaped attribute keys
  (passwords, tokens, codes, cookies…) with `[REDACTED]` before they reach
  the sink, at any nesting depth, including pre-attached `logger.With` attrs.
- **Audit retention policy (G1)** — release mode with `AUDIT_RETENTION_DAYS`
  unset emits a boot warning (policy decision: warning, not failure —
  retention is a governance choice). Durable-audit-queue design note added at
  `docs/audit-durable-queue-design.md` (implementation remains a non-goal).
- **OpenAPI contract (A1)** — `docs/openapi.yaml` documents every public
  endpoint (envelope, request/response schemas, security schemes) and is the
  contract of record. The `internal/apidrift` test builds the real router and
  fails CI on any path/method drift between spec and code.
- **MySQL/Redis integration layer (T1)** — integration-tagged tests
  (`-tags=integration`) run against real service containers in CI:
  migration up/down + re-up proof (`TestMigrationUpDown_T1`), EXPLAIN plan
  assertions for every hot-path query (`TestRefreshRotationQueryPlan_D1`),
  and Redis fixed-window/guard semantics
  (`TestRedisStore_Integration_FixedWindowAndGuards_T1`).
- **Fuzz targets (T2)** — `FuzzJWTVerify` (parsing never panics, forged
  types rejected), `FuzzTOTPCodeValidation` (accepted codes are exactly
  well-formed 6-digit ASCII), `FuzzRecoveryCodeConsumption` (acceptance
  agrees with exact match against the active set). 30-second smoke per target
  in CI.
- **Coverage floors (T3)** — CI fails below 73.0% (`internal/services`) and
  91.0% (`internal/jwt`); ratchet up as coverage improves, never down.
- **Security scans (T4)** — dedicated blocking `gosec` run (0 findings) and
  a Trivy filesystem scan (go.mod vulnerabilities + Dockerfile/compose
  misconfiguration, HIGH/CRITICAL) in CI.

### Changed
- Phase-0 reconciliation committed at
  `docs/enterprise-review-reconciliation.md`: every external-review finding
  marked OPEN / ALREADY-DONE with symbol-level evidence; six review claims
  confirmed already fixed by the v2 hardening (CAS refresh revoke, used-token
  index, AutoMigrate gating, retention job, fail-fast config, DSN UTC).

### Verified (D1–D2, evidence in the enterprise phase report)
- All refresh-rotation and audit-purge queries are index-served on MySQL 8
  (EXPLAIN: `const` on `uni_refresh_tokens_token_hash`, `range` on
  `PRIMARY`, `ref`/`range` on the user/created-at indexes — zero full scans;
  asserted continuously by the integration suite).
- Rotation hot path (Create + FindByHash + CAS Revoke) benchmarks at ~14 ms
  per rotation against a local MySQL container, dominated by three sequential
  network round-trips; the raw-SQL rewrite was REJECTED with this evidence
  (GORM overhead is microseconds; query shapes are already optimal).

## [1.7] — v2 hardening (PR #4, `refactor/p0-correctness` and follow-ups)

Correctness, hardening, performance and reliability program (catalog
C1–C11, A1–A8, P1–P4, R1–R4).

### Security
- **C1** Refresh-token revocation via compare-and-set (`revoked = false`
  guard + RowsAffected) — of two concurrent refreshes exactly one wins;
  reuse is detected and audited.
- **C2** Recovery-code consumption compare-and-set — a code cannot be
  double-consumed by parallel requests.
- **C3** Atomic failed-login counter — parallel failures all persist toward
  lockout.
- **C4** Fixed-window `IncrBy` with TTL anchored at the first increment —
  counters reset under sustained load instead of staying locked.
- **C5** JWT verification enforces issuer, required `exp`, HS256-only.
- **C6** Sudo-gated re-enrollment can no longer disable active TOTP.
- **C7** TOTP shared secrets sealed at rest with AES-256-GCM (legacy
  plaintext rows lazily re-sealed on read).
- **C8** Durable single-use token enforcement survives a store flush
  (DB-backed jti guard as the backstop).
- **C9** Login/TOTP successes no longer feed the failure windows.
- **C10** Lockout cleared on password change; registration survives an email
  outage (account persisted, audit records the send failure).
- **C11** Re-registration of a stale unverified account completes instead of
  leaking existence.
- **A1** Store failure semantics split — counters fail OPEN (a Redis outage
  must not become an auth outage), single-use guards fail CLOSED.
- **A2** SMTP client: deadlines, context propagation, mandatory TLS transport.
- **A3** Baseline security headers on every response (nosniff, no-referrer,
  `Cache-Control: no-store`, optional HSTS via `HSTS_SECONDS`).
- **A4** Auth denials log client IP + request id; request log gains
  `client_ip`.
- **A5** Rate limiting on the public token-consumption endpoints (refresh,
  reset, verify).
- **A6** Audit writer: dropped-entry metric, `Detail` truncation, insert-loss
  visibility.
- **A7** Access tokens embed the password version (`pwdver`) and are revoked
  on credential change.
- **A8** Console notifier refuses to log live tokens in release mode.
- Shared global and per-IP verification-email resend circuit breakers;
  blocked abuse is audited.
- Passwords rejected above bcrypt's 72-byte limit during hashing and
  comparison, preventing credential confusion from bcrypt truncation.

### Performance
- **P1** Indexed, LIMIT-batched purge jobs replace OR-scan deletes.
- **P2** Prometheus `/metrics` with process + custom availability metrics
  (`finnapigo_store_errors_total`, `finnapigo_audit_entries_dropped_total`,
  `finnapigo_rate_limited_requests_total`, `finnapigo_audit_buffer_depth`).
- **P3** `net/http/pprof` on an internal port gated by `PPROF_ADDR`.
- **P4** k6 load scenarios for login + refresh rotation with documented
  baselines.
- AES-256-GCM cipher block computed once at startup instead of per call;
  in-memory store sweeper deletes expired keys in bounded batches; graceful
  shutdown drains the async audit writer before closing the DB pool.

### Reliability
- **R1** golang-migrate replaces boot-time AutoMigrate (`MIGRATE_AUTO=true`
  is the dev-only escape hatch; production migrates via `cmd/migrate`).
- **R2** Fail-fast config loader — invalid numeric/duration/bool env values
  refuse to boot; `DB_TLS` values validated.
- **R3** DSN pins `loc=UTC` — DATETIME round-trips normalize to UTC.
- **R4** Audit retention purge job behind `AUDIT_RETENTION_DAYS`.
- Redis store failure semantics split (counters fail open, `SetNX` guards
  fail closed); INCRBY+PEXPIRE run as one atomic Lua script.
- Request IDs are UUIDv4 (the previous generator always emitted `00000000`
  as the tail); `recordFailedLogin` failures are logged, not dropped.

### Quality
- Structured `log/slog` JSON logging with observable audit writes; hardened
  `.golangci.yml` (gosec, gocritic, exhaustive, nilerr, errorlint, unused,
  ineffassign) — 0 issues.
- Removed the legacy email-OTP MFA feature entirely — TOTP is the only MFA
  mechanism.
- Services consume `store.Store` directly; the KV contract has one
  definition.

## [1.6] - 2026-08-07

### Security
- Added shared global and per-IP verification-email resend circuit breakers, alongside the existing per-email cap; blocked abuse is audited.
- Reject passwords above bcrypt's 72-byte limit during hashing and comparison, preventing credential confusion from bcrypt truncation.
- Added HTTP tests for malformed input, sentinel-error status mapping, protected-route missing-identity handling, response envelopes, and request-log redaction.

### Quality
- Added tests for hash primitives, configuration loading/defaults, response envelopes, handlers, route wiring, and all GORM repositories.
- Repository tests use per-test in-memory SQLite databases; MySQL error-code-specific duplicate mapping remains covered at the service boundary.
- Added the pure-Go `github.com/glebarez/sqlite` test dependency; no CGO runtime dependency was added.

## [1.5] - 2026-08-05

### Security
- §1.1: Register no longer leaks verification token in response; delivered via `Notifier.SendEmailVerification`
- §1.2: `SMTPNotifier` implemented using `net/smtp`; selected when `SMTP_HOST` is set, `ConsoleNotifier` fallback with warning
- §1.3: Rate limiter tracks `lastSeen` per IP with background sweeper for TTL eviction (fixes OOM); `RedisStore` added for multi-instance shared state
- §1.4: All repository methods accept `context.Context`; all GORM calls use `.WithContext(ctx)`
- §1.5: OTP comparison uses `crypto/subtle.ConstantTimeCompare` (timing side-channel fix)
- §1.6: Login runs bcrypt against a dummy hash when user not found (timing equalization)
- §1.7: `mapDuplicateKey` uses `errors.As(err, &*mysql.MySQLError)` + `Number==1062` (replaces fragile string matching)
- §1.8: Reset/verify tokens carry `jti` (UUID); single-use enforced via `Store.SetNX` + `UsedToken` DB table
- §1.9: Removed dead code `var _ = errors.New`
- §2: CAPTCHA (Turnstile) on `/register`, disposable email blocklist, registration velocity limiting (per-IP via store), honeypot field
- §2: `RequireEmailVerified` configurable gate on login (default `false` — policy decision documented)
- §3: Per-email login rate limiter via `store.IncrBy` (shared across instances)
- §3: Adaptive CAPTCHA after N failed logins from an IP
- §3: Exponential lockout backoff via `MaxLockoutMultiplier` (tracked in store, 24h window)
- §4: Refresh token reuse detection — presenting a revoked token revokes ALL tokens + logs `token_reuse` audit event
- §4: Explicit AuthMiddleware tests proving reset/verify-email tokens are rejected (401)
- §5: Global body-size cap via `http.MaxBytesReader` applied in `routes.Register` (fixed no-op ordering bug)
- §5: Password max-length cap (128 chars), max-length validation on all DTO fields
- §5: Per-user OTP send rate limit via `store.IncrBy`

- `POST /api/v1/auth/logout-all` endpoint (sign-out-everywhere)
- `GET /readyz` health check with DB ping
- `X-Request-ID` correlation middleware
- Graceful shutdown with SIGINT/SIGTERM handling
- `RedisStore` (`internal/store/redis.go`) — `store.Store` backed by `go-redis/v9`
- `InMemoryStore` with background sweeper for single-instance dev
- `UsedToken` model and repository (jti durability backstop)
- `ErrRateLimited`, `ErrCaptchaRequired` sentinel errors
- 11 dedicated hardening tests in `hardening_test.go`
- §7: Async audit logging via `AsyncAuditWriter` (buffered channel + background batch worker; sync fallback when `AUDIT_BUFFER_SIZE=0`)
- §7: `ARCHITECTURE.md` documenting extension patterns for future modules
- §8: `.github/workflows/ci.yml` — CI pipeline (`go vet`, `golangci-lint`, `go test -race -cover`, `go build`, `govulncheck`)
- §8: `.golangci.yml` — linter config (govet, staticcheck, errcheck, gosec, depguard)
- §8: `CHANGELOG.md`
- 7 new `AuthMiddleware` / `RequireRole` tests in `internal/middleware/auth_test.go`
- 2 new `AsyncAuditWriter` tests in `internal/services/async_audit_test.go`

### Changed
- `/healthz` returns process liveness only; `/readyz` checks DB connectivity
- `RegisterResponse` no longer includes `VerifyEmailToken`
- `AuthService` and `MFAService` constructors accept `RateLimitConfig` and `CaptchaVerifier`
- Velocity limiters now use `store.IncrBy` (shared when Redis is configured)
- `isMySQLDup` uses `errors.As` instead of string matching
- Bumped `gin-gonic/gin`
- Audit logging is now asynchronous via `AsyncAuditWriter` (wraps `AuditRepository`); wired in `main.go` with graceful flush on shutdown

### Removed
- Dead code `var _ = errors.New` compile-time guard (replaced by depguard linter rule)

## [1.0.0] — initial public release

Core auth (register, login, refresh rotation, password reset, email
verification), TOTP MFA with single-use recovery codes, session & device
management, Google OAuth sign-in, per-IP/per-account rate limiting, lockout
with exponential backoff, audit logging, in-memory/Redis store seam, Bruno
collection, k6 load scripts.
