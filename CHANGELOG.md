# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- §8: `.github/workflows/ci.yml` — Go 1.24 CI pipeline (`go vet`, `golangci-lint`, `go test -race -cover`, `go build`, `govulncheck`)
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
- Bumped `gin-gonic/gin` from v1.10.0 to **v1.12.0**
- Audit logging is now asynchronous via `AsyncAuditWriter` (wraps `AuditRepository`); wired in `main.go` with graceful flush on shutdown

### Removed
- Dead code `var _ = errors.New` compile-time guard (replaced by depguard linter rule)

### Notes
- The per-IP token-bucket limiter (`internal/middleware/rate_limit.go`) stays in-memory even when Redis is configured — only the newer velocity/lockout counters are Redis-backed
