# FinnApiGo

Authentication & MFA backend written in **Go**, built as a reusable module (`handler → service → repository`) meant to plug into larger applications. Implements core auth (register, login, refresh-token rotation, password reset, email verification) plus TOTP-based two-factor verification, with the security hardening a production system needs: rate limiting, lockout, single-use tokens, audit logging, session & device management, and an optional Redis backend for multi-instance deployments.

> **Naming note:** "MFA" here means TOTP-based two-step verification. It is unrelated to OAuth 2.0 — nothing in this codebase is an OAuth/third-party login flow (Google sign-in is a separate, optional feature).

---

## Features

- **Core auth** — register, login, logout, logout-all, refresh-token (with rotation + reuse detection), forgot/reset password, change password, set-password (OAuth-only accounts), email verification, resend verification, profile (`/me`)
- **MFA — TOTP** — RFC 6238 time-based one-time passwords with QR provisioning, single-use recovery codes, brute-force protection, and concurrency-gated CPU-bound verification
- **Session & device management** — list all active devices (IP, user-agent, device name, location estimate, last active), revoke individual sessions, IDOR-protected revocation, metadata populated on every login and refresh
- **Security hardening**
  - Passwords hashed with bcrypt (72-byte cap enforced), never stored or logged in plaintext
  - Access tokens are short-lived JWTs; refresh tokens are opaque, stored as SHA-256 hashes, and **rotated** on every use — presenting an already-used refresh token revokes every session for that user (theft response)
  - **JWT key rotation** — issued tokens carry a `kid` header; set `JWT_SECRET_PREVIOUS` during a rotation so existing sessions survive until expiry
  - **Release-mode key policy** — `GIN_MODE=release` refuses to boot without an explicit `RECOVERY_CODE_KEY` (no silent derivation from `JWT_SECRET`)
  - **At-rest sealing** — TOTP secrets and re-viewable recovery codes are sealed with AES-256-GCM
  - Reset/verify-email tokens are single-use (tracked by JWT ID, durable DB backstop)
  - Timing-safe comparisons for TOTP verification; login response time is equalized for unknown vs. wrong-password accounts to resist enumeration
  - Account lockout after repeated failed logins, with optional exponential backoff for repeat offenders
  - Per-IP **and** per-account rate limiting on login; per-IP registration velocity limiting; rate limits on all public token-consumption endpoints
  - Verification-email resend protection with per-email, shared per-IP, and shared global circuit-breaker limits; blocked abuse is audited
  - Optional CAPTCHA (Cloudflare Turnstile) on registration and adaptively after repeated login failures
  - Disposable-email domain blocking and a honeypot field on registration
  - Global request body-size cap and baseline security headers (nosniff, no-referrer, `no-store`, optional HSTS)
  - **Log redaction** — a structural `slog` handler guarantees secret-shaped attributes (passwords, tokens, codes) never reach the log output
  - Structured audit log (login, failed login, logout, password change/reset, token reuse, session revocation) with IP + request-ID correlation, async buffered writes, and a dropped-entry metric
  - Reverse-proxy-aware IP resolution via configurable trusted proxies (`TRUSTED_PROXIES`); defaults to trust-no-one
  - Concurrency limiter middleware (semaphore) caps parallel CPU-bound TOTP verifications to prevent resource exhaustion
- **Performance**
  - Sonic JSON parser (`bytedance/sonic`) with `sync.Pool` buffer recycling for zero-alloc request body parsing on hot paths
  - Indexed, LIMIT-batched purge jobs; every hot-path query verified index-served by EXPLAIN assertions against real MySQL
- **Pluggable storage backend** — in-memory by default (single instance); set `REDIS_URL` to share rate-limit counters and single-use-token state across multiple instances, no code changes required
- **Pluggable email delivery** — logs to console by default; set `SMTP_*` to send real email
- **Pluggable geo-resolver** — `NoOpResolver` returns `"Unknown"` by default; inject a GeoIP resolver for IP-to-location mapping on sessions
- **Graceful shutdown**, `/healthz` (liveness) and `/readyz` (DB connectivity) endpoints for orchestration
- Every response follows one JSON envelope: `{ "code": ..., "message": ..., "data": ... }`

---

## Tech stack

| Layer | Choice |
|---|---|
| Language | Go 1.25 |
| HTTP framework | [Gin](https://github.com/gin-gonic/gin) |
| ORM / DB | [GORM](https://gorm.io) + MySQL 8 (golang-migrate SQL migrations) |
| Auth tokens | [golang-jwt/jwt](https://github.com/golang-jwt/jwt) v5 (HS256, `kid`-keyed rotation) |
| Password hashing | `golang.org/x/crypto/bcrypt` |
| TOTP | RFC 6238 via `github.com/pquerna/otp` |
| JSON parsing | [sonic](https://github.com/bytedance/sonic) (AST-based, `sync.Pool` recycled buffers) |
| Rate limiting | `golang.org/x/time/rate` (per-instance) + a `store.Store` abstraction for shared counters |
| Observability | Prometheus client (`/metrics`), structured `slog` JSON with redaction |
| Optional shared store | Redis via `github.com/redis/go-redis/v9` |
| Config | Environment variables / `.env` via `godotenv` |
| Load testing | [k6](https://k6.io) scripts in `tests/load/` |
| API contract | OpenAPI 3.0 at `docs/openapi.yaml`, drift-checked in CI |

---

## Architecture

```
Handler  ->  Service  ->  Repository  ->  DB
 (HTTP)      (logic)      (queries)
```

- **Handlers** (`internal/handlers`) parse the request and format the response. They never touch GORM directly.
- **Services** (`internal/services`) hold all business logic. They never import Gin (depguard enforces), so every rule (lockout, rotation, single-use tokens, rate windows, TOTP) is unit-tested with in-memory fakes — no database or HTTP server needed.
- **Repositories** (`internal/repositories`) are thin, context-aware GORM wrappers with no business logic.
- **`store.Store`** (`internal/store`) is a small key-value interface (`Get`/`Set`/`SetNX`/`IncrBy`/`Delete`, all TTL-aware) used for rate-limit counters and single-use-token tracking. `InMemoryStore` is the default; `RedisStore` implements the same interface for multi-instance deployments. Failure semantics are split: counters fail open, single-use guards fail closed.
- **`jwt`** (`internal/jwt`) — purpose-bound tokens over a versioned keyset: `kid`-stamped issuance, `JWT_SECRET` + `JWT_SECRET_PREVIOUS` verification, HS256-only.
- **`logging`** (`internal/logging`) — redacting slog handler decorator (secret-shaped attributes become `[REDACTED]` before any sink).
- **`crypto` / `hash`** — AES-256-GCM sealing for at-rest secrets that must be re-read; bcrypt + SHA-256 + constant-time compare for everything one-way.
- **`metrics`** (`internal/metrics`) — Prometheus registry: process/Go collectors plus `finnapigo_store_errors_total`, `finnapigo_audit_entries_dropped_total`, `finnapigo_rate_limited_requests_total`, `finnapigo_audit_buffer_depth`.
- **`apidrift`** (`internal/apidrift`) — CI test that diffs the registered router against `docs/openapi.yaml` in both directions.
- **`device`** (`internal/device`) — zero-dependency User-Agent parser producing human-readable labels (e.g. "Chrome on Windows").
- **`geo`** (`internal/geo`) — mockable IP-to-location resolver interface; `NoOpResolver` returns `"Unknown"`, production can inject a GeoIP implementation.

### Project structure

```
FinnApiGo/
├── cmd/server/main.go          # config -> DB -> keys -> wire dependencies -> serve
├── cmd/migrate/main.go         # deploy-step migration runner (up | down | force | version)
├── internal/
│   ├── config/                 # env loading, typed config structs, fail-fast validation
│   ├── database/               # GORM/MySQL connection + embedded golang-migrate runner
│   ├── models/                 # User, RefreshToken, TOTPDevice, RecoveryCode, AuditLog, UsedToken, OAuthIdentity
│   ├── repositories/           # GORM-backed repos (context-aware queries only)
│   ├── services/               # business logic — auth, TOTP, notifier, CAPTCHA, async audit
│   ├── handlers/               # HTTP layer: parse -> call service -> respond (sonic JSON, sync.Pool)
│   ├── middleware/             # auth, rate limiter, concurrency limiter, security headers, sudo
│   ├── routes/                 # route registration + request logging + trusted proxies
│   ├── store/                  # Store interface, in-memory + Redis implementations
│   ├── hash/                   # bcrypt password and SHA-256 token primitives
│   ├── jwt/                    # JWT issuance/verification over a versioned keyset (kid)
│   ├── crypto/                 # AES-256-GCM sealing for at-rest secrets
│   ├── logging/                # redacting slog handler decorator
│   ├── metrics/                # Prometheus registry
│   ├── apidrift/               # OpenAPI <-> router drift check (A1)
│   ├── device/                 # User-Agent -> human-readable device label parser
│   ├── geo/                    # IP-to-location resolver interface (NoOp default)
│   └── response/               # HTTP response envelope
├── migrations/                 # embedded golang-migrate SQL pairs
├── docs/
│   ├── openapi.yaml            # API contract of record (A1)
│   ├── enterprise-review-reconciliation.md
│   └── audit-durable-queue-design.md
├── tests/load/                 # k6 load test scripts (login, refresh rotation)
├── .github/workflows/ci.yml   # CI: vet, lint, test, integration (MySQL+Redis), fuzz, coverage floors, gosec, trivy
├── .golangci.yml               # linter config (govet, staticcheck, errcheck, gosec, depguard)
├── ARCHITECTURE.md             # extension patterns & module guide
├── CHANGELOG.md                # all hardening changes (Keep a Changelog format)
├── docker-compose.yml          # MySQL for local dev
├── Dockerfile                  # multi-stage build, non-root runtime user
└── .env.example
```

---

## Getting started

### 1. Start MySQL

```bash
docker compose up -d db
```

### 2. Configure

```bash
cp .env.example .env
```

At minimum:

- `JWT_SECRET` — any long random string (`openssl rand -hex 32`); the app refuses to start without one.
- `RECOVERY_CODE_KEY` — required whenever `GIN_MODE=release` (64 hex chars, `openssl rand -hex 32`). In dev it may be left unset and is derived from `JWT_SECRET` with a loud warning.

### 3. Apply the schema and run

```bash
go mod tidy
go run ./cmd/migrate up     # apply embedded migrations (deploy step)
go run ./cmd/server
```

Servers do not auto-migrate at boot. `MIGRATE_AUTO=true` re-enables GORM AutoMigrate as a dev-only escape hatch.

### 4. Run the tests

```bash
go test ./...                                    # unit suite
go test -tags=integration ./... -count=1         # + integration (skipped without DB/Redis env)
TEST_MYSQL_DSN='test:testpw@tcp(127.0.0.1:3306)/finnapigo_test?multiStatements=true' \
TEST_REDIS_URL='redis://127.0.0.1:6379/0' \
    go test -tags=integration ./internal/database/ ./internal/store/ -v   # against real backends
```

The CI pipeline runs `go test -race -cover`, `go vet`, `golangci-lint`, `govulncheck`, a blocking gosec scan, a Trivy scan, the integration-tagged suite against MySQL + Redis service containers, three 30-second fuzz smokes, and coverage floors (73% `internal/services`, 91% `internal/jwt`). Note: `go test -race` requires cgo and cannot run on Windows hosts without a C compiler — race coverage comes from CI.

---

## Configuration reference

Everything is read from environment variables (`.env` supported). See `.env.example` for the full, up-to-date list. Key groups:

| Group | Variables | Notes |
|---|---|---|
| Server | `SERVER_PORT`, `GIN_MODE`, `TRUSTED_PROXIES`, `PPROF_ADDR`, `HSTS_SECONDS` | `TRUSTED_PROXIES` is a comma-separated CIDR list; empty = trust no one. `PPROF_ADDR` starts an internal-only pprof listener |
| Database | `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`, `DB_MAX_IDLE_CONNS`, `DB_MAX_OPEN_CONNS`, `DB_TLS`, `MIGRATE_AUTO` | `DB_TLS` appends `&tls=...` to the DSN; `MIGRATE_AUTO` is the dev-only AutoMigrate escape hatch |
| JWT | `JWT_SECRET` (required, no default), `JWT_SECRET_PREVIOUS`, `JWT_ISSUER`, `ACCESS_TOKEN_TTL`, `REFRESH_TOKEN_TTL`, `RESET_TOKEN_TTL`, `EMAIL_VERIFY_TOKEN_TTL`, `MFA_PENDING_TOKEN_TTL`, `SUDO_TOKEN_TTL` | `JWT_SECRET_PREVIOUS` enables zero-downtime rotation |
| Keys & secrets | `RECOVERY_CODE_KEY` (**required in release mode**), `KEY_PROVIDER` (`env`\|`file`), `KEY_DIR` | AES-256 key sealing recovery codes and TOTP secrets |
| Account security | `MAX_LOGIN_ATTEMPTS`, `LOGIN_LOCKOUT_DURATION`, `MAX_LOCKOUT_MULTIPLIER`, `REQUIRE_EMAIL_VERIFIED` | `MAX_LOCKOUT_MULTIPLIER` scales lockout duration for repeat offenders |
| MFA / TOTP | `TOTP_MAX_ATTEMPTS`, `TOTP_ATTEMPT_WINDOW`, `TOTP_MAX_CONCURRENT`, `RECOVERY_CODE_COUNT`, `RECOVERY_CODE_BYTES` | Brute-force lockout + concurrency gate on CPU-bound verification |
| Rate limiting | `RATE_LIMIT_RPS`, `RATE_LIMIT_BURST`, `LOGIN_PER_ACCOUNT_MAX`, `LOGIN_WINDOW`, `REGISTER_PER_IP_MAX`, `REGISTER_WINDOW`, `VERIFY_RESEND_PER_EMAIL_MAX`, `VERIFY_RESEND_PER_IP_MAX`, `VERIFY_RESEND_GLOBAL_MAX`, `LOGIN_CAPTCHA_AFTER_FAILS` | Resend limits are shared when `REDIS_URL` is configured |
| Email | `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM` | Empty `SMTP_HOST` -> console notifier (no live tokens in release mode) |
| CAPTCHA | `CAPTCHA_PROVIDER` (`turnstile` \| empty), `CAPTCHA_SECRET`, `CAPTCHA_SITE_KEY` | Off unless a provider + secret are set |
| Shared store | `REDIS_URL` | Empty -> in-memory store (single instance only) |
| Audit | `AUDIT_BUFFER_SIZE`, `AUDIT_FLUSH_BATCH`, `AUDIT_RETENTION_DAYS` | Release mode warns when `AUDIT_RETENTION_DAYS` is unset — see the PII/retention policy below |
| Hardening | `MAX_REQUEST_BODY_BYTES`, `MAX_PASSWORD_LENGTH`, `RATE_LIMITER_ENTRY_TTL` | |

### JWT secret rotation procedure

1. Set `JWT_SECRET` to the NEW value and `JWT_SECRET_PREVIOUS` to the old one; restart. Tokens signed by the previous secret keep verifying (via `kid`), new tokens are signed with the new key.
2. Leave the previous secret in place for at least the access-token + reset-token TTLs (until every legacy token has expired).
3. Remove `JWT_SECRET_PREVIOUS` and restart. No sessions are invalidated at any step.

---

## API reference

The contract of record is **`docs/openapi.yaml`** (OpenAPI 3.0) — every public endpoint, envelope, and schema; CI fails on drift between it and the router (`internal/apidrift`). The Bruno collection stays the executable companion. Summary:

Base path: `/api/v1/auth`. MFA endpoints are nested under `/api/v1/auth/mfa`.

### Core auth

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/register` | – | Create an account |
| POST | `/login` | – | Authenticate, receive access + refresh token (or `mfaRequired` + `mfaToken`) |
| POST | `/refresh-token` | – | Rotate refresh token, issue a new pair |
| POST | `/forgot-password` | – | Request a password reset (same response whether or not the email exists) |
| POST | `/reset-password` | – | Set a new password using a reset token |
| POST | `/verify-email` | – | Confirm email ownership using a verification token |
| POST | `/resend-verification` | – | Request a fresh verification link without account enumeration |
| POST | `/logout` | Yes | Revoke one refresh token |
| POST | `/logout-all` | Yes | Revoke every refresh token for the current user |
| POST | `/change-password` | Yes | Change password (revokes all sessions afterward) |
| POST | `/set-password` | Yes | Establish a first password for Google-OAuth-only accounts (409 if a password already exists) |
| GET | `/me` | Yes | Current user's profile |
| GET | `/google/login`, `/google/callback` | – | Google OAuth sign-in (registered only when configured) |

### Sessions

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/sessions` | Yes | List active devices (IP, device, location, last active) |
| DELETE | `/sessions/{id}` | Yes | Revoke one session (IDOR-protected) |

### MFA (TOTP)

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/mfa/login-verify` | mfa_pending token | Complete a login pending TOTP |
| POST | `/mfa/totp/enable` | Yes | Begin enrollment (secret + provisioning URI) |
| POST | `/mfa/totp/verify` | Yes | Activate TOTP; recovery codes shown once |
| POST | `/mfa/totp/validate` | Yes | Re-validate a current code on an active session |
| POST | `/mfa/totp/recovery-codes` | Yes | Re-view codes (requires current TOTP); mints sudo token |
| POST | `/mfa/totp/recovery-codes/regenerate` | X-Sudo-Token | Regenerate codes |

### Operational

| Method | Endpoint | Description |
|---|---|---|
| GET | `/healthz` | Liveness — process is running |
| GET | `/readyz` | Readiness — also checks DB connectivity |
| GET | `/metrics` | Prometheus scrape — **must stay internal** (see below) |

### Response envelope

Every response, success or error, has the same shape:

```json
{
  "code": 200,
  "message": "login successful",
  "data": { }
}
```

---

## Design notes

A few decisions worth knowing if you're extending this:

- **Password reset / email verification use JWTs with a `type` claim** (`reset`, `verify-email`) rather than a separate token table — reuses the existing JWT infrastructure and gets expiry for free. Single-use is enforced separately via the JWT ID, tracked in `store.Store` with a durable DB backstop.
- **Passwords are capped at bcrypt's 72-byte limit.** This prevents bcrypt truncation from treating two distinct long passwords as the same credential.
- **`locked_until` is a nullable timestamp**, distinct from `is_active` — a boolean can't express a *temporary* lock, only a permanent enable/disable state.
- **Refresh tokens are hashed with SHA-256**, not bcrypt — they're already high-entropy random values, so bcrypt's deliberately slow KDF isn't needed (unlike user-chosen passwords, which are lower-entropy and benefit from that slowness). The same logic applies to recovery codes; both consumption paths are compare-and-set so parallel double-use is impossible.
- **The `store.Store` interface is the seam for horizontal scaling.** Nothing above it knows whether counters live in a Go map or Redis — swapping is a config change (`REDIS_URL`), not a code change. Failure semantics are deliberate: counters fail open, single-use guards fail closed.
- **TOTP shared secrets are sealed at rest with AES-256-GCM** (`totp_devices.secret_encrypted`). Rows written before this column existed keep their plaintext `secret` and keep validating (lazy migration on read); the next enrollment or sudo-gated rotation re-writes them sealed and blanks the plaintext column. Rotating `RECOVERY_CODE_KEY` (or the dev derivation from `JWT_SECRET`) orphans existing sealed secrets — affected users must re-enroll TOTP, exactly like recovery codes.
- **Data layer (D1/D2).** All hot-path queries are index-served — verified by EXPLAIN assertions that run against real MySQL in CI and fail on a full-scan plan. The rotation repository stays on GORM: the measured ~14 ms/rotation is dominated by three network round-trips, not ORM overhead (a raw-SQL rewrite was rejected with this evidence).

## Operational notes

- **`GET /metrics` (Prometheus) is unauthenticated by design** so scrapers need no credentials. It exposes process/Go runtime metrics plus `finnapigo_store_errors_total`, `finnapigo_audit_entries_dropped_total`, `finnapigo_rate_limited_requests_total`, and `finnapigo_audit_buffer_depth`. **Never expose it publicly** — bind the server to an internal interface or restrict it at the load balancer; the payload reveals internals useful to an attacker.
- **Schema migrations (R1).** Schema changes ship as golang-migrate SQL files under `migrations/` and are applied as a DEPLOY STEP: `go run ./cmd/migrate up` (also `down N`, `force V`, `version`). The up/down/re-up cycle is proven continuously by the CI integration job against a real MySQL service container.
- **Log redaction guarantee (G2).** The default logger is wrapped in a redacting handler: attributes keyed like `password`, `token`, `code`, `secret`, `recovery_code`, `authorization`, cookies, and their case variants are replaced with `[REDACTED]` before output, at any nesting depth. Metrics never carry user-identifying labels.
- **Audit & PII retention policy (G1).** `audit_logs` rows contain PII (email addresses, client IPs, usernames). Release mode without `AUDIT_RETENTION_DAYS` emits a boot warning (a deliberate warning, not a failure — retention is a governance choice; some deployments must keep evidence long). Set `AUDIT_RETENTION_DAYS` (e.g. `90`) to have the cleanup job batch-delete older rows every 15 minutes. Pick a posture deliberately — "keep evidence long" or "minimize PII" — and document it internally. The future durable audit queue is designed (not implemented) in `docs/audit-durable-queue-design.md`.
- **`PPROF_ADDR`** (optional) starts a `net/http/pprof` listener on a separate internal port (e.g. `localhost:6060`). Empty (default) = disabled. Never expose this port publicly.

## Known limitations / roadmap

The enterprise-readiness reconciliation (`docs/enterprise-review-reconciliation.md`) tracks these open items:

- `/metrics` still rides the public listener; binding it (and pprof) behind a dedicated internal listener with optional bearer auth is planned (`METRICS_ADDR`).
- Background cleanup jobs run on every replica; leader election via the shared store (or an explicit `RUN_JOBS` flag) is planned.
- Distributed tracing (OpenTelemetry) and trace-ID log correlation are not wired yet.
- A KMS seam (`crypto.KeyProvider`, `KEY_PROVIDER=env|file`) is designed but not implemented; keys live in env config today.
- Passkeys / WebAuthn is designed (catalog W1–W8) but not implemented.
- `go test -race` requires cgo — CI runs it on Linux; Windows hosts without a C compiler cannot.

---

## Testing with Bruno / Postman

Import the Bruno collection (`Bruno/`) or any REST client and point it at `http://localhost:8080` (use `{{baseUrl}}` in the collection). A typical flow:

1. `POST /register`
2. `POST /login` → save `accessToken` and `refreshToken` from the response
3. `GET /me` with `Authorization: Bearer <accessToken>`
4. `POST /refresh-token` with the saved `refreshToken` → confirms rotation (the old token stops working)

Verification and password-reset tokens are logged to the server console (or emailed, if SMTP is configured) rather than returned in the API response — check the terminal running `go run ./cmd/server`. In release mode live tokens are never logged; the console notifier emits a redacted notice instead.
