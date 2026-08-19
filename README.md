# FinnApiGo

Authentication & MFA backend written in **Go**, built as a reusable module (`handler → service → repository`) meant to plug into larger applications. Implements core auth (register, login, refresh-token rotation, password reset, email verification) plus TOTP-based two-factor verification, with the security hardening a production system needs: rate limiting, lockout, single-use tokens, audit logging, session & device management, and an optional Redis backend for multi-instance deployments.

> **Naming note:** "MFA" here means TOTP-based two-step verification. It is unrelated to OAuth 2.0 — nothing in this codebase is an OAuth/third-party login flow.

---

## Features

- **Core auth** — register, login, logout, logout-all, refresh-token (with rotation + reuse detection), forgot/reset password, change password, email verification, resend verification, profile (`/me`)
- **MFA — TOTP** — RFC 6238 time-based one-time passwords with QR provisioning, single-use recovery codes, brute-force protection, and concurrency-gated CPU-bound verification
- **Session & device management** — list all active devices (IP, user-agent, device name, location estimate, last active), revoke individual sessions, IDOR-protected revocation, metadata populated on every login and refresh
- **Security hardening**
  - Passwords hashed with bcrypt, never stored or logged in plaintext
  - Access tokens are short-lived JWTs; refresh tokens are opaque, stored as SHA-256 hashes, and **rotated** on every use — presenting an already-used refresh token revokes every session for that user (theft response)
  - Reset/verify-email tokens are single-use (tracked by JWT ID)
  - Timing-safe comparisons for TOTP verification; login response time is equalized for unknown vs. wrong-password accounts to resist enumeration
  - Account lockout after repeated failed logins, with optional exponential backoff for repeat offenders
  - Per-IP **and** per-account rate limiting on login; per-IP registration velocity limiting
  - Verification-email resend protection with per-email, shared per-IP, and shared global circuit-breaker limits; blocked abuse is audited
  - Optional CAPTCHA (Cloudflare Turnstile) on registration and adaptively after repeated login failures
  - Disposable-email domain blocking and a honeypot field on registration
  - Global request body-size cap
  - Structured audit log (login, failed login, logout, password change/reset, token reuse, session revocation) with IP + request-ID correlation
  - Reverse-proxy-aware IP resolution via configurable trusted proxies (`TRUSTED_PROXIES`); defaults to trust-no-one
  - Concurrency limiter middleware (semaphore) caps parallel CPU-bound TOTP verifications to prevent resource exhaustion
- **Performance**
  - Sonic JSON parser (`bytedance/sonic`) with `sync.Pool` buffer recycling for zero-alloc request body parsing on hot paths
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
| HTTP framework | [Gin](https://github.com/gin-gonic/gin) v1.10.1 |
| ORM / DB | [GORM](https://gorm.io) + MySQL 8 |
| Auth tokens | [golang-jwt/jwt](https://github.com/golang-jwt/jwt) v5 |
| Password hashing | `golang.org/x/crypto/bcrypt` |
| TOTP | RFC 6238 via `github.com/pquerna/otp` |
| JSON parsing | [sonic](https://github.com/bytedance/sonic) (AST-based, `sync.Pool` recycled buffers) |
| Rate limiting | `golang.org/x/time/rate` (per-instance) + a `store.Store` abstraction for shared counters |
| Optional shared store | Redis via `github.com/redis/go-redis/v9` |
| Config | Environment variables / `.env` via `godotenv` |
| Load testing | [k6](https://k6.io) scripts in `tests/load/` |

---

## Architecture

```
Handler  ->  Service  ->  Repository  ->  DB
 (HTTP)      (logic)      (queries)
```

- **Handlers** (`internal/handlers`) parse the request and format the response. They never touch GORM directly.
- **Services** (`internal/services`) hold all business logic. They never import Gin, so every rule (lockout, rotation, single-use tokens, rate windows, TOTP) is unit-tested with in-memory fakes — no database or HTTP server needed.
- **Repositories** (`internal/repositories`) are thin, context-aware GORM wrappers with no business logic.
- **`store.Store`** is a small key-value interface (`Get`/`Set`/`SetNX`/`IncrBy`/`Delete`, all TTL-aware) used for rate-limit counters and single-use-token tracking. `InMemoryStore` is the default; `RedisStore` implements the same interface for multi-instance deployments — nothing above this layer knows or cares which one is active.
- **`device`** (`internal/device`) — zero-dependency User-Agent parser producing human-readable labels (e.g. "Chrome on Windows").
- **`geo`** (`internal/geo`) — mockable IP-to-location resolver interface; `NoOpResolver` returns `"Unknown"`, production can inject a GeoIP implementation.
- **`middleware.ConcurrencyLimiter`** (`internal/middleware/semaphore.go`) — semaphore-based middleware that caps concurrent requests through CPU-bound endpoints (TOTP verification).

### Project structure

```
FinnApiGo/
├── cmd/server/main.go          # config -> DB -> migrate -> wire dependencies -> serve
├── internal/
│   ├── config/                 # env loading, typed config structs
│   ├── database/               # GORM/MySQL connection
│   ├── models/                 # User, RefreshToken, OtpCode, TOTPDevice, RecoveryCode, AuditLog, UsedToken
│   ├── repositories/           # GORM-backed repos (context-aware queries only)
│   ├── services/               # business logic - auth, MFA (OTP+TOTP), notifier, CAPTCHA, async audit
│   ├── handlers/               # HTTP layer: parse -> call service -> respond (sonic JSON, sync.Pool)
│   ├── middleware/             # AuthMiddleware, rate limiter, concurrency limiter (semaphore)
│   ├── routes/                 # route registration + request logging + trusted proxies
│   ├── store/                  # Store interface, in-memory + Redis implementations
│   ├── hash/                   # bcrypt password and SHA-256 token primitives
│   ├── jwt/                    # JWT issuance and verification
│   ├── device/                 # User-Agent -> human-readable device label parser
│   ├── geo/                    # IP-to-location resolver interface (NoOp default)
│   └── response/               # HTTP response envelope
├── tests/load/                 # k6 load test scripts (registration, TOTP)
├── .github/workflows/ci.yml   # CI pipeline (vet, lint, test, build, govulncheck)
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

At minimum, set a real `JWT_SECRET` (the app refuses to start without one):

```bash
# any long random string, e.g.:
openssl rand -hex 32
```

### 3. Run

```bash
go mod tidy
go run ./cmd/server
```

The schema (`users`, `refresh_tokens`, `otp_codes`, `totp_devices`, `recovery_codes`, `audit_logs`, `used_tokens`) is created automatically on boot. The server listens on `:8080` by default (`SERVER_PORT`).

### 4. Run the tests

```bash
go test ./...
```

Unit tests cover hashing, configuration, HTTP response envelopes, handlers, routes, service rules, store behavior, and GORM repositories. Repository tests use isolated in-memory SQLite databases; MySQL duplicate-key mapping remains covered at the service boundary with fakes. The CI pipeline runs `go test -race -cover`, `go vet`, `golangci-lint`, and `govulncheck` on push and PR.

---

## Configuration reference

Everything is read from environment variables (`.env` supported). See `.env.example` for the full, up-to-date list. Key groups:

| Group | Variables | Notes |
|---|---|---|
| Server | `SERVER_PORT`, `GIN_MODE`, `TRUSTED_PROXIES` | `TRUSTED_PROXIES` is a comma-separated CIDR list; empty = trust no one |
| Database | `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`, `DB_MAX_IDLE_CONNS`, `DB_MAX_OPEN_CONNS`, `DB_TLS` | `DB_TLS` appends `&tls=...` to the DSN (`true`/`skip-verify`/`preferred`); empty = plaintext (local dev) |
| JWT | `JWT_SECRET` (required, no default), `JWT_ISSUER`, `ACCESS_TOKEN_TTL`, `REFRESH_TOKEN_TTL`, `RESET_TOKEN_TTL`, `EMAIL_VERIFY_TOKEN_TTL` | |
| Account security | `MAX_LOGIN_ATTEMPTS`, `LOGIN_LOCKOUT_DURATION`, `MAX_LOCKOUT_MULTIPLIER`, `REQUIRE_EMAIL_VERIFIED` | `MAX_LOCKOUT_MULTIPLIER` scales lockout duration for repeat offenders |
| MFA / TOTP | `TOTP_MAX_ATTEMPTS`, `TOTP_ATTEMPT_WINDOW`, `TOTP_MAX_CONCURRENT` | Brute-force lockout + concurrency gate on CPU-bound verification |
| Rate limiting | `RATE_LIMIT_RPS`, `RATE_LIMIT_BURST`, `LOGIN_PER_ACCOUNT_MAX`, `LOGIN_WINDOW`, `REGISTER_PER_IP_MAX`, `REGISTER_WINDOW`, `VERIFY_RESEND_PER_EMAIL_MAX`, `VERIFY_RESEND_PER_IP_MAX`, `VERIFY_RESEND_GLOBAL_MAX`, `LOGIN_CAPTCHA_AFTER_FAILS` | Resend limits are shared when `REDIS_URL` is configured. |
| Email | `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM` | Empty `SMTP_HOST` -> tokens are logged to console instead of emailed |
| CAPTCHA | `CAPTCHA_PROVIDER` (`turnstile` \| empty), `CAPTCHA_SECRET`, `CAPTCHA_SITE_KEY` | Off unless a provider + secret are set |
| Shared store | `REDIS_URL` | Empty -> in-memory store (single instance only) |
| Hardening | `MAX_REQUEST_BODY_BYTES`, `MAX_PASSWORD_LENGTH`, `RATE_LIMITER_ENTRY_TTL` | |

---

## API reference

Base path: `/api/v1/auth`. MFA endpoints are nested under `/api/v1/auth/mfa`.

### Core auth

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/register` | – | Create an account |
| POST | `/login` | – | Authenticate, receive access + refresh token |
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

### Operational

| Method | Endpoint | Description |
|---|---|---|
| GET | `/healthz` | Liveness — process is running |
| GET | `/readyz` | Readiness — also checks DB connectivity |

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

- **Password reset / email verification use JWTs with a `type` claim** (`reset`, `verify-email`) rather than a separate token table — reuses the existing JWT infrastructure and gets expiry for free. Single-use is enforced separately via the JWT ID, tracked in `store.Store`.
- **Passwords are capped at bcrypt's 72-byte limit.** This prevents bcrypt truncation from treating two distinct long passwords as the same credential.
- **`locked_until` is a nullable timestamp**, distinct from `is_active` — a boolean can't express a *temporary* lock, only a permanent enable/disable state.
- **Refresh tokens are hashed with SHA-256**, not bcrypt — they're already high-entropy random values, so bcrypt's deliberately slow KDF isn't needed (unlike user-chosen passwords, which are lower-entropy and benefit from that slowness).
- **The `store.Store` interface is the seam for horizontal scaling.** Nothing above it knows whether counters live in a Go map or Redis — swapping is a config change (`REDIS_URL`), not a code change.
- **TOTP shared secrets are sealed at rest with AES-256-GCM** (`totp_devices.secret_encrypted`, keyed by the same `RECOVERY_CODE_KEY`/JWT-secret derivation as recovery codes). Rows written before this column existed keep their plaintext `secret` and keep validating (lazy migration on read); the next enrollment or sudo-gated rotation re-writes them sealed and blanks the plaintext column. Rotating the encryption key (or `JWT_SECRET`) orphans existing sealed secrets — affected users must re-enroll TOTP, exactly like recovery codes.

## Operational notes

- **`GET /metrics` (Prometheus) is unauthenticated by design** so scrapers need no credentials. It exposes process/Go runtime metrics plus `finnapigo_store_errors_total`, `finnapigo_audit_entries_dropped_total`, `finnapigo_rate_limited_requests_total`, and `finnapigo_audit_buffer_depth`. **Never expose it publicly** — bind the server to an internal interface or restrict it at the load balancer; the payload reveals internals useful to an attacker.
- **Audit retention (R4).** `audit_logs` rows contain PII (email addresses, client IPs, usernames) and are kept **forever by default**. Set `AUDIT_RETENTION_DAYS` (e.g. `90`) to have the cleanup job batch-delete older rows every 15 minutes. Consider your jurisdiction's requirements before enabling: retention supports both "keep evidence long" and "minimize PII" postures — pick one deliberately.
- **`PPROF_ADDR`** (optional) starts a `net/http/pprof` listener on a separate internal port (e.g. `localhost:6060`). Empty (default) = disabled. Never expose this port publicly.

## Known limitations

- The per-IP token-bucket limiter (`internal/middleware/rate_limit.go`) stays in-memory even when Redis is configured — only the store-backed velocity/lockout counters are shared across instances today
- `-race` requires `CGO_ENABLED=1` on Windows (CI runs it on Linux where cgo is available by default)

---

## Testing with Bruno / Postman

Import any REST client and point it at `http://localhost:8081`. A typical flow:

1. `POST /register`
2. `POST /login` → save `accessToken` and `refreshToken` from the response
3. `GET /me` with `Authorization: Bearer <accessToken>`
4. `POST /refresh-token` with the saved `refreshToken` → confirms rotation (the old token stops working)

Verification and password-reset tokens are logged to the server console (or emailed, if SMTP is configured) rather than returned in the API response — check the terminal running `go run ./cmd/server`.
