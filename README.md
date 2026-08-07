# FinnApiGo

Authentication & MFA backend written in **Go**, built as a reusable module (`handler → service → repository`) meant to plug into larger applications. Implements core auth (register, login, refresh-token rotation, password reset, email verification) plus OTP-based two-factor verification, with the security hardening a production system needs: rate limiting, lockout, single-use tokens, audit logging, and an optional Redis backend for multi-instance deployments.

> **Naming note:** "MFA" here means OTP-based two-step verification. It is unrelated to OAuth 2.0 — nothing in this codebase is an OAuth/third-party login flow.

---

## Features

- **Core auth** — register, login, logout, logout-all, refresh-token (with rotation + reuse detection), forgot/reset password, change password, email verification, profile (`/me`)
- **MFA** — 6-digit OTP send/verify, single-use, capped verification attempts
- **Security hardening**
  - Passwords hashed with bcrypt, never stored or logged in plaintext
  - Access tokens are short-lived JWTs; refresh tokens are opaque, stored as SHA-256 hashes, and **rotated** on every use — presenting an already-used refresh token revokes every session for that user (theft response)
  - Reset/verify-email tokens are single-use (tracked by JWT ID)
  - Timing-safe comparisons for OTP verification; login response time is equalized for unknown vs. wrong-password accounts to resist enumeration
  - Account lockout after repeated failed logins, with optional exponential backoff for repeat offenders
  - Per-IP **and** per-account rate limiting on login; per-IP registration velocity limiting; per-user OTP send limiting
  - Verification-email resend protection with per-email, shared per-IP, and shared global circuit-breaker limits; blocked abuse is audited
  - Optional CAPTCHA (Cloudflare Turnstile) on registration and adaptively after repeated login failures
  - Disposable-email domain blocking and a honeypot field on registration
  - Global request body-size cap
  - Structured audit log (login, failed login, logout, password change/reset, token reuse) with IP + request-ID correlation
- **Pluggable storage backend** — in-memory by default (single instance); set `REDIS_URL` to share rate-limit counters and single-use-token state across multiple instances, no code changes required
- **Pluggable email delivery** — logs to console by default; set `SMTP_*` to send real email
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
| Rate limiting | `golang.org/x/time/rate` (per-instance) + a `store.Store` abstraction for shared counters |
| Optional shared store | Redis via `github.com/redis/go-redis/v9` |
| Config | Environment variables / `.env` via `godotenv` |

---

## Architecture

```
Handler  ->  Service  ->  Repository  ->  DB
 (HTTP)      (logic)      (queries)
```

- **Handlers** (`internal/handlers`) parse the request and format the response. They never touch GORM directly.
- **Services** (`internal/services`) hold all business logic. They never import Gin, so every rule (lockout, rotation, single-use tokens, rate windows) is unit-tested with in-memory fakes — no database or HTTP server needed.
- **Repositories** (`internal/repositories`) are thin, context-aware GORM wrappers with no business logic.
- **`store.Store`** is a small key-value interface (`Get`/`Set`/`SetNX`/`IncrBy`/`Delete`, all TTL-aware) used for rate-limit counters and single-use-token tracking. `InMemoryStore` is the default; `RedisStore` implements the same interface for multi-instance deployments — nothing above this layer knows or cares which one is active.

### Project structure

```
FinnApiGo/
├── cmd/server/main.go          # config -> DB -> migrate -> wire dependencies -> serve
├── internal/
│   ├── config/                 # env loading, typed config structs
│   ├── database/               # GORM/MySQL connection
│   ├── models/                 # User, RefreshToken, OtpCode, AuditLog, UsedToken
│   ├── repositories/           # GORM-backed repos (context-aware queries only)
│   ├── services/               # business logic - auth, MFA, notifier, CAPTCHA, async audit
│   ├── handlers/               # HTTP layer: parse -> call service -> respond
│   ├── middleware/             # AuthMiddleware, rate limiter
│   ├── routes/                 # route registration + request logging
│   ├── store/                  # Store interface, in-memory + Redis implementations
│   ├── hash/                   # bcrypt password and SHA-256 token primitives
│   ├── jwt/                    # JWT issuance and verification
│   └── response/               # HTTP response envelope
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

The schema (`users`, `refresh_tokens`, `otp_codes`, `audit_logs`, `used_tokens`) is created automatically on boot. The server listens on `:8080` by default (`SERVER_PORT`).

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
| Server | `SERVER_PORT`, `GIN_MODE` | |
| Database | `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`, `DB_MAX_IDLE_CONNS`, `DB_MAX_OPEN_CONNS` | |
| JWT | `JWT_SECRET` (required, no default), `JWT_ISSUER`, `ACCESS_TOKEN_TTL`, `REFRESH_TOKEN_TTL`, `RESET_TOKEN_TTL`, `EMAIL_VERIFY_TOKEN_TTL` | |
| Account security | `MAX_LOGIN_ATTEMPTS`, `LOGIN_LOCKOUT_DURATION`, `MAX_LOCKOUT_MULTIPLIER`, `REQUIRE_EMAIL_VERIFIED` | `MAX_LOCKOUT_MULTIPLIER` scales lockout duration for repeat offenders |
| MFA / OTP | `OTP_TTL`, `OTP_LENGTH`, `OTP_MAX_ATTEMPTS`, `OTP_SEND_PER_USER_MAX`, `OTP_SEND_WINDOW` | |
| Rate limiting | `RATE_LIMIT_RPS`, `RATE_LIMIT_BURST`, `LOGIN_PER_ACCOUNT_MAX`, `LOGIN_WINDOW`, `REGISTER_PER_IP_MAX`, `REGISTER_WINDOW`, `VERIFY_RESEND_PER_EMAIL_MAX`, `VERIFY_RESEND_PER_IP_MAX`, `VERIFY_RESEND_GLOBAL_MAX`, `LOGIN_CAPTCHA_AFTER_FAILS` | Resend limits are shared when `REDIS_URL` is configured. |
| Email | `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM` | Empty `SMTP_HOST` -> tokens/OTPs are logged to console instead of emailed |
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
| GET | `/me` | Yes | Current user's profile |

### MFA

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/mfa/send-otp` | Yes | Generate and deliver a 6-digit OTP |
| POST | `/mfa/verify-otp` | Yes | Verify the submitted OTP |

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
- **OTPs and refresh tokens are hashed with SHA-256**, not bcrypt — they're already high-entropy random values, so bcrypt's deliberately slow KDF isn't needed (unlike user-chosen passwords, which are lower-entropy and benefit from that slowness).
- **The `store.Store` interface is the seam for horizontal scaling.** Nothing above it knows whether counters live in a Go map or Redis — swapping is a config change (`REDIS_URL`), not a code change.

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
