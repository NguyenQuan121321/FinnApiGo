# FinnApiGo

Enterprise-grade Authentication, MFA, and Multi-Tenant Identity engine written in **Go 1.26**, built with strict architectural boundaries (`handler → service → repository → database`). 

Designed for high-throughput, mission-critical systems, FinnApiGo delivers complete credential lifecycle management, TOTP and Passkey (WebAuthn) multi-factor authentication, multi-tenant organization isolation, dynamic RBAC permission gating, trusted device remember-me bypass, outbound signed webhooks with SSRF protection, personal and tenant audit logging, and single-use cryptographic token rotation.

---

## Key Features

- **Core Authentication & Identity Lifecycle**
  - Registration with honeypot field, disposable email domain blocking, and velocity rate limits.
  - Login with per-IP and per-account rate limits, account lockout with exponential backoff, and timing-safe enumeration resistance.
  - Opaque refresh tokens stored as SHA-256 hashes with **automatic rotation and theft reuse detection** (reusing a consumed token revokes all user sessions).
  - Password reset and email verification using single-use purpose-bound JWTs backed by a distributed replay guard.
  - Three-tier rate-limited email verification resending (per-email, per-IP, and global circuit-breakers).
  - Secure email change flow with two-step password confirmation and verification token validation.
  - Self-deactivation and GDPR Right to Erasure (`DELETE /api/v1/auth/me`).
  - Google OAuth 2.0 / OpenID Connect integration and identity provider unlinking.
  - Post-OAuth initial password establishment (`POST /api/v1/auth/set-password`) for passwordless-created accounts.

- **Multi-Factor Authentication (MFA)**
  - **TOTP (RFC 6238)**: Time-based one-time passwords, QR provisioning URI, AES-256-GCM sealed secrets at rest, single-use recovery codes, and CPU-bound concurrency semaphore protection.
  - **Passkeys (FIDO2 / WebAuthn)**: Platform and roaming authenticators, challenge-response attestation and assertion, monotonic sign-counter **clone detection** (cloned credentials are automatically revoked and audited), and sudo-gated credential removal.
  - **Aggregated MFA Methods Summary**: `GET /api/v1/auth/mfa/methods` provides clients with an unified status of enrolled factors.
  - **Isolated MFA Pending Gate**: `POST /api/v1/auth/mfa/login-verify` strictly accepts short-lived `mfa_pending` JWTs, preventing token escalation from fully authenticated sessions.

- **Enterprise Multi-Tenancy & RBAC**
  - Transparent tenant resolution via `X-Tenant-ID`, `X-Tenant-Slug`, or request subdomain.
  - Tenant context injection through `internal/tenant` into GORM persistence queries.
  - Role-Based Access Control (RBAC) with granular permissions (`users:read`, `users:write`, `sessions:read`, `audit:export`, `webhooks:write`).
  - Strict tenant boundary isolation preventing cross-tenant privilege escalation.

- **Session & Trusted Device Management**
  - Active session inventory reporting IP address, operating system / browser user-agent, geolocation estimate, and activity timestamps.
  - Individual session revocation and global logout (`/logout-all`) with password version (`pwd_version`) invalidation.
  - 30-day "Remember this device" trusted device registration allowing step-up MFA bypass for recognized hardware fingerprints.

- **GitHub-Style Sudo Mode Elevation**
  - Sensitive operations (viewing/regenerating recovery codes, revoking passkeys, deactivating accounts) require elevated authorization via `X-Sudo-Token`.
  - Sudo tokens are short-lived (configurable, default 5–15 minutes) and require primary factor or TOTP step-up verification to issue.

- **Governance, Admin & Webhook Engine**
  - Enterprise Admin APIs to search/paginate tenant users, lock accounts, unlock accounts, and immediately force-logout compromised users.
  - Real-time tenant-wide active session monitoring.
  - Paginated personal security audit log for end-users (`/me/audit-log`) and streaming export in CSV or NDJSON format for compliance auditors (`/admin/audit-log/export`).
  - Outbound Webhooks with HMAC-SHA256 signatures, event subscriptions, and strict SSRF loopback/private CIDR defense.

- **Security Hardening & Defense in Depth**
  - Passwords hashed with bcrypt (strict 72-byte cap enforced to eliminate bcrypt truncation vulnerabilities).
  - Zero-downtime JWT key rotation using `kid` headers and `JWT_SECRET_PREVIOUS`.
  - Release-mode safety: `GIN_MODE=release` refuses to boot without an explicit 256-bit `RECOVERY_CODE_KEY`.
  - Structural `slog` logging decorator with automatic secret redaction: passwords, tokens, recovery codes, and authorization headers never reach stdout or log sinks.
  - Optional HaveIBeenPwned k-anonymity breached password check on registration and password updates.
  - Optional Cloudflare Turnstile CAPTCHA verification on registration and adaptively upon repeated login failures.
  - Baseline security headers on all responses: `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, and HSTS.

- **High Performance & Test Execution Speed**
  - High-speed JSON serialization using `bytedance/sonic` with `sync.Pool` buffer recycling for zero-alloc request decoding on hot paths.
  - Configurable `BCRYPT_COST` parameterization allowing test suites across all 28 packages to execute in ~20 seconds without compromising production cryptographic difficulty.
  - Index-served queries verified with EXPLAIN assertions against real MySQL.
  - Pluggable `store.Store` abstraction: thread-safe in-memory store for single-node deployments or Redis for horizontally scaled clusters with split failure semantics (rate limits fail-open; single-use guards fail-closed).

---

## Tech Stack

| Layer | Technology | Details |
|---|---|---|
| **Language** | Go 1.26 | Pinned in `go.mod`; consistent across local dev, CI, and multi-stage Docker builds |
| **HTTP Framework** | [Gin](https://github.com/gin-gonic/gin) | High performance HTTP routing with custom middleware pipeline |
| **ORM / Storage** | [GORM](https://gorm.io) + MySQL 8 / SQLite | Context-aware queries, embedded `golang-migrate` SQL migrations |
| **Token System** | [golang-jwt/jwt](https://github.com/golang-jwt/jwt) v5 | HS256, purpose-bound claims, `kid`-keyed versioned keyset |
| **Password Hashing** | `golang.org/x/crypto/bcrypt` | Configurable cost (DefaultCost in prod, MinCost in testing) |
| **TOTP MFA** | RFC 6238 via `github.com/pquerna/otp` | Time-based one-time passwords with QR code generation |
| **Passkeys / WebAuthn** | [go-webauthn/webauthn](https://github.com/go-webauthn/webauthn) | W3C WebAuthn Level 3 FIDO2 authentication and clone detection |
| **JSON Engine** | [sonic](https://github.com/bytedance/sonic) | Zero-alloc AST parser with recycled buffer pools |
| **State & Rate Limiting** | In-Memory / Redis v9 | Token bucket and sliding window rate limits via `store.Store` |
| **Observability** | Prometheus client (`/metrics`) | Structured `slog` JSON logs with automated secret redaction |
| **API Contract** | OpenAPI 3.0 / Swagger UI | Contract of record at `docs/openapi.yaml`, interactive UI at `/swagger/index.html` |
| **Test Suites** | Go `testing` + Bruno | Exhaustive 49-endpoint audit (`all_49_endpoints_test.go`), E2E, and Bruno collections |

---

## Architecture

FinnApiGo strictly adheres to clean layered architecture principles:

```
HTTP Client / Reverse Proxy
         │
    [Middleware] (Tenant Resolution, CORS, Security Headers, Body Cap, Request Logging)
         │
    [Routes] (Rate Limiting, RBAC Permissions, Concurrency Limiter, Sudo Gate, Auth Guard)
         │
    [Handlers] (HTTP binding, validation, DTO transformation, response envelope)
         │
    [Services] (Business logic, password/token hashing, MFA verification, audit dispatch)
         │
    [Repositories] (GORM persistence, multi-tenant scoping, transactional updates)
         │
    [Databases & Caches] (MySQL 8 / SQLite, Redis / In-Memory Store)
```

### Complete Directory Structure

```
FinnApiGo/
├── .agent/                                # AI agent context, specifications, and execution tracking
│   ├── enterprise-auth-execution-prompt.md# Core enterprise auth prompt & architectural guidelines
│   ├── IMPLEMENTATION_PROGRESS.md         # Milestone and deliverable progress tracking
│   ├── prompt_cicd_hardening.md           # CI/CD pipeline and test hardening instructions
│   └── skill.md                           # AI assistant skill profile and capabilities
├── .github/                               # GitHub Actions CI/CD and dependency automation
│   ├── workflows/
│   │   ├── ci.yml                         # Automated lint, vet, test, integration (MySQL+Redis), fuzz, scans
│   │   ├── release.yml                    # Automated Goreleaser build and container image publishing
│   │   └── security.yml                   # CodeQL, Trivy vulnerability, and Govulncheck security scanning
│   └── dependabot.yml                     # Automated Go module dependency maintenance
├── Bruno/                                 # Complete Bruno API collection for manual testing (GUI)
│   ├── Admin/                             # Tenant user management, lockout, force-logout, audit export
│   │   ├── audit-export.yml
│   │   ├── force-logout.yml
│   │   ├── list-users.yml
│   │   ├── lock-user.yml
│   │   ├── tenant-sessions.yml
│   │   └── unlock-user.yml
│   ├── Auth/                              # Core authentication, profile, credentials, sessions, OAuth
│   │   ├── audit-log.yml
│   │   ├── change-email-confirm.yml
│   │   ├── change-email-request.yml
│   │   ├── change-password.yml
│   │   ├── deactivate.yml
│   │   ├── forgot-password.yml
│   │   ├── google-callback.yml
│   │   ├── google-login.yml
│   │   ├── login.yml
│   │   ├── logout-all.yml
│   │   ├── logout.yml
│   │   ├── me-erase.yml
│   │   ├── me.yml
│   │   ├── oauth-unlink.yml
│   │   ├── refresh-token.yml
│   │   ├── register.yml
│   │   ├── resend-verification.yml
│   │   ├── reset-password.yml
│   │   ├── session-revoke.yml
│   │   ├── sessions.yml
│   │   ├── set-password.yml
│   │   └── verify-email.yml
│   ├── environments/                      # Environment definitions
│   │   ├── Local.yml                      # Local environment (http://localhost:8080)
│   │   ├── Production.yml                 # Production deployment environment
│   │   └── bruno-collection-environments.json
│   ├── MFA/                               # TOTP enrollment, validation, sudo codes, disable
│   │   ├── login-verify.yml
│   │   ├── methods.yml
│   │   ├── recovery-codes-regenerate.yml
│   │   ├── recovery-codes-view.yml
│   │   ├── totp-disable.yml
│   │   ├── totp-enable.yml
│   │   ├── totp-validate.yml
│   │   └── totp-verify.yml
│   ├── Passkey/                           # FIDO2 / WebAuthn registration & step-up authentication
│   │   ├── passkey-auth-challenge.yml
│   │   ├── passkey-auth-verify.yml
│   │   ├── passkey-list.yml
│   │   ├── passkey-register-challenge.yml
│   │   ├── passkey-register-verify.yml
│   │   └── passkey-revoke.yml
│   ├── system/                            # Operational health & metrics probes
│   │   ├── healthz.yml
│   │   ├── metrics.yml
│   │   └── readyz.yml
│   ├── test/                              # Negative test cases, rate limit abuse, and security probes
│   │   ├── login-wrongpass-repeat.yml
│   │   ├── register-bigbody.yml
│   │   ├── register-disposable-email.yml
│   │   ├── register-duplicate.yml
│   │   ├── register-honeypot.yml
│   │   └── register-velocity-repeat.yml
│   ├── TrustedDevices/                    # Remember-me MFA bypass device management
│   │   ├── list-devices.yml
│   │   └── revoke-device.yml
│   └── Webhooks/                          # Outbound signed webhook subscription management
│       └── create-webhook.yml
├── cmd/                                   # Application entry points
│   ├── migrate/main.go                    # Database migration CLI runner (up, down, force, version)
│   └── server/main.go                     # Composition root, dependency injection, HTTP daemon, graceful shutdown
├── docs/                                  # API contracts, architectural designs, and operational runbooks
│   ├── audit-durable-queue-design.md      # Future durable audit queue design document
│   ├── deep-review-remediation-2026-08.md # Security audit and remediation record
│   ├── docs.go                            # Embedded Swagger 2.0 Go declarations
│   ├── enterprise-review-reconciliation.md# Enterprise hardening reconciliation matrix
│   ├── openapi.yaml                       # OpenAPI 3.0 contract of record (drift-verified in CI)
│   ├── OPERATIONS.md                      # Operational runbook, Bruno catalog, and testing procedures
│   ├── supply-chain-hardening-2026-08.md  # Supply chain & dependency security audit
│   ├── swagger-integration-handoff-2026-09.md # Swagger UI integration documentation
│   ├── swagger.json                       # Compiled Swagger 2.0 JSON specification
│   └── swagger.yaml                       # Compiled Swagger 2.0 YAML specification
├── internal/                              # Internal domain packages (private to FinnApiGo)
│   ├── apidrift/                          # Bidirectional Gin router vs docs/openapi.yaml contract drift check
│   ├── config/                            # Twelve-Factor environment variable parser with fail-fast validation
│   ├── crypto/                            # Reversible AES-256-GCM cipher for at-rest secrets (TOTP secrets, recovery codes)
│   ├── database/                          # GORM connection pool (MySQL/SQLite) and embedded golang-migrate runner
│   ├── device/                            # Zero-dependency User-Agent string parser for session metadata
│   ├── geo/                               # Pluggable IP-to-location resolver interface (NoOp default, GeoIP pluggable)
│   ├── handlers/                          # HTTP adapters (Sonic JSON parsing, DTO validation, envelope responses)
│   ├── hash/                              # Cost-parameterized bcrypt password hashing and SHA-256 token hashing
│   ├── jobs/                              # Distributed background jobs and leader election coordination
│   ├── jwt/                               # Keyset-aware JWT issuance & verification (kid stamping, secret rotation)
│   ├── logging/                           # Slog JSON handler decorator with automated secret/credential redaction
│   ├── metrics/                           # Prometheus metrics registry, counters, and internal-only bearer guard
│   ├── middleware/                        # Tenant, Auth, RBAC, Sudo, MFA Pending, Rate Limit, Semaphore, Security Headers
│   ├── models/                            # GORM database schemas & domain models (User, Tenant, Session, AuditLog, etc.)
│   ├── netutil/                           # IP resolution, trusted proxy validation, and anti-SSRF CIDR checking
│   ├── repositories/                      # Context-aware GORM persistence layer with tenant scoping and batch purge
│   ├── response/                          # Standardized JSON response envelope ({code, message, data})
│   ├── routes/                            # Route tree wiring, access logging, OpenTelemetry tracing, and Swagger mount
│   ├── services/                          # Pure business logic (Auth, TOTP, Passkey, Admin, TrustedDevice, Webhook, etc.)
│   ├── store/                             # Distributed state abstraction (InMemoryStore and RedisStore v9)
│   ├── swagger/                           # Documentation-only response envelope types for Swag annotations
│   ├── tenant/                            # Multi-tenancy context injection and extraction helpers
│   └── tracing/                           # OpenTelemetry tracer provider initialization and propagation
├── migrations/                            # Embedded SQL migration files (golang-migrate)
│   ├── 0001_init.up.sql / down.sql        # Core auth tables (users, refresh_tokens, used_tokens, totp_devices, etc.)
│   ├── 0002_passkey_credentials.up/down   # WebAuthn passkey credentials table
│   ├── 0003_sessions.up.sql / down.sql    # Active device sessions table
│   ├── 0004_enterprise.up.sql / down.sql  # Multi-tenant, RBAC, trusted devices, webhooks, and audit log tables
│   └── embed.go                           # Embeds SQL migrations into the Go binary
├── tests/                                 # Automated integration, load, and browser test suites
│   ├── integration/                       # High-level integration test suite
│   │   ├── all_49_endpoints_test.go       # Exhaustive audit of all 49 endpoints (<1s runtime on in-memory SQLite)
│   │   ├── live_api_demo_test.go          # Multi-tenant session and workflow integration test
│   │   ├── phase1_e2e_test.go             # Core auth, GDPR erasure, and MFA aggregation integration test
│   │   └── phase2_e2e_test.go             # Tenant isolation, RBAC, and trusted devices integration test
│   ├── load/                              # High-concurrency k6 load test scripts
│   │   ├── login_test.js                  # Login endpoint concurrency benchmark
│   │   ├── passkey_test.js                # Passkey assertion load test
│   │   ├── README.md                      # Load test execution guide
│   │   ├── refresh_test.js                # Refresh token rotation concurrency test
│   │   ├── register_test.js               # Registration throughput test
│   │   └── totp_load_test.js              # TOTP concurrency and semaphore saturation test
│   ├── passkey_test.html                  # Browser-based test interface for WebAuthn passkey ceremonies
│   └── README.md                          # Test suite overview and agent runner instructions
├── .env.example                           # Documented template of all configuration environment variables
├── .gitattributes                         # Git line-ending and binary file attributes
├── .gitignore                             # Files and directories ignored by Git
├── .golangci.yml                          # Linter rules (govet, staticcheck, errcheck, gosec, depguard, etc.)
├── .goreleaser.yml                        # GoReleaser configuration for automated binary release packaging
├── ARCHITECTURE.md                        # Architectural patterns, runtime flow, and package boundaries
├── CHANGELOG.md                           # Version history and security hardening log (Keep a Changelog format)
├── docker-compose.yml                     # Local development MySQL 8 and Redis v9 service containers
├── Dockerfile                             # Multi-stage container build running as non-root user
├── go.mod                                 # Go module definition and dependencies (pinned Go 1.26)
├── go.sum                                 # Checksums for Go module dependencies
├── README.md                              # Main project documentation and comprehensive API reference
└── SECURITY.md                            # Security vulnerability reporting policy
```

---

## Getting Started

### 1. Prerequisites

- **Go 1.26+**
- **Docker & Docker Compose** (for local MySQL and Redis)
- Git

### 2. Start MySQL and Redis

```bash
docker compose up -d db redis
```

### 3. Configure Environment

Copy the template file:

```bash
cp .env.example .env
```

At minimum, generate required 256-bit secrets:

```bash
# Generate 32-byte hex keys
openssl rand -hex 32   # Use for JWT_SECRET
openssl rand -hex 32   # Use for RECOVERY_CODE_KEY
```

Configure `.env`:

```env
SERVER_PORT=8080
GIN_MODE=debug
JWT_SECRET=your_generated_jwt_secret_hex_string_32_chars_min
RECOVERY_CODE_KEY=your_generated_recovery_code_key_hex_string
DB_HOST=127.0.0.1
DB_PORT=3306
DB_USER=finnapigo
DB_PASSWORD=secret
DB_NAME=finnapigo
REDIS_URL=redis://127.0.0.1:6379/0
SWAGGER_ENABLED=true
```

### 4. Apply Database Migrations and Run

```bash
go mod tidy

# Apply embedded SQL migrations (deploy step)
go run ./cmd/migrate up

# Start the server daemon
go run ./cmd/server
```

> **Note:** The server does not auto-migrate on boot in production. `MIGRATE_AUTO=true` is provided solely as a development convenience.

---

## Testing Guide

The test suite is structured for high verification depth and rapid execution:

### 1. Run the Complete 49-Endpoint Audit (< 1 second)

Exhaustively verifies every route registered in `internal/routes/routes.go` against an in-memory SQLite database, mock OAuth provider, and console notifier:

```bash
go test -v -count=1 ./tests/integration/ -run TestAll49Endpoints
```

### 2. Run All Unit & Integration Tests

Thanks to the `BCRYPT_COST` optimization, the entire codebase (28 packages) executes in **~20 seconds**:

```bash
# Run all unit tests across all packages
go test ./...

# Run without cache
go test -count=1 ./...

# Run integration tests against real MySQL & Redis services
TEST_MYSQL_DSN='test:testpw@tcp(127.0.0.1:3306)/finnapigo_test?multiStatements=true' \
TEST_REDIS_URL='redis://127.0.0.1:6379/0' \
go test -tags=integration ./...
```

### 3. Run OpenAPI Drift Verification

Ensures `docs/openapi.yaml` and Gin routes stay in 100% bidirectional sync:

```bash
go test -v ./internal/apidrift
```

---

## Complete API Reference (All 49 Endpoints)

The API is served under the `/api/v1` base path. Every response conforms to the standard envelope:

```json
{
  "code": 200,
  "message": "success",
  "data": {}
}
```

### Group A: Operational & System Probes (4 Endpoints)

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/healthz` | Public | Liveness probe; returns 200 OK while process is alive. |
| `GET` | `/readyz` | Public | Readiness probe; pings database connectivity (503 if unreachable). |
| `GET` | `/metrics` | Internal | Prometheus exposition scrape endpoint (counters, latency, store errors). |
| `GET` | `/swagger/*any` | Public | Interactive Swagger UI (mounted when `SWAGGER_ENABLED=true`). |

### Group B: Public Core Auth & Credential Lifecycle (8 Endpoints)

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/api/v1/auth/register` | Rate Limit | Create user account with honeypot & disposable domain checks. |
| `POST` | `/api/v1/auth/login` | Rate Limit | Authenticate with email/password; returns tokens or `mfaRequired`. |
| `POST` | `/api/v1/auth/refresh-token` | Rate Limit | Rotate refresh token; revokes prior token; detects token theft reuse. |
| `POST` | `/api/v1/auth/forgot-password` | Rate Limit | Request password reset email (timing-equalized to prevent enumeration). |
| `POST` | `/api/v1/auth/reset-password` | Rate Limit | Update password using single-use reset JWT. |
| `POST` | `/api/v1/auth/verify-email` | Rate Limit | Confirm email address ownership using single-use verification JWT. |
| `POST` | `/api/v1/auth/resend-verification` | Multi-Tier Limit | Request fresh verification link with per-email/IP/global velocity limits. |
| `POST` | `/api/v1/auth/change-email/confirm` | Rate Limit | Confirm new email address using single-use confirmation token. |

### Group C: Third-Party OAuth 2.0 / OpenID Connect (2 Endpoints)

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/api/v1/auth/google/login` | Rate Limit | Initiate Google OAuth 2.0 flow with store-backed PKCE state. |
| `GET` | `/api/v1/auth/google/callback` | Rate Limit | Process OAuth callback, exchange code, link or authenticate user. |

### Group D: Authenticated Profile & Credential Management (10 Endpoints)

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/api/v1/auth/logout` | Bearer JWT | Revoke caller's current refresh token. |
| `POST` | `/api/v1/auth/logout-all` | Bearer JWT | Revoke all active sessions and refresh tokens for user. |
| `POST` | `/api/v1/auth/change-password` | Bearer JWT | Change password with current password verification; revokes all sessions. |
| `POST` | `/api/v1/auth/set-password` | Bearer JWT | Establish initial password for OAuth accounts (409 if password exists). |
| `GET` | `/api/v1/auth/me` | Bearer JWT | Retrieve current user's profile information. |
| `DELETE` | `/api/v1/auth/me` | Bearer JWT | GDPR Right to Erasure; permanently delete account (password verified). |
| `GET` | `/api/v1/auth/me/audit-log` | Bearer JWT | Paginated personal security audit log history. |
| `POST` | `/api/v1/auth/change-email/request` | Bearer JWT | Request email address change (password verified; issues confirmation token). |
| `POST` | `/api/v1/auth/deactivate` | Bearer JWT | Self-deactivate account (password or sudo-gated; revokes all sessions). |
| `DELETE` | `/api/v1/auth/oauth/:provider` | Bearer JWT | Unlink third-party OAuth identity provider (e.g., `google`). |

### Group E: Session & Device Management (2 Endpoints)

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/api/v1/auth/sessions` | Bearer JWT | List caller's active device sessions (IP, User-Agent, Geo, Last Active). |
| `DELETE` | `/api/v1/auth/sessions/:id` | Bearer JWT | Revoke a specific active session (IDOR-protected). |

### Group F: Trusted Devices (Remember-Me) (2 Endpoints)

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/api/v1/auth/trusted-devices` | Bearer JWT | List recognized trusted devices eligible for 30-day MFA bypass. |
| `DELETE` | `/api/v1/auth/trusted-devices/:id` | Bearer JWT | Revoke trusted device status. |

### Group G: MFA Pending Isolation Gate (1 Endpoint)

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/api/v1/auth/mfa/login-verify` | `mfa_pending` JWT | Complete step-up login using TOTP code (rejects standard access tokens). |

### Group H: TOTP Multi-Factor Authentication (7 Endpoints)

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/api/v1/auth/mfa/totp/enable` | Bearer JWT | Initialize TOTP enrollment (returns sealed secret and QR otpauth URI). |
| `POST` | `/api/v1/auth/mfa/totp/verify` | Bearer JWT | Confirm initial 6-digit TOTP code and obtain recovery codes (shown once). |
| `POST` | `/api/v1/auth/mfa/totp/validate` | Bearer JWT | Re-validate TOTP code on an active session. |
| `POST` | `/api/v1/auth/mfa/totp/recovery-codes` | Bearer JWT | View unconsumed recovery codes (requires current TOTP; mints sudo token). |
| `POST` | `/api/v1/auth/mfa/totp/disable` | Bearer JWT | Disable TOTP authentication (requires current TOTP or password). |
| `GET` | `/api/v1/auth/mfa/methods` | Bearer JWT | Retrieve summary of configured authentication factors and recovery codes. |
| `POST` | `/api/v1/auth/mfa/totp/recovery-codes/regenerate` | `X-Sudo-Token` | Invalidate all existing recovery codes and mint fresh set. |

### Group I: Passkey / WebAuthn FIDO2 Ceremonies (6 Endpoints)

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/api/v1/auth/mfa/passkey/register/challenge` | Bearer JWT | Generate WebAuthn creation options challenge (60s TTL in store). |
| `POST` | `/api/v1/auth/mfa/passkey/register/verify` | Bearer JWT | Verify attestation response and persist credential public key. |
| `POST` | `/api/v1/auth/mfa/passkey/authenticate/challenge` | Bearer JWT | Generate WebAuthn assertion options challenge for step-up login. |
| `POST` | `/api/v1/auth/mfa/passkey/authenticate/verify` | Bearer JWT | Verify assertion signature; enforces monotonic sign-count clone detection. |
| `GET` | `/api/v1/auth/mfa/passkeys` | Bearer JWT | List user's registered passkey authenticators. |
| `DELETE` | `/api/v1/auth/mfa/passkeys/:id` | `X-Sudo-Token` | Revoke a registered passkey authenticator. |

### Group J: Enterprise Admin, Multi-Tenancy & Webhooks (7 Endpoints)

| Method | Endpoint | Auth / Permission | Description |
|---|---|---|---|
| `GET` | `/api/v1/admin/users` | `users:read` | Paginated search and listing of users within the caller's tenant. |
| `POST` | `/api/v1/admin/users/:id/lock` | `users:write` | Lock user account (temporary duration or indefinite; self-lockout prevented). |
| `POST` | `/api/v1/admin/users/:id/unlock` | `users:write` | Unlock user account and reset failed login counters. |
| `POST` | `/api/v1/admin/users/:id/force-logout` | `users:write` | Invalidate all sessions, refresh tokens, and increment password version. |
| `GET` | `/api/v1/admin/sessions` | `sessions:read` | Monitor all active user sessions across the tenant. |
| `GET` | `/api/v1/admin/audit-log/export` | `audit:export` | Stream tenant audit logs in CSV or NDJSON format. |
| `POST` | `/api/v1/admin/webhooks` | `webhooks:write` | Register outbound webhook endpoint with SSRF loopback block and HMAC signing. |

---

## Configuration Reference

Configuration is managed via environment variables (with `.env` file support):

| Variable | Type | Default | Description |
|---|---|---|---|
| `SERVER_PORT` | int | `8080` | Port for the primary HTTP service. |
| `GIN_MODE` | string | `debug` | Gin runtime mode (`debug`, `release`, `test`). |
| `TRUSTED_PROXIES` | string | `""` | Comma-separated CIDR list for reverse proxy IP extraction. Empty = trust no one. |
| `HSTS_SECONDS` | int | `0` | Strict-Transport-Security header duration on HTTPS. |
| `SWAGGER_ENABLED` | bool | `false` | Mounts Swagger UI at `/swagger/index.html`. |
| `BCRYPT_COST` | int | `0` | Bcrypt hashing cost (0 defaults to `bcrypt.DefaultCost` = 10; use 4 in tests). |
| `JWT_SECRET` | string | *Required* | 256-bit secret string used to sign and verify JWTs. |
| `JWT_SECRET_PREVIOUS`| string | `""` | Previous secret to enable zero-downtime key rotation. |
| `ACCESS_TOKEN_TTL` | duration | `15m` | Lifetime of access tokens. |
| `REFRESH_TOKEN_TTL` | duration | `168h` | Lifetime of refresh tokens (7 days). |
| `RESET_TOKEN_TTL` | duration | `15m` | Lifetime of password reset tokens. |
| `EMAIL_VERIFY_TOKEN_TTL` | duration | `24h` | Lifetime of email verification tokens. |
| `MFA_PENDING_TOKEN_TTL` | duration | `5m` | Lifetime of short-lived `mfa_pending` JWTs. |
| `SUDO_TOKEN_TTL` | duration | `15m` | Lifetime of elevated `X-Sudo-Token` JWTs. |
| `RECOVERY_CODE_KEY`| string | *Required in Release* | 64-character hex key (AES-256-GCM) sealing recovery codes and TOTP secrets. |
| `MAX_LOGIN_ATTEMPTS` | int | `5` | Failed attempts before account lockout. |
| `LOGIN_LOCKOUT_DURATION` | duration | `15m` | Lockout duration upon reaching attempt threshold. |
| `MAX_LOCKOUT_MULTIPLIER` | int | `4` | Maximum multiplier for repeated lockout offenders. |
| `TOTP_MAX_ATTEMPTS`| int | `5` | Failed TOTP attempts before temporary lockout. |
| `TOTP_MAX_CONCURRENT` | int | `50` | Maximum parallel CPU-bound TOTP verifications before 429 backoff. |
| `WEBAUTHN_RP_ID` | string | `""` | Relying Party ID for Passkeys (e.g., `localhost` or `example.com`). |
| `WEBAUTHN_RP_ORIGINS`| string | `""` | Comma-separated list of allowed HTTPS origins. |
| `WEBAUTHN_RP_DISPLAY_NAME` | string | `"FinnApiGo"`| Display name shown during passkey registration prompts. |
| `REDIS_URL` | string | `""` | Redis connection URL (`redis://host:6379/0`). Empty uses in-memory store. |
| `AUDIT_RETENTION_DAYS` | int | `0` | Automatic audit log purge retention period in days (0 disables purge). |
| `BREACHED_PASSWORD_CHECK`| bool | `false` | Screens passwords against Pwned Passwords API via k-anonymity. |
| `CORS_ALLOWED_ORIGINS` | string | `""` | Comma-separated allowlist of browser origins. |

---

## Security Policies & Operational Runbooks

### 1. Zero-Downtime JWT Key Rotation

1. Update config: set `JWT_SECRET` to the new secret and `JWT_SECRET_PREVIOUS` to the current secret.
2. Deploy/restart instances. New tokens will be signed with the new secret (stamped with a fresh `kid`), while active tokens signed with the previous secret continue to verify cleanly.
3. Wait for `ACCESS_TOKEN_TTL` and `REFRESH_TOKEN_TTL` to elapse.
4. Remove `JWT_SECRET_PREVIOUS` and restart instances.

### 2. Passkey Monotonic Counter Clone Detection

WebAuthn authenticators maintain an internal signature counter incremented on every assertion. Upon receiving an assertion, FinnApiGo compares the incoming counter against the stored counter:
- If `incoming_counter <= stored_counter` (and counter > 0), authenticator cloning is detected.
- FinnApiGo immediately revokes the credential, audits the event (`passkey.clone_detected`), and terminates the ceremony with 401 Unauthorized.

### 3. Outbound Webhook SSRF Loopback Defense

When registering webhook endpoints via `POST /api/v1/admin/webhooks`:
- Target URLs are parsed and resolved via DNS.
- If the resolved IP belongs to loopback (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`), or private RFC 1918 ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), the request is rejected with `400 Bad Request` to eliminate SSRF attacks.

### 4. Logging and Secret Redaction Guarantee

The application logger is wrapped in a redacting structural `slog.Handler`. Any attribute containing terms such as `password`, `token`, `secret`, `code`, `recovery_code`, `authorization`, or cookie values is replaced with `[REDACTED]` prior to emission, guaranteeing that secrets are never written to disk or centralized log collectors.

---

## Manual Testing with Bruno

The repository includes a ready-to-use Bruno API collection under `Bruno/`:

1. Open [Bruno](https://www.usebruno.com/).
2. Select **Open Collection** and browse to `e:/FinnApiGo/Bruno`.
3. Choose the `local` environment (`http://localhost:8080`).
4. Execute requests in the following sequence:
   - `Auth/register.yml` → `Auth/login.yml` (tokens are automatically saved).
   - `Auth/sessions.yml` → View active device session.
   - `MFA/totp-enable.yml` → `MFA/totp-verify.yml` → Complete TOTP enrollment.
   - `Admin/list-users.yml` → Manage tenant user accounts.

---

## License

Internal proprietary software. All rights reserved.
