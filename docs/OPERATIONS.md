# Enterprise Operations and Testing Runbook

This document details the architectural separation between operational application code and testing infrastructure, manual verification using the Bruno API collections, automated test execution, and deployment health verification for the **FinnApiGo** Enterprise Authentication service.

---

## 1. Enterprise Separation of Concerns

FinnApiGo enforces strict boundaries between operational domain logic, infrastructure persistence, and test suites:

```
FinnApiGo/
├── cmd/                               # Production entry points
│   ├── migrate/main.go                # Database migration CLI runner (up, down, force, version)
│   └── server/main.go                 # HTTP daemon composition root, dependency wiring, graceful shutdown
│
├── internal/                          # Core domain business logic (private, encapsulated)
│   ├── apidrift/                      # Route-to-OpenAPI bidirectional contract drift check
│   ├── config/                        # Twelve-Factor typed configuration & fail-fast validation
│   ├── crypto/                        # Reversible AES-256-GCM authenticated cipher
│   ├── database/                      # GORM connection pool (MySQL/SQLite) and embedded migrator
│   ├── device/                        # Zero-dependency User-Agent string parser
│   ├── geo/                           # Pluggable IP-to-location resolver interface
│   ├── handlers/                      # HTTP request decoding, DTO validation, and response envelopes
│   ├── hash/                          # Cost-parameterized bcrypt password hashing and SHA-256 token hashing
│   ├── jobs/                          # Distributed background jobs and leader election coordination
│   ├── jwt/                           # Keyset-aware JWT manager with kid stamping & key rotation
│   ├── logging/                       # Slog JSON handler decorator with automated secret redaction
│   ├── metrics/                       # Prometheus metric registry, counters, and bearer auth guard
│   ├── middleware/                    # Tenant, Auth, RBAC, Sudo, MFA Pending, Rate Limit, Semaphore, Security Headers
│   ├── models/                        # GORM database schemas & domain models
│   ├── netutil/                       # IP resolution, trusted proxy validation, and anti-SSRF CIDR checking
│   ├── repositories/                  # Persistence layer with context & tenant scoping (GORM)
│   ├── response/                      # Standardized JSON response envelope ({code, message, data})
│   ├── routes/                        # Route tree registration, request logger, tracing, trusted proxies
│   ├── services/                      # Business logic, cryptography, security policies (zero Gin deps)
│   ├── store/                         # Key-value state abstraction (InMemoryStore and RedisStore v9)
│   ├── swagger/                       # Documentation-only response envelope types for Swag
│   ├── tenant/                        # Multi-tenancy context injection & extraction helpers
│   └── tracing/                       # OpenTelemetry tracer provider initialization & span propagation
│
├── tests/                             # Dedicated high-level test suites (isolated from domain code)
│   ├── integration/                   # High-level integration tests
│   │   ├── all_49_endpoints_test.go   # Exhaustive audit of all 49 endpoints (<1s runtime on in-memory SQLite)
│   │   ├── live_api_demo_test.go      # Multi-tenant workflow & session verification
│   │   ├── phase1_e2e_test.go         # Account lifecycle, GDPR erasure, MFA aggregation
│   │   └── phase2_e2e_test.go         # Tenant isolation, RBAC, and trusted devices
│   ├── load/                          # Concurrency, benchmark, and k6 load testing scripts
│   │   ├── login_test.js              # Login endpoint concurrency benchmark
│   │   ├── passkey_test.js            # Passkey assertion load test
│   │   ├── README.md                  # Load test execution guide
│   │   ├── refresh_test.js            # Refresh token rotation concurrency test
│   │   ├── register_test.js           # Registration throughput test
│   │   └── totp_load_test.js          # TOTP concurrency and semaphore saturation test
│   ├── passkey_test.html              # Browser testbed for WebAuthn passkey ceremonies
│   └── README.md                      # Test suite quickstart and runner guide
│
├── Bruno/                             # Operational API collection for manual testing (GUI)
│   ├── Admin/                         # Tenant user management, lockout, force-logout, audit export (6 requests)
│   ├── Auth/                          # Core authentication, profile, credentials, sessions, OAuth (22 requests)
│   ├── environments/                  # Environment definitions (Local, Production)
│   ├── MFA/                           # TOTP enrollment, validation, sudo codes, disable (8 requests)
│   ├── Passkey/                       # WebAuthn registration & step-up authentication (6 requests)
│   ├── system/                        # Operational health & metrics probes (3 requests)
│   ├── test/                          # Negative test cases, rate limit abuse, security probes (6 requests)
│   ├── TrustedDevices/                # Remember-me MFA bypass device management (2 requests)
│   └── Webhooks/                      # Signed webhook registration (1 request)
│
├── migrations/                        # Versioned SQL migration files (up/down pairs)
│   ├── 0001_init.up.sql / down.sql
│   ├── 0002_passkey_credentials.up/down
│   ├── 0003_sessions.up.sql / down.sql
│   ├── 0004_enterprise.up.sql / down.sql
│   └── embed.go                       # Embedded migration assets
│
└── docs/                              # OpenAPI 3.0 specification, architecture guides, runbooks
    ├── openapi.yaml                   # OpenAPI 3.0 contract of record
    ├── swagger.json                   # Swagger 2.0 specification
    ├── swagger.yaml                   # Swagger 2.0 YAML specification
    ├── docs.go                        # Embedded Swagger 2.0 Go declarations
    ├── OPERATIONS.md                  # Enterprise operational runbook
    ├── enterprise-review-reconciliation.md
    ├── audit-durable-queue-design.md
    ├── deep-review-remediation-2026-08.md
    ├── supply-chain-hardening-2026-08.md
    └── swagger-integration-handoff-2026-09.md
```

### Architectural Benefits of Separation

1. **Clean Packaging**: Keeping `internal/` packages free from heavy test fixtures maintains rapid compilation and prevents accidental test-only code from leaking into production builds.
2. **Multi-Tier Testing Pyramid**:
   - **Tier 1 - Unit Tests (`internal/*/*_test.go`)**: Lightning-fast tests with mock fakes executing in seconds.
   - **Tier 2 - Exhaustive Audit (`tests/integration/all_49_endpoints_test.go`)**: Self-contained SQLite test verifying all 49 routes in < 1 second.
   - **Tier 3 - Multi-Service Integration (`tests/integration/`)**: Validates real MySQL 8 and Redis instances in CI.
   - **Tier 4 - Executable Manual Collections (`Bruno/`)**: Used by QA engineers and operators to test deployed endpoints without writing custom scripts.

---

## 2. Manual Testing Guide with Bruno

The project includes an operational Bruno collection in the `Bruno/` directory.

### Getting Started

1. Download and install [Bruno](https://www.usebruno.com/).
2. Click **Open Collection** and open:
   ```
   e:/FinnApiGo/Bruno
   ```
3. Select the `local` environment from the top-right environment selector (configured for `http://localhost:8080`).

### Complete Bruno Endpoint Catalog

#### Directory `Bruno/Auth/` (Core Auth, Profile & Sessions):
- `register.yml`: Register a new user account (returns 201 Created).
- `login.yml`: Authenticate with email/password; saves `accessToken` and `refreshToken` into environment variables.
- `refresh-token.yml`: Rotate refresh token and obtain a fresh token pair.
- `forgot-password.yml`: Request password reset email (timing-equalized enumeration resistance).
- `reset-password.yml`: Set a new password using a single-use reset token.
- `verify-email.yml`: Confirm email ownership with verification token.
- `resend-verification.yml`: Request a fresh email verification link.
- `change-email-request.yml`: Request email change (password verified).
- `change-email-confirm.yml`: Confirm new email address using single-use confirmation token.
- `google-login.yml`: Initiate Google OAuth PKCE flow.
- `google-callback.yml`: Exchange OAuth authorization code for session tokens.
- `logout.yml`: Revoke current refresh token.
- `logout-all.yml`: Revoke all active sessions and refresh tokens.
- `change-password.yml`: Update password with current password verification.
- `set-password.yml`: Establish first password for OAuth-only accounts.
- `me.yml`: Fetch authenticated profile information.
- `me-erase.yml`: Permanent GDPR account erasure.
- `audit-log.yml`: View personal security audit log history.
- `deactivate.yml`: Self-deactivate account.
- `oauth-unlink.yml`: Disassociate third-party identity provider.
- `sessions.yml`: List all active sessions with IP, device name, location, and activity timestamps.
- `session-revoke.yml`: Revoke a specific active device session.

#### Directory `Bruno/MFA/` (TOTP Multi-Factor Authentication):
- `login-verify.yml`: Complete pending MFA login with `mfa_pending` JWT and TOTP code.
- `totp-enable.yml`: Generate TOTP secret and provisioning QR URI.
- `totp-verify.yml`: Confirm initial 6-digit TOTP code and display recovery codes.
- `totp-validate.yml`: Re-validate code on an active session.
- `totp-disable.yml`: Disable TOTP factor.
- `methods.yml`: Retrieve unified summary of enabled authentication factors.
- `recovery-codes-view.yml`: View unconsumed recovery codes (mints `X-Sudo-Token`).
- `recovery-codes-regenerate.yml`: Regenerate all recovery codes (requires `X-Sudo-Token`).

#### Directory `Bruno/Passkey/` (FIDO2 / WebAuthn):
- `passkey-register-challenge.yml`: Generate WebAuthn creation options challenge.
- `passkey-register-verify.yml`: Verify attestation response and persist credential.
- `passkey-auth-challenge.yml`: Generate WebAuthn assertion challenge.
- `passkey-auth-verify.yml`: Verify assertion signature and check monotonic clone counter.
- `passkey-list.yml`: List registered passkeys for current user.
- `passkey-revoke.yml`: Revoke a passkey authenticator (requires `X-Sudo-Token`).

#### Directory `Bruno/TrustedDevices/` (Remember-Me):
- `list-devices.yml`: List recognized devices eligible for 30-day MFA bypass.
- `revoke-device.yml`: Revoke trusted device status.

#### Directory `Bruno/Admin/` (Tenant Administration & Governance):
- `list-users.yml`: Search and paginate users within caller's tenant.
- `lock-user.yml`: Lock user account (temporary duration or indefinite).
- `unlock-user.yml`: Unlock user account and reset failure counters.
- `force-logout.yml`: Invalidate all sessions, refresh tokens, and increment password version.
- `tenant-sessions.yml`: Monitor active sessions across the entire tenant.
- `audit-export.yml`: Stream tenant audit logs in CSV or NDJSON format.

#### Directory `Bruno/Webhooks/` (Signed Event Webhooks):
- `create-webhook.yml`: Register outbound webhook URL with SSRF protection and HMAC signature secret.

#### Directory `Bruno/system/` (Operational Probes):
- `healthz.yml`: Liveness health check probe (`GET /healthz`).
- `readyz.yml`: Database readiness probe (`GET /readyz`).
- `metrics.yml`: Prometheus metrics scrape probe (`GET /metrics`).

#### Directory `Bruno/test/` (Negative & Security Scenarios):
- `login-wrongpass-repeat.yml`: Repeated failed login attempts triggering account lockout (expects 401 then 423).
- `register-bigbody.yml`: Request payload exceeding `MaxRequestBodyBytes` (expects 413 Payload Too Large).
- `register-disposable-email.yml`: Disposable email domain rejection (expects 400 Bad Request).
- `register-duplicate.yml`: Duplicate email registration attempt (expects 409 Conflict).
- `register-honeypot.yml`: Registration with honeypot field populated (expects silent 201 without DB persist).
- `register-velocity-repeat.yml`: Rapid registration burst exceeding IP velocity rate limit (expects 429 Too Many Requests).

---

## 3. Automated Test Execution

### 3.1. Fast 49-Endpoint Audit
Run the self-contained audit verifying all 49 Gin routes:
```bash
go test -v -count=1 ./tests/integration/ -run TestAll49Endpoints
```

### 3.2. Fast Unit Tests Across Packages
Execute unit tests across internal packages:
```bash
go test ./internal/...
```

### 3.3. API Contract Drift Verification
Verify that `docs/openapi.yaml` and registered routes match with zero drift:
```bash
go test -v ./internal/apidrift
```

### 3.4. Full Uncached Suite
Run before opening a pull request or deploying to production (executes in ~20 seconds thanks to `BCRYPT_COST` optimization):
```bash
go test -count=1 ./...
```

### 3.5. Integration Tests Against MySQL & Redis
```bash
TEST_MYSQL_DSN='test:testpw@tcp(127.0.0.1:3306)/finnapigo_test?multiStatements=true' \
TEST_REDIS_URL='redis://127.0.0.1:6379/0' \
go test -tags=integration ./...
```

---

## 4. System Health & Observability Probes

When the server is running (`go run cmd/server/main.go`):
- **Liveness Probe**: `GET http://localhost:8080/healthz`
  - Responds with `200 OK` and `{ "code": 200, "message": "ok", "data": { "status": "ok" } }`.
- **Readiness Probe**: `GET http://localhost:8080/readyz`
  - Validates database connectivity with a 3-second timeout.
  - Responds with `200 OK` (`db: "up"`) or `503 Service Unavailable` (`db: "down"`).
- **Prometheus Scrape Endpoint**: `GET http://localhost:8080/metrics`
  - Exposes Go runtime metrics, HTTP counters, store errors, and audit dropped counts.
- **Swagger Documentation**: `GET http://localhost:8080/swagger/index.html`
  - Mounted when `SWAGGER_ENABLED=true`.
