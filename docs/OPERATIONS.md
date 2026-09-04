# Enterprise Operations and Testing Runbook

This document details the architectural separation between operational application code and testing infrastructure, manual verification using the Bruno API collections, automated test execution, and deployment health verification for the **FinnApiGo** Enterprise Authentication service.

---

## 1. Enterprise Separation of Concerns

FinnApiGo enforces strict boundaries between operational domain logic, infrastructure persistence, and test suites:

```
FinnApiGo/
├── cmd/                          # Production entry points
│   ├── server/                   # HTTP daemon composition root & graceful shutdown
│   └── migrate/                  # Database migration CLI runner
│
├── internal/                     # Core domain business logic (private, encapsulated)
│   ├── routes/                   # Route tree registration and middleware pipelines
│   ├── handlers/                 # HTTP request decoding, DTO validation, and response envelopes
│   ├── services/                 # Business logic, cryptography, security policies (zero Gin deps)
│   ├── repositories/             # Persistence layer with context & tenant scoping (GORM)
│   ├── middleware/               # Auth, RBAC, Sudo, Tenant, Rate Limiting, Concurrency Limiting
│   ├── tenant/                   # Multi-tenancy context injection & extraction helpers
│   ├── store/                    # Key-value state abstraction (In-Memory and Redis v9)
│   ├── models/                   # GORM domain models
│   └── config/                   # Twelve-Factor typed configuration
│
├── tests/                        # Dedicated high-level test suites (isolated from domain code)
│   ├── integration/              # High-level integration tests
│   │   ├── all_49_endpoints_test.go # Exhaustive audit of all 49 endpoints (<1s execution)
│   │   ├── live_api_demo_test.go # Multi-tenant workflow & session verification
│   │   ├── phase1_e2e_test.go    # Account lifecycle, GDPR erasure, MFA aggregation
│   │   └── phase2_e2e_test.go    # Tenant isolation, RBAC, and trusted devices
│   ├── load/                     # Concurrency, benchmark, and k6 load testing scripts
│   ├── passkey_test.html         # Browser testbed for WebAuthn passkey ceremonies
│   └── README.md                 # Test suite quickstart and runner guide
│
├── Bruno/                        # Operational API collection for manual testing (GUI)
│   ├── Auth/                     # 22 requests covering registration, login, profile, sessions
│   ├── MFA/                      # 8 requests covering TOTP enrollment, validation, sudo codes
│   ├── Passkey/                  # 6 requests covering WebAuthn registration & step-up auth
│   ├── Admin/                    # 6 requests covering tenant users, lock, unlock, export
│   ├── TrustedDevices/           # 2 requests covering remember-me device management
│   ├── Webhooks/                 # 1 request covering signed webhook registration
│   └── environments/             # Environment definitions (Local, Staging, Production)
│
├── migrations/                   # Embedded SQL migration pairs (up / down)
└── docs/                         # OpenAPI 3.0 specification, architecture guides, runbooks
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
