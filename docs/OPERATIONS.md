# Enterprise Operations and Testing Runbook

This document details the architectural separation between operational production code and test suites, manual verification using Bruno API collections, and automated testing procedures for the FinnApiGo Enterprise Authentication service.

---

## 1. Enterprise Separation of Concerns

In modern enterprise architectures, a strict boundary is enforced between operational application code and high-level testing infrastructure:

```
FinnApiGo/
├── cmd/                          # Production entry points
│   ├── server/                   # HTTP server daemon
│   └── migrate/                  # Database migration CLI tool
│
├── internal/                     # Core domain business logic (private, encapsulated)
│   ├── routes/                   # HTTP route tree and middleware wiring
│   ├── handlers/                 # Request binding, response formatting, and validation
│   │   ├── *_test.go             # Unit tests isolated per handler
│   ├── services/                 # Business logic, cryptography, security policies
│   │   ├── *_test.go             # Mock-based unit tests
│   ├── repositories/             # Persistence layer (GORM / MySQL / SQLite)
│   │   ├── *_test.go             # Repository data-access tests
│   ├── middleware/               # Auth, security headers, rate limiting, CORS, RBAC
│   ├── models/                   # Database entities and GORM schemas
│   ├── tenant/                   # Tenant isolation context helpers
│   └── config/                   # Strongly typed application configuration
│
├── tests/                        # Dedicated high-level test suites (isolated from domain code)
│   ├── integration/              # End-to-end integration tests running on real/in-memory DB
│   │   ├── phase1_e2e_test.go    # Account lifecycle, GDPR erasure, MFA aggregation
│   │   └── phase2_e2e_test.go    # Multi-tenant isolation, RBAC, hash chaining, trusted device
│   └── load/                     # Concurrency, benchmark, and load testing
│
├── Bruno/                        # Operational API collection (GUI manual testing)
│   ├── Auth/                     # Authentication, email change, deactivation, erasure
│   ├── MFA/                      # TOTP enrollment, validation, disable, recovery codes
│   ├── Admin/                    # Tenant user management, lockout, force-logout, audit export
│   ├── TrustedDevices/           # Remember-me MFA bypass device management
│   ├── Webhooks/                 # Webhook subscription registration
│   └── environments/             # Environment configuration (local, staging, production)
│
├── migrations/                   # Versioned database migration scripts (up / down)
└── docs/                         # OpenAPI 3.0 specification, architecture guides, runbooks
```

### Architectural Benefits of Separation

1. **Maintainability and Developer Experience**: Keeping `internal/` packages focused solely on domain logic and lightweight unit tests prevents cognitive overload from hundreds of lines of integration fixtures.
2. **Standard Testing Pyramid**:
   - **Tier 1 - Unit Tests (`internal/*/*_test.go`)**: Fast, mock-based unit tests executing in seconds on local workstations and pre-commit hooks.
   - **Tier 2 - Integration and E2E Tests (`tests/integration/`)**: Complete user journeys and security assertions running against pure-Go SQLite or staging MySQL instances.
   - **Tier 3 - Operational Collections (`Bruno/`)**: Executable API collections used by QA engineers, operations teams, and product managers for manual acceptance testing across environments.

---

## 2. Manual Testing Guide with Bruno

The project includes an operational Bruno collection in the `Bruno/` directory for manual testing without external dependencies.

### Getting Started

1. Download and install [Bruno](https://www.usebruno.com/).
2. Select **Open Collection** and choose the directory:
   ```
   e:/FinnApiGo/Bruno
   ```
3. Select the `local` environment in the top-right dropdown (defaults to `http://localhost:8080`).

### Endpoint Catalog in Bruno

#### Directory `Bruno/Auth/`:
- `register.yml`: Register a new user account.
- `login.yml`: Authenticate with email/password and obtain `accessToken` and `refreshToken`.
- `change-email-request.yml`: Request email address change (password verified).
- `change-email-confirm.yml`: Confirm email change token and revoke existing sessions.
- `deactivate.yml`: Self-deactivate account (password or sudo token gated).
- `me-erase.yml`: Permanent account erasure (GDPR Right to Erasure).
- `audit-log.yml`: Inspect personal security audit history (paginated).
- `oauth-unlink.yml`: Disassociate third-party identity provider (Google OAuth).
- `sessions.yml`: List all active login sessions for the authenticated user.
- `session-revoke.yml`: Revoke a specific active device session.

#### Directory `Bruno/MFA/`:
- `totp-enable.yml`: Initialize TOTP secret and QR code URI.
- `totp-verify.yml`: Confirm initial 6-digit TOTP code and obtain recovery codes.
- `totp-validate.yml`: Validate second-factor code during step-up or login.
- `methods.yml`: Aggregate summary of enabled authentication factors.
- `totp-disable.yml`: Disable TOTP (sudo token or password + TOTP code required).
- `recovery-codes-view.yml`: View unconsumed recovery codes (sudo-gated).
- `recovery-codes-regenerate.yml`: Invalidate and regenerate recovery codes.

#### Directory `Bruno/Admin/`:
- `list-users.yml`: List tenant users with pagination and search filtering.
- `lock-user.yml`: Temporarily or indefinitely lock a user account.
- `unlock-user.yml`: Unlock account and reset failed login attempt counters.
- `force-logout.yml`: Revoke all sessions, refresh tokens, and increment password version immediately.
- `tenant-sessions.yml`: Monitor all active sessions within the tenant.
- `audit-export.yml`: Stream audit logs in CSV or NDJSON format.

#### Directory `Bruno/TrustedDevices/`:
- `list-devices.yml`: List remembered devices eligible for 30-day MFA bypass.
- `revoke-device.yml`: Revoke trusted status for a specific device.

#### Directory `Bruno/Webhooks/`:
- `create-webhook.yml`: Register outbound webhook endpoint with HMAC-SHA256 signature.

---

## 3. Automated Test Execution

### 3.1. Fast Unit Tests
Run unit tests across internal packages:
```bash
go test ./internal/...
```

### 3.2. End-to-End Integration Suite
Execute the high-level integration suite:
```bash
go test -v ./tests/integration/...
```

### 3.3. API Contract Drift Verification
Verify that `docs/openapi.yaml` matches registered Gin routes exactly:
```bash
go test -v ./internal/apidrift
```

### 3.4. Full Uncached Test Suite
Run before opening a pull request or deploying to CI/CD:
```bash
go test -count=1 ./...
```

---

## 4. System Health and Observability

When the server is running (`go run cmd/server/main.go`):
- **Health Check**: `GET http://localhost:8080/healthz` (liveness probe).
- **Readiness Check**: `GET http://localhost:8080/readyz` (database connectivity probe).
- **Prometheus Metrics**: `GET http://localhost:8080/metrics` (request counts, latency distributions, failure counters).
