# FinnApiGo Test Suite Guide

This directory contains integration, end-to-end, and performance test suites for the **FinnApiGo** enterprise authentication service.

## 🚀 Quick Start for Developers & AI Agents

To run the complete audit of all **49 registered API endpoints**:

```bash
go test -v -count=1 ./tests/integration/ -run TestAll49Endpoints
```

To run a specific group of endpoints:

```bash
# Operational probes (/healthz, /readyz, /metrics, /swagger/*any)
go test -v -count=1 ./tests/integration/ -run "TestAll49Endpoints/A"

# Core Auth (/register, /login, /refresh-token, /forgot-password, /reset-password, /verify-email, etc.)
go test -v -count=1 ./tests/integration/ -run "TestAll49Endpoints/B"

# OAuth 2.0 / OIDC (/google/login, /google/callback)
go test -v -count=1 ./tests/integration/ -run "TestAll49Endpoints/C"

# Authenticated Profile & Credentials (/logout, /logout-all, /change-password, /set-password, /me, etc.)
go test -v -count=1 ./tests/integration/ -run "TestAll49Endpoints/D"

# Sessions (/sessions, /sessions/:id)
go test -v -count=1 ./tests/integration/ -run "TestAll49Endpoints/E"

# Trusted Devices (/trusted-devices, /trusted-devices/:id)
go test -v -count=1 ./tests/integration/ -run "TestAll49Endpoints/F"

# MFA Pending Isolation (/mfa/login-verify)
go test -v -count=1 ./tests/integration/ -run "TestAll49Endpoints/G"

# TOTP MFA & Sudo Mode (/totp/enable, /verify, /validate, /recovery-codes, /disable, /methods, /regenerate)
go test -v -count=1 ./tests/integration/ -run "TestAll49Endpoints/H"

# Passkey / WebAuthn (/passkey/register/challenge, /verify, /authenticate/challenge, /verify, /passkeys)
go test -v -count=1 ./tests/integration/ -run "TestAll49Endpoints/I"

# Enterprise Admin & Webhook SSRF (/admin/users, /lock, /unlock, /force-logout, /sessions, /export, /webhooks)
go test -v -count=1 ./tests/integration/ -run "TestAll49Endpoints/J"
```

## 📁 Directory Structure

- `tests/integration/all_49_endpoints_test.go`:
  Comprehensive test file covering all 49 endpoints in `internal/routes/routes.go`. Completely self-contained with in-memory SQLite, mock OAuth provider, console email notifier, and anti-SSRF fixtures. Runs in < 1 second.
- `tests/integration/live_api_demo_test.go`: Integration test suite demonstrating multi-tenant session flows.
- `tests/integration/phase1_e2e_test.go`: Phase 1 core authentication and security tests.
- `tests/integration/phase2_e2e_test.go`: Phase 2 RBAC, trusted devices, and admin features.
- `tests/load/`: High-concurrency benchmarks and load tests.
- `tests/passkey_test.html`: Manual WebAuthn testing interface in the browser.
