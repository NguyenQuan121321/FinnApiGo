# Enterprise Review Reconciliation — Phase 0

Baseline: branch `feat/enterprise-readiness` from `main` @ `32e957e`.
Gate evidence: `go build ./...`, `go vet ./...`, `go test ./... -count=1`,
`golangci-lint run ./...` — all clean (see Phase 0 report).

The external AI review (2026-08) predates the v2 hardening (PR #4 + follow-ups).
Every item below was verified **by symbol** against the current tree.

## Verify-first items (believed already fixed by v2) — all confirmed

| Review claim | Status | Evidence |
|---|---|---|
| Refresh-rotation race | ALREADY-DONE | `RefreshTokenRepository.Revoke` compare-and-set (`revoked = false` guard + `RowsAffected` → `ErrTokenAlreadyRevoked`), `internal/repositories/refresh_token_repository.go:68` — commit `d1c15fe` [C1] |
| Missing index `used_tokens(expires_at)` | ALREADY-DONE | `idx_used_tokens_expires_at` in `migrations/0001_init.up.sql:71`; batched purge in `internal/repositories/batched_delete.go` — commit `4cd8bef` [P1] |
| AutoMigrate at boot | ALREADY-DONE | Gated behind `MIGRATE_AUTO` (default false), `cmd/server/main.go:67` — commit `71d9402` [R1] |
| Audit retention job | ALREADY-DONE | `startCleanup` → `AuditRepository.PurgeOlderThan`, `cmd/server/main.go:295` — commit `80a705b` [R4] |
| Silent config fallbacks | ALREADY-DONE | `loader` fail-fast on invalid int/bool/float/duration, `internal/config/config.go:334` — commit `366e60c` [R2] |
| DSN timezone | ALREADY-DONE | `loc=UTC` pinned in `DBConfig.DSN`, `internal/config/config.go:76` — commit `470af09` [R3] |

## Known-Issue Catalog reconciliation

| ID | Finding | Status | Evidence / plan |
|---|---|---|---|
| K1 | `RECOVERY_CODE_KEY` falls back to JWT_SECRET derivation | **OPEN** | `recoveryEncryptionKey` (`cmd/server/main.go:259`) only warns in every mode. Phase 1: release mode refuses to boot; dev keeps loud warning. |
| K2 | Single HMAC secret, no `kid`, no rotation path | **OPEN** | `JWTManager` holds one secret (`internal/jwt/jwt.go:37`), no `kid` header. Phase 1: `kid` on issue, versioned key map (`JWT_SECRET` + `JWT_SECRET_PREVIOUS`), HS256-only preserved. |
| K3 | No KMS seam | **OPEN** | No `KeyProvider` interface exists. Phase 1: design-level `crypto.KeyProvider` behind `KEY_PROVIDER=env\|file`; vendor binding is an operator decision. |
| X1 | `/metrics` unauthenticated on public listener | **OPEN** | Mounted on the public router (`internal/routes/routes.go:78`), no `METRICS_ADDR` / `METRICS_TOKEN` anywhere. Phase 2. |
| X2 | pprof internal-listener policy / unification | **OPEN (partial)** | pprof already internal-only via `PPROF_ADDR` private mux (`cmd/server/main.go:310`, commit `08c5167` [P3]). Remaining: unify metrics+pprof behind one internal server. Phase 2. |
| S1 | Per-IP limiter process-local under Redis | **ALREADY-DONE** | `RateLimiter.Handler` shared-counter path (`rate:ip:` key via `store.IncrBy`) wired with the shared store in `cmd/server/main.go:176`; Lua fixed-window keeps C4 TTL-anchor semantics (`internal/store/redis.go:27`), counters fail open per A1. Tests: `TestRateLimiterSharedCounter*`, `TestRedisStore_IncrBy_FixedWindowNotExtended_C4`. Phase 3 adds the two-instance gate test if missing (test-only). |
| S2 | Background jobs run on every instance | **OPEN** | `go startCleanup(...)` unconditional (`cmd/server/main.go:213`). Phase 3: leader election via `store.Store` CAS lock + `RUN_JOBS` flag; both documented. |
| S3 | Concurrent-refresh integration coverage | **OPEN** | No test fires N concurrent refreshes against a real stack. Phase 3 (testcontainers, `-tags=integration`). |
| D1 | Index audit: refresh_tokens(user_id/token_hash), audit_logs(created_at/user_id) | **ALREADY-DONE (pending EXPLAIN evidence)** | All four exist in `migrations/0001_init.up.sql:40-58` (`idx_refresh_tokens_user_id`, `uni_refresh_tokens_token_hash`, `idx_audit_logs_created_at`, `idx_audit_logs_user_id`). Phase 4 captures EXPLAIN output as evidence. |
| D2 | Rotation hot-path query cost | **OPEN (measure first)** | Rotation is CAS-update by `token_hash` (indexed UNIQUE). Phase 4 measures EXPLAIN + benchmark; rewrite only on evidence, else REJECTED-with-evidence. |
| G1 | Retention defaults to keep-forever | **OPEN** | `RetentionDays` default 0 = keep forever (`internal/config/config.go:306`); no release-mode boot warning. Phase 5: boot warning + README PII/retention policy + durable-queue design note. |
| G2 | No log redaction guarantee | **OPEN** | No redaction handler exists; request logger hand-picks safe fields only. Phase 5: redacting `slog.Handler` wrapper for secret-shaped fields. |
| O1 | No distributed tracing | **OPEN** | No otel usage. Phase 6: otel + otelgin, no-op exporter when `OTEL_EXPORTER_OTLP_ENDPOINT` unset. |
| O2 | Trace IDs not in logs | **OPEN** | No `trace_id`/`span_id` anywhere. Phase 6: slog enrichment from span context. |
| O3 | Fine-grained auth metrics missing | **OPEN** | Only `store_errors_total`, `audit_entries_dropped_total`, `rate_limited_requests_total`, `audit_buffer_depth` exist (`internal/metrics/metrics.go`). Phase 6 adds login/refresh/reuse/TOTP outcome counters. |
| T1 | No CI integration layer | **OPEN** | `.github/workflows/ci.yml` has a single job, no service containers. Phase 7: MySQL+Redis job, `go test -tags=integration ./... -race`, migration up/down test. |
| T2 | No fuzzing | **OPEN** | No `FuzzXxx` in tree. Phase 7: JWT parse, TOTP validation, recovery-code consumption. |
| T3 | No coverage gates | **OPEN** | CI runs `-cover` without a floor. Phase 7: floor at currently-measured coverage for `internal/services` + `internal/jwt`. |
| T4 | Image/dependency scanning gaps | **OPEN** | govulncheck runs; no dedicated gosec run, no container scan. Phase 7: gosec + trivy steps. |
| A1 | No OpenAPI spec | **OPEN** | No `docs/` directory at all. Phase 8: `docs/openapi.yaml` + drift check. |
| W1–W8 | Passkeys / WebAuthn | **OPEN** | No passkey code, no `go-webauthn` dependency. Phase 9 sub-phases 9A–9E. |

## Phase mapping

- Phase 1: K1, K2, K3 · Phase 2: X1, X2 · Phase 3: S1 (gate test), S2, S3
- Phase 4: D1 (EXPLAIN evidence), D2 · Phase 5: G1, G2 · Phase 6: O1, O2, O3
- Phase 7: T1–T4 · Phase 8: A1 · Phase 9: W1–W8 · Phase 10: final DoD
