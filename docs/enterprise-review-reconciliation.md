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
| K3 | No KMS seam | **DONE** | `crypto.KeyProvider` (`internal/crypto/keyprovider.go`) with Env/File providers behind `KEY_PROVIDER=env\|file` + `KEY_DIR`; Vault/AWS/GCP plug-in documented in the package comment; no vendor SDK bound (operator decision). |
| X1 | `/metrics` unauthenticated on public listener | **DONE** | `METRICS_ADDR` moves /metrics onto a dedicated internal listener; `METRICS_TOKEN` bearer gate (constant-time compare); release mode warns when unset. httptest gates in `internal/metrics` + `internal/routes`. |
| X2 | pprof internal-listener policy / unification | **DONE** | pprof + metrics unified: one internal server when `METRICS_ADDR == PPROF_ADDR`, otherwise per-feature listeners with the same semantics (`startInternalServers`). |
| S1 | Per-IP limiter process-local under Redis | **DONE (gate test added)** | `RateLimiter.Handler` shared-counter path (`rate:ip:` key via `store.IncrBy`) wired with the shared store in `cmd/server/main.go:176`; Lua fixed-window keeps C4 TTL-anchor semantics (`internal/store/redis.go:27`), counters fail open per A1. Tests: `TestRateLimiterSharedCounter*`, `TestRedisStore_IncrBy_FixedWindowNotExtended_C4`. Phase 3 adds the two-instance gate test if missing (test-only). |
| S2 | Background jobs run on every instance | **DONE** | `internal/jobs.LeaderRunner`: SetNX lock + Renew heartbeat via the shared store (single-instance is always leader); `RUN_JOBS` tri-state override; two-contender + failover tests. |
| S3 | Concurrent-refresh integration coverage | **DONE** | `TestRefresh_ConcurrentRotationExactlyOneWinner_S3` — 16 concurrent refreshes vs real MySQL: exactly 1 winner, 15 reuse-audited losers. |
| D1 | Index audit: refresh_tokens(user_id/token_hash), audit_logs(created_at/user_id) | **ALREADY-DONE (pending EXPLAIN evidence)** | All four exist in `migrations/0001_init.up.sql:40-58` (`idx_refresh_tokens_user_id`, `uni_refresh_tokens_token_hash`, `idx_audit_logs_created_at`, `idx_audit_logs_user_id`). Phase 4 captures EXPLAIN output as evidence. |
| D2 | Rotation hot-path query cost | **OPEN (measure first)** | Rotation is CAS-update by `token_hash` (indexed UNIQUE). Phase 4 measures EXPLAIN + benchmark; rewrite only on evidence, else REJECTED-with-evidence. |
| G1 | Retention defaults to keep-forever | **OPEN** | `RetentionDays` default 0 = keep forever (`internal/config/config.go:306`); no release-mode boot warning. Phase 5: boot warning + README PII/retention policy + durable-queue design note. |
| G2 | No log redaction guarantee | **OPEN** | No redaction handler exists; request logger hand-picks safe fields only. Phase 5: redacting `slog.Handler` wrapper for secret-shaped fields. |
| O1 | No distributed tracing | **DONE** | `internal/tracing` (OTLP/HTTP exporter + W3C propagator) + otelgin middleware; no-op provider when `OTEL_EXPORTER_OTLP_ENDPOINT` unset. |
| O2 | Trace IDs not in logs | **DONE** | Request logger emits `trace_id`/`span_id` from the request span; gate test proves traceparent propagation. |
| O3 | Fine-grained auth metrics missing | **DONE** | Label-free counters: `login_success_total`, `login_failure_total`, `refresh_rotations_total`, `token_reuse_detections_total`, `totp_failure_total` (+ alert suggestions in README). |
| T1 | No CI integration layer | **OPEN** | `.github/workflows/ci.yml` has a single job, no service containers. Phase 7: MySQL+Redis job, `go test -tags=integration ./... -race`, migration up/down test. |
| T2 | No fuzzing | **OPEN** | No `FuzzXxx` in tree. Phase 7: JWT parse, TOTP validation, recovery-code consumption. |
| T3 | No coverage gates | **OPEN** | CI runs `-cover` without a floor. Phase 7: floor at currently-measured coverage for `internal/services` + `internal/jwt`. |
| T4 | Image/dependency scanning gaps | **OPEN** | govulncheck runs; no dedicated gosec run, no container scan. Phase 7: gosec + trivy steps. |
| A1 | No OpenAPI spec | **OPEN** | No `docs/` directory at all. Phase 8: `docs/openapi.yaml` + drift check. |
| W1–W8 | Passkeys / WebAuthn | **DONE** | 9A: migration+model+repo [W1][W2]; 9B: registration ceremony, 60s store challenges [W3][W4]; 9C: authentication + clone revoke/audit [W5]; 9D: list + sudo revoke + last_used_at [W6]; 9E: policy config (`WEBAUTHN_*`), rate limits on all POSTs, recovery policy + HTTPS docs, full-ceremony tests via software authenticator, k6 scenario [W7][W8]. |

## Phase mapping

- Phase 1: K1, K2, K3 · Phase 2: X1, X2 · Phase 3: S1 (gate test), S2, S3
- Phase 4: D1 (EXPLAIN evidence), D2 · Phase 5: G1, G2 · Phase 6: O1, O2, O3
- Phase 7: T1–T4 · Phase 8: A1 · Phase 9: W1–W8 · Phase 10: final DoD
