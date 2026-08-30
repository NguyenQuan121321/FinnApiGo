# Supply-Chain & Dependency Hardening — 2026-08

Execution of the dependency/toolchain review (2026-08-30) against strict
enterprise criteria (NIST SSDF, OWASP, SLSA, ISO/IEC 27001:2022, and Vietnam's
Decree 13/2023/NĐ-CP / Decree 85/2016/NĐ-CP). This document is the record of
what changed, why, and the verification evidence.

## 1. Findings that drove this batch

| # | Finding | Severity |
|---|---------|----------|
| F1 | Production built on **Go 1.25** — series EOL the day Go 1.27.0 shipped (2026-08). The 6 reachable stdlib advisories (GO-2026-6218, -6091, -6090, -6089, -5972, -5026) plus 2 package-level ones (GO-2026-6088, -5942) are fixed only in **go1.26.6+**; no patched 1.25.x exists. | Critical |
| F2 | Runtime base image `alpine:3.20` — **EOL 2026-04-01**, four months without upstream patches. | High |
| F3 | 8 of 25 direct Go modules outdated — worst: `gorm.io/gorm` six minors behind (v1.25.12 → v1.31.2). | Medium |
| F4 | GitHub Actions pinned by branch/tag (`trivy-action@master`), lint toolchain unpinned → build reproducibility and supply-chain risk (OWASP A08). | Medium |
| F5 | No automated dependency-update mechanism (no Dependabot/Renovate) — the root cause of F3 drift. | Medium |
| F6 | No SBOM, no security policy, no patch SLA. | Medium |

## 2. Changes delivered

### 2.1 Toolchain (F1, F2)

- `go.mod`: `go 1.25.0` → `go 1.26.7`, explicit `toolchain go1.26.7` directive
  (deterministic builds on every machine).
- CI `setup-go`: `1.25.13` → `1.26.7` (all four jobs).
- `Dockerfile` builder: `golang:1.25-alpine` → `golang:1.26.7-alpine` (exact
  supported patch, no floating minor).
- `Dockerfile` runtime: `alpine:3.20` → `alpine:3.22` (supported until
  2027-05-01; both base image pins are Dependabot-managed from here on).

### 2.2 Dependency refresh (F3)

All outdated direct modules upgraded. The only source change required was
migrating `internal/services/passkey_ceremony_test.go` off the Go 1.26
`ecdsa.PublicKey.X`/`.Y` deprecated accessors to `PublicKey.Bytes()` (SEC1
uncompressed encoding) — caught by staticcheck SA1019, proving the lint gate
works on toolchain-driven deprecations. The existing unit suite, race builds
and integration suites are the compatibility gate.

| Module | Before | After |
| ------ | ------ | ----- |
| gorm.io/gorm | v1.25.12 | v1.31.2 |
| gorm.io/driver/mysql | v1.5.7 | v1.6.0 |
| github.com/go-sql-driver/mysql | v1.7.0 | v1.10.0 |
| go.opentelemetry.io/otel (+sdk/trace/exporters) | v1.44.0 | v1.46.0 |
| otelgin | v0.69.0 | v0.71.0 |
| google.golang.org/api | v0.293.0 | v0.295.0 |
| github.com/pquerna/otp | v1.4.0 | v1.5.0 |
| github.com/bytedance/sonic | v1.15.1 | v1.15.3 |

The remaining 17 direct modules were already current and are untouched.

### 2.3 CI supply-chain hardening (F4)

Every `uses:` is now pinned to a full commit SHA (annotated-tag SHA peeled to
the commit), with the release tag recorded in a trailing comment:

| Action | Version | Commit SHA |
| ------ | ------- | ---------- |
| actions/checkout | v7.0.1 | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| actions/setup-go | v7.0.0 | `b7ad1dad31e06c5925ef5d2fc7ad053ef454303e` |
| golangci/golangci-lint-action | v9.3.0 | `ba0d7d2ec06a0ea1cb5fa41b2e4a3ab91d21278a` |
| aquasecurity/trivy-action | v0.36.0 | `ed142fd0673e97e23eac54620cfb913e5ce36c25` |
| anchore/sbom-action | v0.24.2 | `3ad7283483fc7af8ff2b4ea19663c2d5ca935e26` |
| actions/upload-artifact | v7.0.1 | `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` |

The lint version is additionally pinned (`v2.12.2`) to match the local dev
toolchain, eliminating version drift between developer machines and CI.

### 2.4 SBOM generation (F6)

New `sbom` CI job: every push emits a **CycloneDX JSON SBOM** of the module
graph as a build artifact (`finnapigo-sbom.cdx.json`). Supports vulnerability
triage, license review and the NIST SSDF PS.3.2 / SLSA component-inventory
expectations.

### 2.5 Automated dependency updates (F5)

`.github/dependabot.yml` — weekly schedule for `gomod`, `github-actions` and
`docker`; minor+patch bumps grouped into one PR per ecosystem, majors arrive
individually, security updates bypass the schedule entirely.

### 2.6 Security policy (F6)

`SECURITY.md` — supported-versions table, private disclosure process
(GitHub private vulnerability reporting), acknowledgement ≤ 2 business days,
and a patch SLA: **Critical ≤ 7 days, High ≤ 30 days, Medium ≤ 90 days**.
Policy explicitly distinguishes symbol-reachable vulnerabilities (emergency
upgrade) from unreachable module-level advisories (next scheduled PR) —
matching how `govulncheck` reports.

### 2.7 Repository hygiene

- `.gitattributes`: canonical LF for all text files (CRLF only for Windows
  scripts). Ends the Windows-checkout churn that made `go mod tidy -diff`
  report a whole-file diff on go.sum. `go.mod`/`go.sum` renormalized to LF.
- `.gitignore`: local root build artifacts `migrate`, `server` now ignored.

## 3. Vulnerability closure evidence

`govulncheck ./...` (symbol-level analysis), before → after:

| Result class | Before | After |
| ------------ | ------ | ----- |
| Reachable from our code (stdlib) | 6 | **0** |
| Imported packages (not called) | 2 | **0** |
| Module-level advisories | 1 | 1 — GO-2026-5932 (`x/crypto/openpgp` unmaintained, fix N/A). Mitigated: no import of `openpgp` anywhere in `cmd/` or `internal/`; unreachable-by-construction, tracked for the next scheduled dependency PR. |

## 4. Verification record (2026-08-31, Go 1.26.7, Windows host)

| Check | Result |
| ----- | ------ |
| `go build ./...` | OK |
| `go vet ./...` | OK |
| `go test ./...` (unit, all packages) | OK |
| `golangci-lint run` (v2.12.2, 11 linters) | 0 issues |
| `govulncheck ./...` | 0 reachable vulnerabilities |
| `go mod tidy -diff` | clean |
| `go mod verify` | all modules verified |
| Workflow YAML parse (`ci.yml`, `dependabot.yml`) | OK |

Integration (`-tags=integration`) and race/fuzz/coverage jobs run on CI
against real MySQL 8 + Redis 7 service containers — same gates as before the
upgrade, so any behavioral regression introduced by GORM 1.31.2 or otp 1.5.0
fails the pipeline.

## 5. Standards mapping

| Standard / control | Status after this batch |
| ------------------ | ----------------------- |
| NIST SP 800-218 SSDF — PW.4/RV.1/RV.2 (vuln management), PS.3.2 (component inventory) | ✅ govulncheck+Trivy+gosec in CI; SBOM per push |
| OWASP Top 10 2021 — A06 (vulnerable & outdated components) | ✅ closed; Dependabot prevents recurrence |
| OWASP Top 10 2021 — A08 (software & data integrity) | ✅ SHA-pinned actions, pinned toolchains, SBOM |
| SLSA v1 (build level) | ✅ improved (pinned inputs, component inventory); full provenance attestation remains a future option |
| ISO/IEC 27001:2022 — A.8.8 (management of technical vulnerabilities) | ✅ SLA documented in SECURITY.md, detection automated |
| Decree 13/2023/NĐ-CP — Art. 24 (safeguards for personal-data processing) | ✅ supported: patched runtime, documented policy surface |
| Decree 85/2016/NĐ-CP (system-safety grading) | ✅ patch-management process now documented and measurable |

## 6. Open items (deliberately not done here)

1. **LICENSE** — legal/ownership decision, not a technical one; required only
   if the repository is published or shared with partners.
2. **Docker base-image digest pinning** — stronger than tag pinning; adds
   Dependabot noise. Revisit if SLSA level targets increase.
3. **Go 1.27.0 adoption** — 1.26.7 is the conservative supported choice;
   evaluate 1.27 after the first patch release (1.27.1).
4. **GORM major-version watch** — v1.31.2 is current; re-check the delta each
   quarter (Dependabot will surface it).
5. Full **SLSA provenance attestation** on release artifacts (goreleaser +
   SLSA GitHub generator) when a formal release process lands.
