# Security Policy

## Supported versions

Only the latest commit on `main` receives security fixes. There are no
long-lived release branches; fixes are delivered by deploying the current
`main` build (Render autodeploy / release command).

| Version / ref        | Supported |
| -------------------- | --------- |
| latest commit, `main` | ✅        |
| older commits / tags  | ❌        |

## Reporting a vulnerability

**Do not open a public GitHub issue for security problems.**

1. Use GitHub's private vulnerability reporting:
   **Security → Report a vulnerability** on this repository, or
2. Contact the maintainers directly through the project's private channel.

Please include: affected endpoint(s) or component, reproduction steps or
proof-of-concept, impact assessment, and any logs/IDs observed. You will get
an acknowledgement within **2 business days** and a status update at least
every **5 business days** until resolution.

## Patch SLA (severity targets from disclosure/confirmation)

| Severity (CVSS v4 / consensus) | Fix target             | Notes                                          |
| ------------------------------ | ---------------------- | ---------------------------------------------- |
| Critical (≥ 9.0)               | ≤ 7 days               | Emergency deploy outside the release cadence   |
| High (7.0–8.9)                 | ≤ 30 days              | Standard release train                         |
| Medium (4.0–6.9)               | ≤ 90 days              | Bundled with the next scheduled release        |
| Low (< 4.0)                    | Best effort            | Tracked as normal issues                       |

Toolchain and dependency vulnerabilities are continuously detected by
`govulncheck`, `gosec` and Trivy in CI; only vulnerabilities **reachable from
our code** (symbol-level analysis) force an emergency upgrade — unreachable
module-level advisories are queued for the next scheduled dependency PR.

## Automated defenses already in place

- Strict allowlist CORS, security headers middleware (HSTS configurable),
  per-IP rate limiting and per-endpoint concurrency caps.
- Mandatory MFA (TOTP) with encrypted-at-rest recovery codes, WebAuthn
  passkeys, argon-grade password hashing, JWT key rotation with `kid`.
- Secret-free logging via a redacting `slog` handler; audit trail with PII
  retention policy.
- Supply chain: pinned GitHub Actions (commit SHA), pinned CI toolchain,
  CycloneDX SBOM per push, Dependabot weekly, Trivy config/container scan.

## Data protection note (Nghị định 13/2023/NĐ-CP)

This service processes personal data (email, IP, device metadata). Breach
notification and data-subject request procedures are operated by the service
operator, not the repository. See `README.md` (PII/retention policy) and
`docs/enterprise-review-reconciliation.md` for the control inventory.
