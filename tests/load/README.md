# Load tests (k6)

k6 scenarios covering the auth API's hot and abuse paths. All tests default
to `http://localhost:8081` and override via `<NAME>_BASE_URL` env vars.

## Scenarios

| File | Endpoint(s) | Scenario | What it proves |
|---|---|---|---|
| `login_test.js` | `/auth/login`, `/auth/register` | `steady` (50 VUs, 20s valid logins) then `wrongpass` (30 VUs, 15s bad passwords) | bcrypt hot path stays under p95 500ms; wrong-password churn drives the per-account velocity window (429s counted, not treated as errors) |
| `refresh_test.js` | `/auth/refresh-token` | `rotate` (40 VUs each maintaining a token chain for 30s) | rotation CAS (C1) never falsely fires on a well-behaved sequential chain; p95 < 300ms; any 401 mid-chain is an error |
| `totp_load_test.js` | `/auth/mfa/totp/validate` | `normal` (30 VUs) + `ddos_spike` (300 VUs invalid codes / 15s) | validation stays fast; rate + concurrency limiters absorb the spike with bounded p95 |
| `register_test.js` | `/auth/register` | 50 VUs, 10s | registration throughput incl. unique-index inserts |

## Running

```bash
# server must be up and reachable; each run seeds its own users via /register
k6 run tests/load/login_test.js
k6 run tests/load/refresh_test.js
k6 run tests/load/totp_load_test.js

# single scenario / custom target:
LOGIN_BASE_URL=http://perf-internal:8081 k6 run --scenario steady tests/load/login_test.js
```

## Thresholds (enforced — k6 exits non-zero)

- login `steady`: p95 < 500ms, HTTP failure rate < 1%
- refresh `rotate`: p95 < 300ms, failure rate < 1%
- TOTP `normal`: p95 < 200ms; `ddos_spike`: bounded p95, no non-429 errors, guards observed firing

## Baselines

Measured numbers are captured per environment — run the block above against
the perf environment and record results here:

| Scenario | Date | Host | p50 | p95 | p99 | req/s | errors | notes |
|---|---|---|---|---|---|---|---|---|
| login steady | _pending_ | | | | | | | |
| login wrongpass (429 rate) | _pending_ | | | | | | | |
| refresh rotate | _pending_ | | | | | | | |
| totp normal | _pending_ | | | | | | | |
| totp ddos_spike | _pending_ | | | | | | | |

**Status (2026-08-17):** not yet measured — the authoring environment has no
reachable MySQL/Docker, so no server could be booted. The scenarios and their
enforced thresholds are in place; capture the table above on the perf
environment before treating any of these paths as regression-free.
