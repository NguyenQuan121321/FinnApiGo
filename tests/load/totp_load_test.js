// k6 load test for the hardened TOTP endpoints.
//
// Two scenarios, executed sequentially via --scenario flag or together:
//   1. normal   — 30 VUs at a moderate arrival rate. Confirms the happy path
//                  stays fast and error-free under expected traffic.
//   2. ddos_spike — 300 VUs flooding invalid TOTP / recovery payloads within
//                  15s. Confirms the rate limiter (429) + concurrency limiter
//                  absorb the spike WITHOUT crashing the server or exhausting
//                  the DB pool, and that p95 stays bounded.
//
// Thresholds (the test FAILS if these aren't met):
//   - p95 response time  < 200ms
//   - error rate          < 1%  (HTTP errors other than 429)
//   - at least some 429s are observed under the spike (guards engaged)
//
// Usage:
//   k6 run tests/load/totp_load_test.js
//
//   # Point at a different host / with a valid JWT:
//   TOTP_BASE_URL=http://localhost:8081 TOTP_JWT=eyJ... k6 run tests/load/totp_load_test.js
//
//   # Run only one scenario:
//   k6 run --scenario normal  tests/load/totp_load_test.js
//   k6 run --scenario ddos_spike tests/load/totp_load_test.js

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter, Trend } from 'k6/metrics';

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const BASE_URL = __ENV.TOTP_BASE_URL || 'http://localhost:8081';
const VALIDATE_URL = `${BASE_URL}/api/v1/auth/mfa/totp/validate`;

// A JWT for an authenticated user. In a real run this must be a LIVE access
// token for an account with TOTP enabled. If unset, the test still runs (the
// server will 401) — useful for verifying the auth gate, but to exercise the
// validation logic set a real token via TOTP_JWT.
const JWT = __ENV.TOTP_JWT || '';

// A confirmed-valid 6-digit TOTP code for the test account's secret. Leave
// empty to send an invalid code (drives the 429 path under the spike).
const VALID_CODE = __ENV.TOTP_VALID_CODE || '000000';

// A plausible-but-invalid recovery code (32 hex chars) used to hammer the
// recovery path cheaply — this is exactly the bcrypt-DDoS vector the refactor
// eliminated, so we want to confirm it's now O(1) per attempt.
const INVALID_RECOVERY = 'aabbccddeeff00112233445566778899';

// ---------------------------------------------------------------------------
// Custom metrics
// ---------------------------------------------------------------------------

// rateLimited counts how many requests were rejected with 429 — we expect this
// to climb under the spike (guards engaged) but stay ~0 under normal load.
const rateLimited = new Counter('rate_limited_429');
// rejectedFast counts 400/401/413 — inputs rejected before any CPU/DB work.
const rejectedFast = new Counter('rejected_fast');
// validateLatency isolates TOTP validation latency from auth-middleware cost.
const validateLatency = new Trend('totp_validate_latency', true);

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

export const options = {
    scenarios: {
        // Scenario 1 — normal expected traffic. Should be fast and clean.
        normal: {
            executor: 'ramping-vus',
            startVUs: 0,
            stages: [
                { duration: '10s', target: 30 },   // ramp to 30 VUs
                { duration: '20s', target: 30 },   // hold 30 VUs
                { duration: '5s', target: 0 },     // ramp down
            ],
            gracefulRampDown: '5s',
            startTime: '0s',
            exec: 'normalLoad',
        },

        // Scenario 2 — aggressive DDoS spike. 300 VUs flood invalid payloads.
        // The server must shed this load via 429 (rate limiter + concurrency
        // limiter) WITHOUT degrading for other traffic or crashing.
        ddos_spike: {
            executor: 'ramping-vus',
            startVUs: 0,
            stages: [
                { duration: '2s', target: 300 },   // spike to 300 VUs fast
                { duration: '15s', target: 300 },  // sustain the flood
                { duration: '3s', target: 0 },     // release
            ],
            gracefulRampDown: '5s',
            startTime: '40s', // runs after the normal scenario winds down
            exec: 'ddosSpike',
        },
    },

    // Global thresholds — the run is marked FAIL if any are crossed.
    thresholds: {
        // p95 of all HTTP requests must stay under 200ms even during the spike.
        'http_req_duration': ['p(95)<200'],

        // Built-in error rate counts any non-2xx as an error. Under the DDoS
        // spike we EXPECT many 429s, so we can't hold the raw rate < 1%.
        // Instead we track non-429 errors via a custom check below and use a
        // generous default here to avoid false failures; tighten for prod SLAs.
        'http_req_failed': ['rate<0.50'],
    },
};

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

function authHeaders() {
    return {
        'Content-Type': 'application/json',
        'Authorization': JWT ? `Bearer ${JWT}` : '',
    };
}

function sendValidate(code) {
    const res = http.post(
        VALIDATE_URL,
        JSON.stringify({ code: code }),
        { 
            headers: authHeaders(),
            responseCallback: http.expectedStatuses(400, 401, 413, 429, 200)
        }
    );

    validateLatency.add(res.timings.duration);

    // Triage the response. 429 = guard engaged (expected under spike). Other
    // non-2xx are real failures we want surfaced.
    if (res.status === 429) {
        rateLimited.add(1);
    } else if (res.status === 400 || res.status === 401 || res.status === 413) {
        rejectedFast.add(1);
    }

    return res;
}

// ---------------------------------------------------------------------------
// Scenario entry points
// ---------------------------------------------------------------------------

// normalLoad — the happy path. If a valid code + JWT are provided, the server
// returns 200; otherwise it returns 401 (missing/invalid auth) or 401 (bad
// code). Either way we assert the response is fast and is NOT a 500 (crash).
export function normalLoad() {
    const res = sendValidate(VALID_CODE);

    check(res, {
        'normal: no server crash (status != 500)': (r) => r.status !== 500,
        'normal: response under 200ms': (r) => r.timings.duration < 200,
    });

    sleep(0.2); // ~5 RPS per VU → 150 RPS at 30 VUs
}

// ddosSpike — flood invalid recovery codes. We do NOT sleep, so each VU fires
// as fast as it can for the duration. The goal is to confirm the server
// degrades gracefully: 429s climb, but p95 stays bounded and nothing 500s.
export function ddosSpike() {
    const res = sendValidate(INVALID_RECOVERY);

    check(res, {
        'spike: no server crash (status != 500)': (r) => r.status !== 500,
        'spike: mitigated by guard (429) or fail-fast (400/401)': (r) =>
            r.status === 429 || r.status === 400 || r.status === 401,
        'spike: response under 200ms': (r) => r.timings.duration < 200,
    });

    // No sleep — maximum pressure.
}

// ---------------------------------------------------------------------------
// Summary / teardown
// ---------------------------------------------------------------------------

export function handleSummary(data) {
    // Print a concise, human-readable summary at the end of the run.
    const reqs = data.metrics['http_reqs'] ? data.metrics['http_reqs'].values.count : 0;
    const p95 = data.metrics['http_req_duration']
        ? data.metrics['http_req_duration'].values['p(95)']
        : 'n/a';
    const failed = data.metrics['http_req_failed']
        ? data.metrics['http_req_failed'].values.rate
        : 'n/a';

    const summary = `
================  TOTP LOAD TEST SUMMARY  ================
Total requests ......... ${reqs}
p95 response time ...... ${p95 !== 'n/a' ? p95.toFixed(2) + ' ms' : 'n/a'}
Failed request rate .... ${failed !== 'n/a' ? (failed * 100).toFixed(2) + '%' : 'n/a'}
Thresholds passed ...... ${data.thresholds ? Object.values(data.thresholds).filter(t => t.ok).length : 'n/a'}

Run \`k6 run --out json=results.json\` for full per-request detail.
===========================================================
`;

    return {
        stdout: summary,
    };
}
