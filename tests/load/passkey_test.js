// k6 load test for the PASSKEY authentication ceremony endpoints (W8, 9E).
//
// WebAuthn assertions are cryptographically bound to the challenge, so a load
// client cannot fabricate them the way it fabricates a password. This scenario
// therefore measures the SERVER-SIDE ceremony cost honestly in two tiers:
//
//   1. "challenge": authenticated users hitting /passkey/authenticate/challenge
//      at load — the DB reads + challenge staging + WebAuthn option building,
//      which IS fully exercisable server-side.
//   2. "verify-invalid": POSTs to /passkey/authenticate/verify with structurally
//      valid-but-garbage assertion bodies — measures the parse+reject path
//      (challenge lookup miss, CBOR/JSON parse failure). These all fail with
//      400/401; latency still bounds the reject path a bot flood would hit.
//
// The signed-assertion success path cannot be load-tested from k6 without a
// WebAuthn browser authenticator; treat "challenge" latency as the lower bound
// for the verify success path (the success path adds signature verification,
// ~microseconds for ES256, plus one indexed UPDATE).
//
// Usage:
//   k6 run tests/load/passkey_test.js
//   PASSKEY_BASE_URL=http://localhost:8080 PASSKEY_TOKEN=<accessToken> k6 run tests/load/passkey_test.js

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter, Trend } from 'k6/metrics';

const BASE_URL = __ENV.PASSKEY_BASE_URL || 'http://localhost:8080';
const TOKEN = __ENV.PASSKEY_TOKEN || '';
const CHALLENGE_URL = `${BASE_URL}/api/v1/auth/mfa/passkey/authenticate/challenge`;
const VERIFY_URL = `${BASE_URL}/api/v1/auth/mfa/passkey/authenticate/verify`;

const challengeLatency = new Trend('passkey_challenge_latency_ms', true);
const verifyLatency = new Trend('passkey_verify_reject_latency_ms', true);
const rejected = new Counter('passkey_verify_rejected');

export const options = {
  scenarios: {
    challenge: {
      executor: 'constant-vus',
      vus: 20,
      duration: '20s',
      exec: 'challengeScenario',
      startTime: '0s',
    },
    'verify-invalid': {
      executor: 'constant-vus',
      vus: 20,
      duration: '20s',
      exec: 'verifyScenario',
      startTime: '25s',
    },
  },
  thresholds: {
    passkey_challenge_latency_ms: ['p(95)<300'],
    passkey_verify_reject_latency_ms: ['p(95)<100'],
    'http_req_failed{scenario:challenge}': ['rate<0.01'],
    // 429s are expected and NOT failures: they are counted separately below.
  },
};

const authHeaders = () => ({
  headers: {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${TOKEN}`,
  },
});

export function challengeScenario() {
  const res = http.post(CHALLENGE_URL, '{}', authHeaders());
  check(res, {
    'challenge accepted (200 or rate-limited)': (r) => r.status === 200 || r.status === 429,
  });
  challengeLatency.add(res.timings.duration);
  if (res.status === 429) {
    rejected.add(1);
  }
  sleep(1);
}

export function verifyScenario() {
  const garbage = JSON.stringify({
    id: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    rawId: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    type: 'public-key',
    response: {
      clientDataJSON: 'e30',
      authenticatorData: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      signature: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    },
  });
  const res = http.post(VERIFY_URL, garbage, authHeaders());
  check(res, {
    'verify rejected (4xx) or rate-limited': (r) => r.status >= 400 && r.status < 500,
  });
  verifyLatency.add(res.timings.duration);
  if (res.status === 429) {
    rejected.add(1);
  }
  sleep(1);
}
