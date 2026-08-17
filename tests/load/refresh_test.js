// k6 load test for the REFRESH-TOKEN ROTATION path (P4).
//
// Every iteration presents the token received from the previous rotation —
// this is the real client behavior and exercises the security-critical
// compare-and-set (C1): each VU's chain is strictly sequential, so exactly
// one rotation per token; a failure here means a token was rejected
// mid-chain (reuse detection firing falsely — a bug).
//
// Scenario "rotate": 40 VUs, each maintaining its own token chain for 30s.
// Per VU: setup registers a user, default() logs in once, then rotates the
// refresh token in a tight loop (sleep 0.1s).
//
// Thresholds: p95 < 300ms; error rate < 1% (a 401 mid-chain counts as an
// error — rotation must never falsely detect reuse on a well-behaved chain).
//
// Usage:
//   k6 run tests/load/refresh_test.js
//   REFRESH_BASE_URL=http://localhost:8081 k6 run tests/load/refresh_test.js

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend } from 'k6/metrics';

const BASE_URL = __ENV.REFRESH_BASE_URL || 'http://localhost:8081';
const LOGIN_URL = `${BASE_URL}/api/v1/auth/login`;
const REGISTER_URL = `${BASE_URL}/api/v1/auth/register`;
const REFRESH_URL = `${BASE_URL}/api/v1/auth/refresh-token`;

const rotateLatency = new Trend('refresh_rotate_latency_ms', true);

export const options = {
  scenarios: {
    rotate: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '5s', target: 40 },
        { duration: '30s', target: 40 },
        { duration: '5s', target: 0 },
      ],
      gracefulRampDown: '5s',
    },
  },
  thresholds: {
    http_req_duration: ['p(95)<300'],
    http_req_failed: ['rate<0.01'],
  },
};

export function setup() {
  const creds = [];
  for (let i = 0; i < 45; i++) {
    const suffix = `${i}_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
    const email = `k6_refresh_${suffix}@example.com`;
    http.post(REGISTER_URL, JSON.stringify({
      username: `k6refresh_${suffix}`,
      email: email,
      password: 'Password1',
      fullName: 'K6 Refresh Test',
    }), { headers: { 'Content-Type': 'application/json' } });
    creds.push({ email: email, password: 'Password1' });
  }
  return { creds };
}

// Per-VU state: the current refresh token in this VU's rotation chain.
const chainToken = {};

export default function (data) {
  const creds = data.creds[__VU % data.creds.length];
  if (!chainToken[__VU]) {
    const res = http.post(LOGIN_URL, JSON.stringify(creds), {
      headers: { 'Content-Type': 'application/json' },
    });
    const body = res.json();
    chainToken[__VU] = body && body.data && body.data.refreshToken;
    if (!chainToken[__VU]) {
      check(res, { 'login ok': () => false });
      return;
    }
  }
  const res = http.post(REFRESH_URL, JSON.stringify({ refreshToken: chainToken[__VU] }), {
    headers: { 'Content-Type': 'application/json' },
  });
  rotateLatency.add(res.timings.duration);
  const ok = check(res, { 'rotate 200': (r) => r.status === 200 });
  const body = res.json();
  const next = body && body.data && body.data.refreshToken;
  if (ok && next) {
    chainToken[__VU] = next; // advance the chain
  } else {
    delete chainToken[__VU]; // force re-login next iteration
  }
  sleep(0.1);
};
