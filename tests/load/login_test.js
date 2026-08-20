// k6 load test for the LOGIN path (P4).
//
// Scenario "steady": 50 VUs logging in continuously for 20s against
// pre-registered accounts (each VU registers its user in setup(), then
// authenticates over and over — the classic credential-check hot path:
// bcrypt + velocity counters + session row insert).
// Scenario "wrongpass": 30 VUs hammering WRONG passwords for 15s — exercises
// the failed-attempt counter (atomic SQL bump), per-account velocity window,
// and dummy-hash timing equalization.
//
// Thresholds: p95 < 500ms (bcrypt dominates; honest bound), HTTP error rate
// (non-429) < 1%. 429s under "wrongpass" are expected and counted separately.
//
// Usage:
//   k6 run tests/load/login_test.js
//   LOGIN_BASE_URL=http://localhost:8081 k6 run --scenario steady tests/load/login_test.js

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter, Trend } from 'k6/metrics';

const BASE_URL = __ENV.LOGIN_BASE_URL || 'http://localhost:8081';
const LOGIN_URL = `${BASE_URL}/api/v1/auth/login`;
const REGISTER_URL = `${BASE_URL}/api/v1/auth/register`;

const loginLatency = new Trend('login_latency_ms', true);
const rateLimited = new Counter('login_rate_limited');

export const options = {
  scenarios: {
    steady: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '5s', target: 50 },
        { duration: '20s', target: 50 },
        { duration: '5s', target: 0 },
      ],
      gracefulRampDown: '5s',
      exec: 'steady',
    },
    wrongpass: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '5s', target: 30 },
        { duration: '15s', target: 30 },
        { duration: '5s', target: 0 },
      ],
      gracefulRampDown: '5s',
      exec: 'wrongpass',
      startTime: '40s', // run after "steady" so the two don't blur
    },
  },
  thresholds: {
    'http_req_duration{scenario:steady}': ['p(95)<500'],
    'http_req_failed{scenario:steady}': ['rate<0.01'],
  },
};

const USERS = 60; // pre-registered pool shared by VUs

export function setup() {
  const creds = [];
  for (let i = 0; i < USERS; i++) {
    const suffix = `${i}_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
    const email = `k6_login_${suffix}@example.com`;
    http.post(REGISTER_URL, JSON.stringify({
      username: `k6login_${suffix}`,
      email: email,
      password: 'Password1',
      fullName: 'K6 Login Test',
    }), { headers: { 'Content-Type': 'application/json' } });
    creds.push({ email: email, password: 'Password1' });
  }
  return { creds };
}

export function steady(data) {
  const creds = data.creds[__VU % data.creds.length];
  const res = http.post(LOGIN_URL, JSON.stringify(creds), {
    headers: { 'Content-Type': 'application/json' },
  });
  loginLatency.add(res.timings.duration);
  check(res, { 'login 200': (r) => r.status === 200 });
  sleep(0.5);
}

export function wrongpass(data) {
  const creds = data.creds[__VU % data.creds.length];
  const res = http.post(LOGIN_URL, JSON.stringify({
    email: creds.email,
    password: 'WrongPassword1',
  }), { headers: { 'Content-Type': 'application/json' } });
  if (res.status === 429) {
    rateLimited.add(1); // velocity window engaged — expected under abuse
  }
  check(res, { 'wrongpass 401': (r) => r.status === 401 || r.status === 429 });
  sleep(0.2);
}
