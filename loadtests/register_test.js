import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  vus: 50,
  duration: '10s',
};

export default function () {
  const url = 'http://localhost:8081/api/v1/auth/register';

  const randomSuffix = Math.random().toString(36).substring(2, 8) + Date.now();
  
  const payload = JSON.stringify({
    username: `k6_${randomSuffix}`,
    email: `k6_${randomSuffix}@example.com`,
    password: "Password1",
    fullName: "K6 Load Test"
  });

  const params = {
    headers: {
      'Content-Type': 'application/json',
      'X-Forwarded-For': `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`
    },
  };

  const res = http.post(url, payload, params);

  check(res, {
    'is status 201': (r) => r.status === 201,
  });

  sleep(0.01); 
}