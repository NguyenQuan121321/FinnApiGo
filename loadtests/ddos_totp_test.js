import http from 'k6/http';
import { check } from 'k6';

export const options = {
    scenarios: {
        ddos_spam: {
            executor: 'constant-arrival-rate',
            rate: 100,
            timeUnit: '1s',
            duration: '15s',
            preAllocatedVUs: 50,
            maxVUs: 200,
        },
    },
};

export default function () {
    const url = 'http://localhost:8081/api/v1/auth/mfa/totp/validate';
    
    const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOjIsInJvbGUiOiJ1c2VyIiwiZW1haWwiOiJ0ZXN0MUBleGFtcGxlLmNvbSIsInR5cGUiOiJhY2Nlc3MiLCJpc3MiOiJmaW5uYXBpZ28iLCJzdWIiOiIyIiwiZXhwIjoxNzg2MTkyMTg5LCJuYmYiOjE3ODYxOTEyODksImlhdCI6MTc4NjE5MTI4OX0.F_mdGYWq3WYhxdfAy50iMwZYlHDERjE7YF7jyLy4N08';

    const payload = JSON.stringify({
        code: '123456'
    });

    const params = {
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        },
    };

    const res = http.post(url, payload, params);

    check(res, {
        'Security: Mitigated by Rate Limiter (HTTP 429)': (r) => r.status === 429,
        'Logic: Rejected by Fail-Fast validation (HTTP 400/401/403)': (r) => r.status === 400 || r.status === 401 || r.status === 403,
        'Vulnerability: Server crashed / Resource exhaustion (HTTP 500)': (r) => r.status === 500,
    });
}