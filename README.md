# FinnApiGo — Auth Module (Core + MFA)

Authentication backend in Go (Gin, GORM/MySQL, JWT, bcrypt). Core auth (register, login, logout, refresh, forgot/reset password, change password, me, verify-email) plus OTP-based MFA.

> "MFA" here = OTP two-step verification. Not OAuth 2.0. Nothing is named "Auth2"/"OAuth".

---

## 1. Quick start

**Start MySQL:**
```bash
docker compose up -d db
```
MySQL 8 on `localhost:3306`, db `your db`, user `finnapigo` / `Your secret key`.

**Inspect in DBeaver:** New Connection → MySQL → host `localhost`, port `3306`, db `your db`, same user/pass. Tables (`users`, `refresh_tokens`, `otp_codes`, `audit_logs`) are created automatically on first run.

**Configure:**
```bash
cp .env.example .env
# set JWT_SECRET at minimum
```

**Run:**
```bash
go run ./cmd/server
# or: go build -o bin/finnapigo.exe ./cmd/server && ./bin/finnapigo.exe
```
Listens on `:8081` (or `SERVER_PORT`). Schema auto-migrates on boot.

**Test:**
```bash
go test ./...
```

---

## 2. Project structure

```
FinnApiGo/
├── cmd/server/main.go     # bootstrap: config → DB → migrate → wire → serve
├── internal/
│   ├── config/             # .env loader
│   ├── database/           # GORM/MySQL connection
│   ├── models/              # User, RefreshToken, OtpCode, AuditLog
│   ├── repositories/        # GORM queries only
│   ├── services/             # business logic, no Gin import
│   ├── handlers/              # parse request → call service → respond
│   ├── middleware/            # AuthMiddleware, RequireRole, RateLimiter
│   ├── routes/                 # route wiring
│   └── utils/                   # response helper, bcrypt, sha256, JWT
├── docker-compose.yml
├── Dockerfile
├── .env.example
└── go.mod
```

Layer rule: `handlers → services → repositories`. Handlers never call GORM directly. Services never import `gin` — plain Go in, plain Go out, which is what makes them unit-testable with mocks. Repositories hold no business logic.

---

## 3. Response format

Every endpoint, success or error, returns:
```json
{ "code": 200, "message": "Login successful", "data": { } }
```
All handlers go through `utils.Respond(c, code, message, data)` — never `c.JSON` directly. `data` is `null` when there's no payload.

---

## 4. Endpoints

All under `/api/v1/auth`. MFA nested under `/api/v1/auth/mfa`. `GET /healthz` for probes.

### Core auth

| Method | Endpoint | Auth | Purpose |
|--------|----------|------|---------|
| POST | `/register` | – | Create account; rejects duplicate email/username |
| POST | `/login` | – | Returns access + refresh token |
| POST | `/logout` | ✅ | Revokes the refresh token |
| POST | `/refresh-token` | – | Rotates refresh token, issues new access token |
| POST | `/forgot-password` | – | Emails reset token; same response whether email exists or not |
| POST | `/reset-password` | – | Sets new password using reset token |
| POST | `/change-password` | ✅ | Verifies old password, revokes all sessions |
| GET | `/me` | ✅ | Current user profile (no password) |
| POST | `/verify-email` | – | Marks email verified using verification token |

### MFA (OTP)

| Method | Endpoint | Auth | Purpose |
|--------|----------|------|---------|
| POST | `/mfa/send-otp` | ✅ | Generate + deliver 6-digit OTP |
| POST | `/mfa/verify-otp` | ✅ | Validate OTP (single-use, ≤5 attempts) |

---

## 5. Security design

- **Passwords**: bcrypt-hashed, never plaintext, `json:"-"` so never serialized.
- **Access token**: JWT, 15 min, `type: "access"`. Only access-type tokens work on protected endpoints.
- **Refresh token**: 32-byte opaque random string, only its SHA-256 hash stored. Rotated on every `/refresh-token` call — old token is revoked, so reuse is detectable.
- **Lockout**: 5 consecutive failed logins locks the account temporarily (default 15 min).
- **Forgot-password**: identical response whether or not the email exists (anti-enumeration).
- **OTP**: SHA-256 hash stored, 5-min expiry, single-use, max 5 verification attempts.
- **Token-type discrimination**: reset / verify-email / access JWTs carry a `type` claim — a reset token can't be replayed as an access token (unit-tested).
- **Rate limiting**: per-IP token bucket on `/login`, `/register`, `/forgot-password`, `/mfa/send-otp` (default 5 rps, burst 10) via `golang.org/x/time/rate`.
- **Audit logging**: login / failed login / logout / password change / reset / OTP sent+verified recorded with user id, email, IP, success flag.

---

## 6. Architectural decisions

1. **Password reset = JWT with `type:"reset"` claim**, not a separate `PasswordResetToken` table. Reuses existing JWT infra, free expiry via `exp`, stateless verification. Trade-off: revocation needs server-side tracking, acceptable for a 15-min window.

2. **`locked_until *time.Time` added to `User`** (beyond the minimum field list). A boolean `is_active` can't express a *temporary* lock — it's the permanent enable/disable flag. `locked_until` nullable timestamp; `nil` = not locked.

3. **OTP and refresh tokens store SHA-256 hashes**; passwords use bcrypt. SHA-256 fits short, high-entropy tokens; bcrypt's slow KDF is for low-entropy user-chosen passwords.

4. **Notifier is an interface** (`ConsoleNotifier` by default). OTP/reset emails log to stdout until SMTP is wired up — swap by implementing `services.Notifier`.

---

## 7. Configuration (`.env`)

See `.env.example`.

| Variable | Default | Notes |
|----------|---------|-------|
| `JWT_SECRET` | — | required, no default |
| `ACCESS_TOKEN_TTL` | `15m` | |
| `REFRESH_TOKEN_TTL` | `168h` (7d) | |
| `MAX_LOGIN_ATTEMPTS` | `5` | |
| `LOGIN_LOCKOUT_DURATION` | `15m` | |
| `OTP_TTL` / `OTP_MAX_ATTEMPTS` | `5m` / `5` | |
| `RATE_LIMIT_RPS` / `BURST` | `5` / `10` | per IP |

---

## 8. Testing with Bruno

Server must be running (`go run ./cmd/server`, keep the terminal open — OTP/reset codes print there since SMTP isn't wired up).

### Setup (once)

1. Install Bruno: https://www.usebruno.com/downloads
2. **Create Collection** → name `FinnApiGo`, pick a folder on disk (Bruno stores requests as `.bru` files — safe to commit to git).
3. Environment dropdown (top right) → **Configure** → **Create Environment**, name `Local`:

   | Variable | Value |
   |---|---|
   | `baseUrl` | `http://localhost:8080` |
   | `accessToken` | *(empty)* |
   | `refreshToken` | *(empty)* |

   Select `Local` as active.

Each request below: set method + URL, `Auth` tab for Bearer token, `Body` tab → `JSON` for payload.

### Requests

**Register** — `POST {{baseUrl}}/api/v1/auth/register`, no auth
```json
{ "username": "alice", "email": "alice@example.com", "password": "Password1", "fullName": "Alice Nguyen" }
```
Password: ≥8 chars, letter + number. Response `data.verifyEmailToken` — copy for later.

**Login** — `POST {{baseUrl}}/api/v1/auth/login`, no auth
```json
{ "email": "alice@example.com", "password": "Password1" }
```
`Script` tab → `Post Response`:
```javascript
bru.setEnvVar("accessToken", res.body.data.accessToken);
bru.setEnvVar("refreshToken", res.body.data.refreshToken);
```
Send again — tokens now save automatically on every login. Re-run whenever the access token expires (15 min).

**Me** — `GET {{baseUrl}}/api/v1/auth/me`, Auth: Bearer `{{accessToken}}`, no body.
Switch Auth to `No Auth` once to confirm it returns `401`.

**MFA — Send OTP** — `POST {{baseUrl}}/api/v1/auth/mfa/send-otp`, Bearer `{{accessToken}}`
```json
{ "purpose": "login" }
```
`purpose`: `login` | `verify-email` | `reset-password`. Code isn't in the response — check the server terminal for `[MAIL] ... CODE=xxxxxx`.

**MFA — Verify OTP** — `POST {{baseUrl}}/api/v1/auth/mfa/verify-otp`, Bearer `{{accessToken}}`
```json
{ "code": "482917", "purpose": "login" }
```
5 wrong attempts → `429`.

**Refresh Token** — `POST {{baseUrl}}/api/v1/auth/refresh-token`, no auth
```json
{ "refreshToken": "{{refreshToken}}" }
```
Optional `Post Response` script (same as Login) to keep tokens fresh. Re-sending with the old token afterward returns `401` — rotation confirmed.

**Verify Email** — `POST {{baseUrl}}/api/v1/auth/verify-email`, no auth
```json
{ "token": "<verifyEmailToken from Register>" }
```

**Change Password** — `POST {{baseUrl}}/api/v1/auth/change-password`, Bearer `{{accessToken}}`
```json
{ "oldPassword": "Password1", "newPassword": "NewPassword2" }
```
Revokes all sessions — log in again with the new password afterward.

**Forgot Password** — `POST {{baseUrl}}/api/v1/auth/forgot-password`, no auth
```json
{ "email": "alice@example.com" }
```
Response is identical for a real or fake email (anti-enumeration). Reset token appears in the server log as `RESET_TOKEN=...`.

**Reset Password** — `POST {{baseUrl}}/api/v1/auth/reset-password`, no auth
```json
{ "token": "<RESET_TOKEN from server log>", "newPassword": "ResetPass9" }
```

**Logout** — `POST {{baseUrl}}/api/v1/auth/logout`, Bearer `{{accessToken}}`
```json
{ "refreshToken": "{{refreshToken}}" }
```
Refresh token is now dead — `/refresh-token` with it returns `401`.

### Quick reference

| Method | URL | Auth | Body |
|---|---|---|---|
| POST | `/api/v1/auth/register` | – | username/email/password/fullName |
| POST | `/api/v1/auth/login` | – | email/password |
| GET | `/api/v1/auth/me` | Bearer | – |
| POST | `/api/v1/auth/mfa/send-otp` | Bearer | purpose |
| POST | `/api/v1/auth/mfa/verify-otp` | Bearer | code/purpose |
| POST | `/api/v1/auth/refresh-token` | – | refreshToken |
| POST | `/api/v1/auth/verify-email` | – | token |
| POST | `/api/v1/auth/change-password` | Bearer | oldPassword/newPassword |
| POST | `/api/v1/auth/forgot-password` | – | email |
| POST | `/api/v1/auth/reset-password` | – | token/newPassword |
| POST | `/api/v1/auth/logout` | Bearer | refreshToken |

### Troubleshooting

- `401` on a protected request → token expired (15 min) or missing — re-run Login.
- `400` → check body; password needs ≥8 chars, letter + number.
- `409` on register → email/username already taken.
- `429` → rate limit (5 req/s/IP) or OTP attempt limit — wait ~1 min.
- No OTP/reset code visible → check the terminal running `go run ./cmd/server` for `[MAIL]` lines.
- Connection refused → server isn't running.

---

## 9. Production hardening (next steps)

- Replace `ConsoleNotifier` with a real SMTP/SMS implementation.
- Replace the in-memory `RateLimiter` with a Redis-backed one for multi-instance deployments.
- Add structured logging (zap/zerolog) and tracing.
- Generate Swagger docs via `swaggo/swag` (handler annotations already in place — run `swag init`).
