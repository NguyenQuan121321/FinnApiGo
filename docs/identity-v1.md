# Finn identity contract v1 (F02)

Finn owns tenant identities, durable accounts/sessions, exact permissions and
revocation. This implementation precedes strict Jake J02 consumption. Jake
runtime is unchanged: the Python harness is an independent reference policy and
does not establish current Jake enforcement or real browser interoperability.

## Issuance and verification

Deployment uses `NewConfiguredJWTManager` with HS256 only, `JWT_KEY_ID`, and a
canonical base64 `JWT_SECRET` containing at least 32 random bytes. Startup rejects
short/default/low-diversity secrets, unsupported algorithms, missing IDs, equal
keys, incomplete rotation, wrong issuer and access lifetimes outside (0,900]s.
Generate keys with a cryptographic RNG outside source/logs; validation cannot
establish entropy provenance. The old constructors are retained for existing
unit fixtures only; server startup never selects legacy policy.

Every production access token has `contract_ver=1`, `iss=finnapigo`, `aud`, numeric
string `sub` matching integer `uid`, `type=access`, nonempty `tid`, `exp`, `iat`,
`nbf`, `jti`, `sid`, explicit `pwdver`/`auth_epoch` including zero, and `perms` array
including empty. TTL <=900s; verification skew <=30s. Missing/null/ill-typed claims,
duplicate JSON keys, conflicting aliases, unknown/missing kid, other algorithms,
excessive lifetime, future times and subject mismatches fail. No header-directed
key URL, algorithm fallback, permission wildcard expansion or platform tenant
authority. `default` is an ordinary tenant.

Protected claim and JOSE header names require exact canonical spelling before
typed decoding, for access and purpose tokens. Case aliases (including Unicode
case equivalents), either member order, same-value aliases and exact duplicate
members are rejected. Optional typed `role`/`email` and forbidden authority
aliases are protected too. Unknown benign extension names remain case-sensitive
and may coexist. The Go/Python corpus exercises both rejection and extension
compatibility; it does not certify Jake runtime enforcement.

The shared AuthService path covers password, OAuth, passkey, MFA completion and
refresh. It reads exact tenant grants, creates/reuses a durable session, signs and
checks authoritative state before returning credentials. Only an exact
`chat:read` or `chat:write` grant selects the fixed audience set
`[finnapigo-api,jakeai-service]`; all others receive `[finnapigo-api]`. This is the
existing conversation capability mapping, not a caller-requestable audience or
scope. Every Jake operation still needs its own exact permission under J02.
Reset/email/MFA/sudo tokens use distinct purpose audiences
`finnapigo-purpose:<type>` and cannot pass access validation. Refresh is opaque.
Sudo binds the verified tenant. There is no service/tool user-token or OBO API.

## Durable authority and service API

`POST /api/v1/identity/introspect` accepts only
`{"token":"<v1 user access>","tenant_id":"<expected tenant>"}` (16KiB cap).
Service identity is fixed to `jakeai-service`, authenticated by
`Authorization: Bearer <IDENTITY_STATE_SECRET>` and
`X-Service-Key-ID: <IDENTITY_STATE_KEY_ID>`. The credential is independently
generated, base64 >=32 random bytes, different from signing/application keys.
It can check only access tokens granting Jake's named audience. No caller-supplied
roles/permissions/headers select authority. Network policy should keep this
service path private; browser clients never receive this credential.

TLS is required on the actual request, including tests that exercise real TLS.
`X-Forwarded-Proto` does not satisfy it. `SERVER_TLS_CERT_FILE` and
`SERVER_TLS_KEY_FILE` enable the server's HTTPS listener (minimum TLS 1.2); a
private ingress must use HTTPS upstream. Provisioning certificates/routes is H06
and is not performed by this PR. Plain HTTP introspection returns 503. Release
mode additionally requires shared Redis. MySQL durable authority does not depend
on Redis retention: Redis revocations are additional denials, and Redis faults
remain errors rather than absence.

Authority reads a repeatable-read transaction: tenant active, tenant-owned active
non-suspended user, exact credential/authorization versions, tenant/owner session
not expired/revoked, durable tenant/JTI denial and exact current permission set.
No positive state cache in Finn. A deleted/unknown account/session is inactive;
DB/query/Redis errors are unavailable. Removing a grant invalidates a token even
if a writer failed to increment the epoch. Role assignment increments the user
epoch in the same transaction. Clients reauthenticate after any permission-set
change, including additional grants. JWT role alone grants nothing.

Responses are raw minimized JSON, distinct from user API envelopes:

- 200: `contract_ver`, `active:true`, `tid`, `sub`, `sid`, `jti`, `pwdver`,
  `auth_epoch`, UTC Unix `checked_at`, `max_cache_seconds:15`; no email or content.
- 401: invalid service credential or invalid/inactive user credential. Inactive
  user response contains only `active:false`; no account existence details.
- 403: authenticated JWT tenant differs from expected tenant; Finn permission
  middleware likewise denies insufficient exact user grants with 403.
- 400: invalid request; 429: shared fixed-window service quota 120 requests/second
  with `Retry-After:1`; 503: TLS/dependency/unknown protected state unavailable.

Current/previous service credentials require explicit IDs and
`IDENTITY_STATE_PREVIOUS_UNTIL` UTC deadline; previous acceptance is capped at one
930s configured overlap and never refreshed implicitly on process restart.
Quota is keyed to service identity across keys, so rotation cannot double it.
Compromise requires immediate removal, key rotation and containment by owners.

J02 consumers must bind cached positives to the whole JWT/state context, cache
<=15s, and stop protected delivery on unavailable/stale state. Long work rechecks
at least every 15s and before effects. Target administrative revocation <=30s
including caches and in-flight delivery remains a staging/F04/release G1 gate;
no local issuance test proves that end-to-end SLA.

## Schema and lifecycle seam

Migration 0005 adds `users.auth_epoch`, `users.admin_suspended`, durable
`access_revocations(tenant_id,jti,expires_at)` and a tenant/user/session index.
Existing rows start epoch zero and unsuspended; no grant/session backfill is
invented. Existing legacy sessions do not create legacy acceptance. Logout
persists the caller's JTI before acknowledgment. A durable write failure is 503.
`Authority.Suspend` atomically sets suspension, increments credential/authorization
versions and revokes tenant-owned sessions. It is an internal seam, not a newly
exposed admin operation or proof of complete refresh-family/factor containment.
F04 owns complete refresh/replay/suspension lifecycle and truthful multi-step
containment. F03 owns transactional critical audit; neither is claimed complete.
Temporary brute-force `locked_until` remains separate from administrative state.

User mutation ownership prevents stale snapshots from restoring security state:

| Mutation | Owned fields / operation |
|---|---|
| `UserRepository.Update` | Profile `username`, `full_name` only, including empty values |
| `UpdateEmail` / `ConfirmChangeEmail` | `email`, `is_email_verified` only |
| `Deactivate` / `DeactivateAccount` | Forces `is_active=false` |
| `Erase` / `EraseAccount` | Anonymized email/username, empty password/name, inactive/unverified |
| Credential, lockout, suspension and grants | Existing dedicated password transaction/CAS, SQL version increments, lockout APIs, `Authority.Suspend`, transactional RBAC epoch increment |

All three former production broad-update callers use the dedicated operations.
No ordinary profile/email snapshot writes password, activity, suspension,
versions or lockout. Deactivation/erasure preserve intervening suspension and
versions. Tenant predicates, missing-row errors and dependency failures remain
enforced; there is no upsert. Existing multi-step email/deactivation/erasure
containment and factor/audit error handling remain F04/F03 work. These repairs
do not certify the complete lifecycle. No schema change is needed.
Expired revocation records are safe to retain; no unapproved retention/purge job
is added. Future cleanup must preserve security through expiry plus skew.

## Rotation, rollout and rollback

1. On authorized synthetic staging, apply additive migration 0005; record actual
   schema version, indexes, row counts, revision pair and TLS/storage inventory.
2. Provision independent current signing/service keys and IDs. For signing
   rotation, stop all old-key issuers, record true final old issuance UTC, then
   set old key/ID and `JWT_PREVIOUS_LAST_ISSUED_AT`. Current-only signing begins
   immediately; verification retires at final old issuance+930s on every replica,
   including restarted replicas. Long-lived old purpose tokens also retire;
   restart email/reset/MFA/sudo flows. Remove old material after retirement.
3. Deploy Finn issuer/state first, verify v1 browser/API issuance and state
   negatives, then deploy J02 consumer policy on staging. The existing memory
   bearer token-pair response shape is retained; no cookie/persistent-storage
   migration is introduced. Finn-only users cannot use Jake. Old tokens require
   reauthentication; new grant changes also require it.
4. This implementation has no legacy runtime acceptance. Any staging-only
   consumer bridge requires an owner-set explicit UTC cutoff, at most a single
   930s drain after final legacy issuance, and removal before pilot. No actual
   rollout date or indefinite production fallback is authorized here.
5. Demonstrate actual rotation, old-key retirement, issuer-before-consumer and
   browser reauthentication on the authorized topology. Missing H05/H06/staging
   makes F02 BLOCKED even if every CI gate passes. Disposable service containers
   are adapter/migration evidence, never staging or live rotation evidence.

Rollback preserves strict identity enforcement and additive authoritative state,
or disables protected access until repaired. It must not restore permissive Jake
verification or old Finn acceptance. Database down is a disposable rehearsal,
not a production rollback: dropping epochs/suspension/revocations while any token
remains usable can resurrect authority. Revoke/drain all credentials, preserve
state/backup and obtain operational approval before a destructive schema rollback.
Restoring old security-state snapshots also needs F04 reconciliation.

Tests: `go test ./...`; Linux CI `go test ./... -race -cover`; independent Python
reference automatically consumes Go synthetic fixtures in `TestV1CrossLanguageContract`.
`go test -tags=integration ./... -race -count=1` requires explicit loopback
disposable `F02_MYSQL_ADMIN_DSN`, `F02_MYSQL_ALLOW_CREATE_DROP=1`,
`TEST_REDIS_URL` plus existing repository integration inputs. F02 creates/drops a
unique schema, applies real migrations, and uses actual MySQL/Redis adapters for
tenant/session/permission/epoch/JTI/outage/admission cases. No production data.
`TestF02RealUserMutations` additionally runs the deterministic stale-snapshot
service/repository matrix against a separate migrated schema and Redis DB 14:
suspension, grant/epoch, credential, activity and lockout interleavings; actual
password login after the mutation; old-session rejection; zero values;
default/foreign tenant negatives; idempotent/missing rows and closed DB errors.
