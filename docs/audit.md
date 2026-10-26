# Durable security audit (F03)

Implementation delivery is separate from release acceptance. Production retention,
legal holds, backup expiry, trusted archive access, recovery objectives and actual
staging topology/owners remain unapproved inputs. No production purge is enabled.

## Admission and production wiring

`cmd/server` validates configured audit keys before opening stores, checks required
historical key IDs, and passes one `AsyncAuditWriter` to Auth, Admin, TOTP, OAuth
and Passkey services. `audit_operations.go` wraps their security operations in a
real repository transaction. All participating repositories and identity-state
checks use `database.FromContext`, including ownership subqueries, session/token
writes and nested credential/recovery transactions.

An event is captured and inserted in `audit_outboxes` before the SQL transaction
commits and before the public operation returns success. The per-tenant
`audit_heads` row is locked to assign sequence and previous hash. Critical
admission failures latch into the operation and roll back SQL even through the
legacy void `Record` interface. HTTP handlers translate admission failure to 503;
token-returning methods return zero values after rollback. `Admit` is the explicit
error-returning interface for internal callers. Direct synchronous recording,
batch insertion and the production async writer all use the same admission and
verification rules. The old best-effort adapter remains only for optional test
doubles without durable capability; production wiring uses the concrete durable
repository.

Expected authentication denials commit lockout/containment evidence and return the
original denial. Unexpected operation errors roll back SQL. The service wrappers
cover registration, password login, MFA completion/pending issuance, refresh,
logout/all, credential/email/account mutations, session revocation, admin actions,
TOTP staging/activation/validation/recovery/disable, OAuth callback/unlink and
passkey completion/revocation. Existing F04/F05 lifecycle obligations remain.

**Atomicity stops at MySQL.** Redis rate/replay/challenge consumption, cache
invalidation, email and OAuth/network effects cannot be rolled back by SQL.
Failed operations can consume a one-time challenge or emit a notification while
their SQL changes roll back. They report failure and require a fresh challenge;
clients must not interpret failure as proof that no external effect occurred.
This does not claim full F04 revocation/lifecycle atomicity.

## Trusted context and privacy

The router generates a server UUID request ID; incoming `X-Request-ID` is not an
authority or a signed correlation value. Authentication middleware binds the
verified actor. Password/refresh/factor services bind actors only after credential
validation. Capture deep-copies subject IDs and fixes the tenant, UUID event ID,
request ID and UTC millisecond timestamp before delivery or request cancellation.

`actorKind` distinguishes authenticated, unauthenticated and explicit internal
system events. An unauthenticated tenant value is the attempted login partition,
not verified membership; tenant-selection headers never create a verified actor.
`default` is an ordinary isolated tenant. `UserID` is the event subject, not proof
of the actor; admin actions sign their action and target separately from the actor.
Query/export/verification/requeue methods reject foreign tenant arguments.

V1 evidence contains pseudonymous numeric actor/subject IDs, bounded event/action,
success, tenant, request/event UUIDs and time. Email, IP and free text (including
password/token/provider/MFA canaries) are omitted from new evidence and outbox
payloads. Numeric IDs are still potentially personal data. Erasure clears legacy
ancillary PII; it does not rewrite signed actor/subject identifiers or fabricate
historical identity. Whether those identifiers may/must be retained is a mandatory
production policy decision, not a claim of completed legal erasure.

## Delivery, bounds and recovery

RAM contains one coalesced wakeup, never the only event copy. Polling every 500ms
recovers missed wakeups and process death. `AUDIT_FLUSH_BATCH` bounds work per
dispatch (maximum 1000). `AUDIT_MAX_PENDING` defaults to an engineering bound of
10000 outstanding events per tenant, including dead letters. Saturation rejects
admission; this bound is not approved production capacity. Delivered receipts and
hot history require the separately approved retention policy.

MySQL `READ COMMITTED` claims use `FOR UPDATE SKIP LOCKED`, a 30-second lease and a
fresh fencing UUID. Delivery locks the claim, validates the canonical event,
inserts evidence and ACKs/decrements backlog in one transaction. Event ID and
tenant/sequence uniqueness reject forks and duplicates. Duplicate delivery accepts
only identical canonical content/MAC. Stale workers cannot ACK a reclaimed lease.
Per-tenant sequence order, rather than replica insertion order, defines history.

Delivery failure schedules exponential backoff from 2 seconds to 256 seconds.
Eight failed attempts, or exhausted crash/reclaim attempts, leave a durable dead
letter. Repair the cause and use tenant-scoped internal `RequeueDead`; corrupt
payloads require an authentic backup/archive copy, never a newly invented event.
No public operator recovery endpoint is exposed. SQL transaction/deadlock failures
are explicit failures; business operations are not blindly replayed across Redis
or network effects. Claims use `READ COMMITTED` to avoid observed gap-lock
deadlocks between delivery and admission.

Shutdown waits at most 10 seconds and attempts one bounded final dispatch; pending
events remain durable for another replica/restart. Close is idempotent. Requests
finishing after Close still admit durably. Operators must monitor admission
failures, delivery failures/retries, outbox pending/dead/oldest-age gauges and
coalesced wakeups on the existing protected metrics endpoint. Counters contain no
tenant, actor or secret labels. The admission-insert counter counts successful
INSERT attempts, including ones subsequently rolled back. Backlog gauges are
last successful poll snapshots and can be stale during a DB outage.

## Keys and canonical integrity

Release mode requires `AUDIT_KEY_ID`, `AUDIT_SIGNING_KEYS` (JSON ID to base64
material), and an independent checkpoint key: `AUDIT_CHECKPOINT_KEY` with
`AUDIT_CHECKPOINT_KEY_ID`, or `AUDIT_CHECKPOINT_KEYS` (JSON retained key map).
Use independently generated cryptographically random material, at least 32 decoded
bytes per key. Missing, short, repeated/public-default and shared signing/checkpoint
material fail startup. Authentication/encryption key reuse is rejected. Key IDs
select only configured material, never URLs or algorithms. Development without
configuration uses ephemeral random keys and cannot promise verification after
restart. Use retained configured keys for any persistent environment.

Rotate by deploying the union of old verification keys and the new key to all
replicas, then select the new current ID. Only the current ID signs. Keep retired
keys externally as verification-only material for all retained hot history,
outbox payloads, independent checkpoints, archives and backups. Startup rejects
missing signing IDs required by hot/pending history; archive restore also verifies
required keys. Removing a key from the active ring is allowed only after affected
hot/pending records are archived under policy and external restore verification
capability is retained. Do not apply JWT's short retirement window to audit keys.
Checkpoint keys rotate independently with their retained ID map. Operators own
external key access control, inventory, backup and compromise response.

Canonical v1 is an ordered JSON array with domain `finn.audit.event.v1`, version,
event UUID, tenant, sequence, previous hash, key ID, UTC Unix milliseconds, actor
kind/ID, subject ID (0 for absent), request UUID, event, action and success. It uses
HMAC-SHA256. Golden bytes and a fixed synthetic MAC freeze interoperability.
Checkpoints use the separate `finn.audit.checkpoint.v1` domain and key ring.

HMAC does not protect against an attacker holding the signing key. A chain stored
only in the mutable DB cannot prove tail completeness or events never admitted.
`VerifyChain` checks local continuity and explicitly rejects any legacy v0 rows;
it is not external truncation proof. `VerifyAgainst` requires independently
retained base/end checkpoints and detects tamper, reorder, deletion and truncation
within that exact interval. A stale checkpoint cannot protect a newer tail.
External checkpoint/archive storage and custody are prerequisites for production
integrity claims and remain staging/policy inputs.

## Archive, retention, restore and migrations

`Archive` requires an injected enabled policy with recorded approval reference,
cutoff, row bound (1–1000) and no legal hold. It exports a contiguous signed prefix
and base/end checkpoints. The caller must durably retain and verify the artifact
and its reference independently before `PurgeArchive` is authorized. The approval
string is metadata in an internal API, not an approval/authentication mechanism.
No duration or role name supplies approval. Tests use clearly labeled synthetic
policies only. `AUDIT_RETENTION_DAYS` cannot authorize deletion and scheduled audit
purge is disabled.

Purge rechecks the actual prefix in a transaction and records its boundary. Heads
and event receipts survive. Verification of the remaining hot suffix starts from
that boundary; full historical verification also needs the external archive.
Restore verifies every row/reference/key, restores only the exact current archived
prefix, preserves newer history/admitted head, rejects duplicates or conflicts and
never recreates excluded PII. Failed restore rolls back rows and boundary. Backup
restore must reconcile external checkpoints, keys and current erasure/containment
state before serving; a DB snapshot alone is insufficient recovery evidence.

Apply migration 0006 before the new binary, with old writers stopped/drained.
It adds nullable identity/sequence columns, uniqueness constraints and fresh
outbox/head/boundary tables. It does not rewrite or resign existing rows: they
remain version 0/unverifiable, even if an old hash is present. Rehearse index DDL
duration/locks on staging-sized data before rollout. Down migration is destructive
to outbox and integrity metadata; use it only on disposable data or after a
separately approved stop/archive/backup procedure. Application rollback must
preserve durable evidence and security fixes rather than restoring RAM-only writes.

## Verification and acceptance boundary

`go test -tags=integration ./... -race -count=1 -v` runs on Linux with isolated
MySQL/Redis. F03 requires explicit loopback `F03_MYSQL_ADMIN_DSN` without a selected
DB and `F03_MYSQL_ALLOW_CREATE_DROP=1`; it creates/deletes only unique test schemas.
Existing F01/F02 fixtures keep their own explicit inputs and coverage/security
gates. Tests include the actual release server process, wired service operations,
trigger-induced admission/restore failure, independent pools, process termination,
leases/duplicate delivery, bounded poison recovery, cancellation, capacity,
canonical/key rotation, trusted checkpoints and migrations/legacy fixtures.

Passing these tests or PR CI does not approve production durations, legal holds,
backup expiry, external archive/key custody, RPO/RTO, staging access/topology or
release owners. F03 acceptance remains pending independent post-merge review and
the mandatory policy/staging evidence. The PR stays open for human merge.
