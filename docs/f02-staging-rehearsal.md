# F02 staging acceptance rehearsal

The separately authorized [ephemeral Actions rehearsal](f02-actions-rehearsal.md)
uses actual Finn/TLS/stores and a deployed strict diagnostic consumer. Its scope,
automatic operations and remaining manual/browser/Jake acceptance limitations
are explicit there; it does not certify Render or replace independent acceptance.

This runbook prepares the remaining original F02 acceptance. It changes no
runtime policy and authorizes no operational action. F02 remains BLOCKED until
the actual staging matrix, accountable owners and consumer boundary are accepted.
Use [identity-v1.md](identity-v1.md) for the unchanged contract. Full refresh-family,
suspension lifecycle and end-to-end revocation SLA acceptance remain F04/G1 work.

## Preconditions and one input checklist

Provide non-secret references only. Credentials and tokens stay in a secret
manager, outside Git, chat, screenshots and evidence files.

1. Named identity, security and platform/on-call owners; security disposition of
   the shared-HMAC risk (a verifier holding HS256 material can also sign).
2. Exact isolated Finn and consumer origins, service/resource IDs, completed
   deployment IDs and SHAs, every replica and direct replica route, TLS certificate
   trust and private service path. Prove HTTPS reaches Finn itself: edge TLS with
   HTTP upstream or `X-Forwarded-Proto` alone fails introspection with 503.
3. Dedicated synthetic MySQL/Redis resource identities, isolation/backup and fault
   controls, current schema version, tenant/account/grant fixture references,
   browser/device/operator access and the application origin. No production copies.
4. Secret-manager **references** for independent current/previous signing and
   service material, key IDs, synthetic account credentials and bearer inputs.
   Confirm at least 32 random bytes, canonical Base64, distinct key purposes, and
   owners' provisioning/custody. Do not paste any value into the manifest.
5. Consumer scope decision: unchanged Jake main is not a strict v1 consumer. Its
   verifier disables audience checking, accepts omitted fields and algorithm
   fallback, and its Redis denylist error path fails open. It does not call Finn
   introspection or enforce this contract's retirement deadline. A dedicated probe
   or Python reference can demonstrate only that explicitly named boundary.
   Owners must resolve the original staging-consumer criterion/dependency gap;
   do not implement J02 here or silently substitute the probe for Jake. Until
   resolved, F02 remains BLOCKED and J02/F04 cannot start under the original index.
6. Target-specific approval for issuer/consumer deploys, secret-reference changes,
   controlled replica restart, dependency faults, synthetic session writes,
   retirement/removal, rollback and cleanup. Supply the exact reviewed commands,
   deployment/configuration references, expected impact and stop conditions.
   Record actual final old issuance UTC and service overlap deadline during the
   run. No invented dates or indefinite legacy bridge; an approved staging-only
   bridge must end by final legacy issuance +930 seconds and before pilot.

Copy `tests/identitycontract/staging.example.json` into a private evidence
directory; fill all fields from verified inventory. The empty template deliberately
returns BLOCKED. Reference IDs attest evidence to be independently inspected;
the probe cannot prove inventory, isolation, authorization or revision from labels.
Every listed route must reach its named replica, without load-balancer ambiguity.
List the exact consumer protected GET route and its required synthetic grant.
Issuer and consumer origins are validated before secret lookup or network use,
including direct runner calls. Supported DNS/IDNA hostnames are canonicalized to
lowercase ASCII, with one terminal dot and default port443 removed. The known
production hostname is excluded after canonicalization, including case, IDNA and
terminal-dot spellings. Unsupported hostname/port forms, whitespace/control
characters, backslashes and empty userinfo/query/fragment spellings are rejected.
The manifest hash still binds the exact reviewed input bytes; canonicalization
does not attest that any other HTTPS hostname is isolated staging.

## Executable probe

Requires standard Python, without `-O`; no packages to install. Offline plan mode
does not read secrets, open sockets, login, deploy, rotate, create resources or
alter settings:

```powershell
python -B tests/identitycontract/rehearsal.py <private-manifest.json> --phase overlap
go test ./tests/identitycontract -count=1 -v
```

Execution is a **separate authorized operation**. Do not run the following until
the invoking owner has approved the concrete manifest, commands and rollback.
The hash guard ties execution to reviewed bytes; it does not grant permission.

```powershell
$reviewedPlanHash = (Get-FileHash -Algorithm SHA256 -LiteralPath <private-manifest.json>).Hash.ToLowerInvariant()
python -B tests/identitycontract/rehearsal.py <private-manifest.json> --phase overlap --execute-reviewed-manifest-sha256 $reviewedPlanHash
```

For each phase, the secret manager injects only dedicated nonproduction values
into the process: `F02_ACCESS_TOKEN`, `F02_CURRENT_SIGNING_KEY`,
`F02_PREVIOUS_SIGNING_KEY`, `F02_CURRENT_SERVICE_KEY`, `F02_PREVIOUS_SERVICE_KEY`,
`F02_SYNTHETIC_EMAIL`, `F02_SYNTHETIC_PASSWORD`; overlap/retired/rollback also use
`F02_PREVIOUS_ACCESS_TOKEN` captured from the actual old issuer; reauth/rollback use
`F02_LEGACY_ACCESS_TOKEN`. `F02_CA_FILE` optionally selects the reviewed CA bundle.
Never type secret values as command arguments or print the environment. Use the
old access/service keys in baseline, fresh current access in later phases.
Keep the seeded bearer session distinct from the runner's temporary login session.
MFA-enabled accounts require an owner-operated browser/device ceremony; the API
password probe reports BLOCKED rather than bypassing MFA/CAPTCHA controls.

The runner performs real HTTPS introspection/protected GETs and synthetic
login/logout; reauth/rollback also refresh the temporary session. Login and refresh
must return an object with a `data` object containing nonempty string `accessToken`
and `refreshToken`. Refresh replaces cleanup credentials only after shape, signature,
claims and authoritative introspection validation. An error preserves the original
failure and makes one best-effort logout attempt using the last usable pair, with
the same10-second request bound and no retry. Missing credentials, a failed request
or non200 logout is recorded as unresolved; no logout is invented without credentials.
After an unvalidated refresh outcome, even fallback logout200 is only an
acknowledgment for that attempt: `cleanup_unresolved:true`/BLOCKED remains until
the owner reconciles any unknown replacement session/credentials. Successful
replacement validation plus logout200 records the cleanup acknowledgment, not a
general refresh-family/revocation-SLA guarantee. Cleanup failures never mask the
original error. A network/process interruption can also leave a synthetic session
for the authorized owner to clean up; retain these failure/NOT_RUN denominators.
It signs malformed challenges with the dedicated test material, never logs or
persists tokens, refuses redirects/proxies/HTTP/TLS bypass, and excludes the known
production origin. The manifest's isolation attestation is still an owner duty;
an arbitrary HTTPS host cannot be identified as staging by naming convention.

Capture stdout JSON to private evidence. It contains case/status/time and the
manifest hash, never response bodies or secrets. Exit 2 is BLOCKED/failed probe,
not success. Even `PROBES_PASS_ACCEPTANCE_PENDING` is not F02 PASS. On an error,
remaining cases are NOT_RUN: retain the failed result, fix the reviewed target
or configuration, and rerun. Do not edit expected status codes to obtain green.

## Ordered operational rehearsal and receipts

The probe never performs these infrastructure operations. The approved operator
executes exact platform commands recorded in the private target plan. On Render,
bind each reviewed `trigger_deploy` request to an explicit workspace/service ID,
and each configuration edit to the reviewed names/references below. A hook HTTP
200 is insufficient: capture the **completed** deployment ID, commit/image,
configuration version and actual instance inventory after every transition.

| Step | Approved operation and executable probe | Mandatory receipt / stop condition |
|---|---|---|
| 0 | Inventory, owner/risk/consumer decision, backup and rollback review; offline manifest command | All inputs above; actual current replica revisions/config IDs; no mutation on unresolved target |
| 1 | On isolated stores only, apply current additive migrations (`go run ./cmd/migrate up`, `version`, `check up`) with reviewed secret-manager DB references | Schema v6, clean migration state and expected identity indexes; never run down against retained authority |
| 2 | Deploy Finn v1 issuer/state **before** enabling strict consumer traffic; old dedicated signing/service IDs act as initial keys. Run `--phase baseline` | Actual Finn completion time, per-replica v1 login/current-old kid, TLS service state, negative matrix; keep consumer disabled or explicitly identify dedicated probe boundary |
| 3 | Stop/quiesce **every** old issuer; observe true final old issuance `T`, capture replica stop/drain receipts. Configure new current keys plus bounded old verification | No rolling mixed issuer continues issuing old keys after T. Last issuance from logs/observations, not inferred solely from JWT iat or local clock |
| 4 | Configure `JWT_KEY_ID`, `JWT_SECRET`, `JWT_PREVIOUS_KEY_ID`, `JWT_SECRET_PREVIOUS`, `JWT_PREVIOUS_LAST_ISSUED_AT=T`; and `IDENTITY_STATE_KEY_ID`, `IDENTITY_STATE_SECRET`, `IDENTITY_STATE_PREVIOUS_KEY_ID`, `IDENTITY_STATE_PREVIOUS_SECRET`, `IDENTITY_STATE_PREVIOUS_UNTIL=U` | Secret-manager versions/IDs only. T <= U <= T+930s in this rehearsal. Keep other audit/recovery/application keys distinct. Owner records startup success and exact config on every replica |
| 5 | Deploy Finn current-key configuration, then enable the approved strict consumer configuration. Inject fresh actual Finn access; run `--phase overlap` before both deadlines | Real issuer-before-consumer deployment timestamps, new-only issuance on every replica; both signing/service keys accepted during overlap; no synthetic claim of Jake runtime enforcement |
| 6 | Restart a named replica under the same immutable T/U; repeat overlap if time remains | Restart does not reset either deadline. Capture instance/config identity and real UTC/clock offset; finish within window or record NOT_RUN |
| 7 | At/after T+930s and U, inject fresh current access; run `--phase retired`; restart replica with unchanged expired config and repeat | Current key stays accepted at Finn and consumer. Old service credential rejected. Genuine previous access and fresh, otherwise-valid old-key challenge rejected by Finn and the identified consumer despite unexpired challenge exp/current authoritative session; restart must not renew overlap |
| 8 | Remove previous signing/service secret references and IDs/timestamps in an approved configuration version; repeat retired on all replicas | Actual removal/configuration receipts and secret-manager disable/retirement custody receipt; do not infer removal merely from expired access tokens |
| 9 | Owner isolates **only the dedicated** MySQL dependency; run `--phase mysql-outage`; restore and rerun positive phase. Repeat for Redis using `--phase redis-outage` | Both trusted introspection and protected delivery return 503, including consumer. Do not confuse inactive401 with unavailable503; preserve outage/restore timestamps |
| 10 | Run `--phase reauth`, then browser ceremony below; no legacy bridge remains | Actual issuer login, current kid, state, refresh, cleanup receipt/unresolved outcome; legacy401 directly at Finn API and consumer; browser/API evidence separate |
| 11 | Perform reviewed secure rollback or protected-access shutdown; run `--phase rollback` after retirement | Strict v1 and authoritative state retained; no old-key resurrection, permissive Jake verifier, schema down or stale security-state restore |
| 12 | Revoke/clean up only run-owned synthetic sessions/fixtures, remove temporary secret-manager access per approved plan | Cleanup receipts, final replica/config IDs, failed/skipped denominators and owner review; retain redacted immutable evidence |

During overlap the runner sends genuine captured previous access and a fresh
old-key challenge over current authoritative session claims directly to both Finn
introspection and the identified consumer, expecting200 at each. In retired and
rollback phases both endpoints must return401 for each previous-key input, while
the current-key control remains200. The fresh challenge must remain otherwise
valid/unexpired and use the live tenant/session/subject/version/permissions; an
expired token, dead session or tenant mismatch cannot substitute for this control.
The runner sets challenge iat/nbf to the actual current clock and exp to+900s,
then requires the identical claims signed by the current key to pass both Finn
and consumer immediately before the previous-key challenge. Neither paired
challenge is evidence of actual issuer issuance or an extension of user access.
Reauth/rollback also require direct consumer legacy401. These are
probe-produced challenges, **not old issuer issuance**. This distinguishes actual
key retirement from natural 900+30-second access expiry without backdating the
clock or forging rollout evidence. The runner also checks genuine old access
captured during baseline in overlap and after retirement; retain its issuer
provenance receipt. Record cessation of old issuance from all real issuers throughout.

## Browser and rollback acceptance

On the approved application origin/device with synthetic accounts in tenants A,
B and default: begin with an actual legacy browser session, attempt a protected
request and observe reauthentication; complete the real login/MFA ceremony; check
new Finn v1 issuance, the approved consumer protected route and refreshed access.
Check tenant/header changes add no authority, logout failures remain visible and
successful logout removes in-memory credentials. Reload/close/reopen and inspect
storage: no access/refresh credential in localStorage/sessionStorage; no new cookie
design is implied. Restart email/reset/MFA/sudo flows invalidated by key retirement.
Repeat approved API/Bearer and browser behavior after secure rollback. Record
browser/version, times, deployment/config identities and redacted HTTP verdicts;
do not save HAR bodies, authorization headers, passwords or tokens.

Stop rollout on any unexpected accept, stale/unavailable delivery, clock error,
unidentified replica or missing old-issuer cessation. Quiesce/disable protected
traffic first. Restore only a reviewed **strict v1** application/configuration with
current uncompromised keys and the latest durable security state, or keep access
disabled until repair. Never restore retired signing/service credentials, legacy
acceptance, the permissive Jake path or an older authority snapshot. Preserve
additive migrations. Destructive DB down/restore requires a separate F04-aware
reconciliation and explicit approval. Restore isolated dependencies before reopening
traffic; rerun positives/negatives, reauthenticate and record rollback completion.

## Evidence matrix and limits

| Boundary | Required result |
|---|---|
| Actual issuer/service wiring | Real login on each deployed replica; minimized trusted introspection200, protected API/consumer200; exact revisions/config/keys |
| Policy negatives | Missing/wrong purpose, audience, issuer, algorithm, kid, tenant, uid/sub and mandatory claims rejected; expected tenant mismatch403; no service credential401 |
| Cross-language | Existing `TestV1CrossLanguageContract` Go/Python corpus plus actual staged verdicts; reference never replaces Jake acceptance |
| Rotation/retirement | Direct Finn and consumer old-access/challenge overlap200 then retired/rollback401 with current200; genuine new-only issuance receipts, real deadlines, service overlap/expiry, restart and actual old-material removal |
| Dependencies | Actual isolated MySQL/Redis faults503, restore positives; no FAIL_OPEN or absence substitution |
| Issuer-first | Platform completion receipts place all Finn v1 issuers before strict consumer enablement; approved explicit legacy cutoff/removal |
| Browser/API/rollback | Real device ceremony, API login/refresh/logout, memory-only credentials, strict secure rollback, synthetic cleanup |
| Owners/consumer | Named signoffs and original criterion satisfied or explicit human scope/dependency resolution; keep BLOCKED otherwise |

Run existing local regressions with `go test ./internal/jwt ./internal/identity
./internal/services ./tests/identitycontract -count=1`. For isolated real stores,
reuse `go test -tags=integration ./... -race -count=1 -v` and the guarded loopback
inputs in identity-v1.md/current CI. MySQL schemas and Redis DBs 14/15 must be
dedicated: existing suites may flush Redis. Never point them at staging/shared
stores to obtain acceptance. Missing daemon/stores means local real-store NOT_RUN.
Offline orchestration tests, SQLite/memory adapters, mocked clocks and automatic
CI services establish only their stated local/disposable boundaries.
The Go wrapper runs all original8 offline cases plus12 review-repair cases. Its
deliberately incorrect consumer accepts a fresh retired-key challenge while Finn
rejects it; the actual runner must report FAIL. Other controls exercise malformed
refresh through login/refresh/finally, original-error preservation, unresolved
cleanup/redaction, production hostname rejection before execution and safe
nonproduction-shaped origins. No production DNS/HTTP request proves these fixes.
