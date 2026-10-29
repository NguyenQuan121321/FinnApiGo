# F02 ephemeral hosted rehearsal

This is diagnostic test tooling, not Jake or a Render deployment. The invoking
owner approved automatic same-repository PR runs on `codex/f02-actions-rehearsal`
in public `NguyenQuan121321/FinnApiGo`, using standard `ubuntu-24.04` runners.
NguyenQuan121321's identity/security/platform-on-call ownership and
`F02-LOCAL-STAGING-RISK-001` extend only to this isolated synthetic rehearsal.
An HS256 diagnostic key holder can mint staging tokens. This is not production
or pilot risk acceptance, full F02 acceptance, or J02 runtime certification.

The Windows Docker hold remains in effect. This workflow has no Render
environment, production secrets, deployment hook, write token, external store,
paid runner, public tunnel, cache upload, artifact upload or image publication.
Current GitHub billing documentation makes standard hosted compute free for
public repositories. Check current visibility before running; a private/forked
target is refused. Logs and summaries hold compact redacted receipts. Existing
mandatory CI/security policies remain unchanged, including their existing SBOM.

## Exact resources and private material

The project is `f02-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}`. Compose owns one
internal bridge, two dedicated volumes, MySQL, Redis, a STARTTLS-only synthetic
mail sink, two actual Finn release replicas and the strict diagnostic service.
Only loopback ports18443/20443/19443/18025 are published. MySQL/Redis ports are
private. The six containers have no shared/external network, privileged mode,
Docker socket, host networking, restart policy or production connection.

Actual host test routes use `<service>-<project>.test:8443` (mail8025), mapped
only to inspected task-owned bridge addresses in this disposable VM's hosts
file. The script checks project labels/private addresses, updates each exact
alias after recreation and removes only its marked entries during cleanup.
No public DNS, proxy, tunnel or Windows host change is involved. Configured
loopback publishing is not assumed reachable: the internal bridge's actual
HTTPS service routes are verified directly. Every leaf SAN names its exact
reviewed test alias and Docker service; CA key usage and constraints are checked
with `openssl verify -x509_strict`, not a certificate-verification bypass.

`RUNNER_TEMP/<project>` is restricted0700; independent RNG signing, service,
audit, checkpoint, recovery, metrics, store and synthetic-account material is
masked before possible output. Private env/config/TLS/manifest/mail/token data
is never uploaded or printed. Individual server key/config RO binds are readable
by the unprivileged container process; the host parent remains0700. The CA key
is never mounted. TLS>=1.2 terminates inside Finn and the diagnostic service;
outgoing introspection and SMTP STARTTLS verify CA and hostnames. No proxy,
redirect or certificate-ignore fallback is permitted. Dependency images and
the diagnostic base are digest pinned in the Compose/Dockerfile sources.

The job builds the repository's existing release Dockerfile, the diagnostic
image and previous strict source9947b8e. It asserts cmd/internal/migrations/
Dockerfile/module files match that rollback source. All three exact artifacts
must pass the existing HIGH/CRITICAL, fixed-vulnerability image policy before
they are launched. No scanner gate is weakened to start a service.

## Automated operations and evidence

The workflow checks out the tested merge with nonpersistent credentials, keeps
contents:read, runs no pull_request_target or manual deployment dispatch, and
has concurrency cancellation and a60-minute deadline. The scripts refuse to
operate outside the approved hosted public same-repository PR/branch.

1. Generate task CA/leaves and private configuration. Apply actual additive
   migrations and run version/schema checks. Register A/B/default accounts via
   real Finn, consume STARTTLS-delivered verification mail privately, then seed
   only explicit tenant-scoped chat:read grants and increment auth_epoch in the
   dedicated database. Password strength, default request/login rate limits and
   release startup/key/audit/state validation remain enforced. External breach
   screening is disabled only in this Internet-isolated synthetic topology;
   no production setting changes. Phase pacing preserves default login limits.
2. Verify both issuers before enabling the consumer. The actual HTTPS consumer
   verifies configured HS256/v1 policy, real retirement deadlines and every
   request's authenticated Finn state; it has no positive cache. Invalid access
   returns401; state/TLS/service-auth/schema/freshness errors return503. The
   separate HTTPS development controls use a fixture upstream, labeled as such.
3. Run the unchanged guarded client with the SHA256 of each actual private
   manifest. Baseline T is only the last observed issuance, not cessation.
   Capture final real old-key login/token iat/HTTP Date on each replica; stop
   both old issuers, retain stopped-container receipts, then freeze actual T
   and U=T+930. Finn is recreated with current keys first; consumer follows.
4. Exercise overlap and restart with immutable deadlines, then wait the real
  930-second maximum. Current controls and fresh previous-key challenges over
   live authoritative state distinguish retirement from natural token expiry.
   Repeat retirement after restart and actual removal of old runtime refs.
   Locally signed challenges do not prove issuer issuance. An intentionally
   incorrect real HTTPS consumer must produce a retained expected FAIL when
   actual Finn rejects a fresh retired-key challenge; that control's detection
   is reported separately from ordinary successful cases.
5. Stop only this project's MySQL, assert actual introspection/protected API/
   consumer503, restore and repeat positives. Repeat for Redis. No FLUSHDB or
   integration test harness targets these stores. Run API refresh/logout and
   the real headless Chrome diagnostic ceremony with normal certificate
   verification, a job-private NSS CA and no credential storage. Browser input
   stays in memory; output contains only verdicts. Repeat after switching both
   Finn replicas to the scanned previous strict artifact, retaining current
   keys and latest stores; no schema-down or stale-state/key rollback.
6. Request run-owned session logout-all and verify observed inactivation.
   Always remove the exact Compose project containers/volumes/network and
   verified RUNNER_TEMP child, checking leftovers. No host-wide prune or
   unrelated resource deletion. Cancellation/VM loss can prevent receipts;
   missing cleanup is unresolved, not invented success. VM disposal is separate
   from proving logout or refresh-family revocation.

`F02_RECEIPT` JSON lines and job summaries record source/head/tested merge/tree,
image/container/config identities, real times, guarded-client case verdicts,
fault/restoration/rollback ordering, failures and cleanup. Read all applicable
checks on the latest PR head; an earlier green run cannot certify a new push.
No change in labels or skipped denominator may manufacture acceptance.

## Acceptance limits

The browser page is a diagnostic memory-only client with actual Finn auth and
actual diagnostic enforcement. Its legacy input is explicitly a locally signed
legacy-shaped negative, not an actual historical session. Historical legacy
browser migration, real MFA/passkey/reset-device flows, actual Jake application
authorization, Render/pilot topology, owner operational signoff and independent
release acceptance remain NOT_RUN or pending. This rehearsal supplies real
ephemeral topology evidence only. It does not pass all original F02/G0-G6
criteria, start J02/F04 or assert Render health.

The WebDriver client uses two verified HTTPS windows. Finn performs same-origin
A/B/default authentication; the diagnostic window performs same-origin access
checks. A memory-only postMessage handoff checks both exact origin and window
source, carries no credential in a URL and returns only status. Finn CSP/CORS
remain unchanged; diagnostic cross-origin preflight is denied. Browser preflight
runs before the timed rotation, then repeats after retirement and strict
rollback. Storage is checked while authenticated, after refresh/logout and on
reload/reopen. This diagnostic transport is not a new Finn UI or certification
of a production frontend or Jake client.

See [the original operator runbook](f02-staging-rehearsal.md) for manual staging
boundaries and [the identity contract](identity-v1.md) for unchanged policy.
