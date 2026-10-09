# Tenant administration

Authenticated operations use the signed token tenant before account-state or
permission lookups. Legacy tokens with no tenant claim are confined to `default`.
Client tenant headers continue to select a partition for unauthenticated login
and registration; they cannot change authenticated authority. Reset, email
verification and MFA-pending tokens issued by the service also carry the tenant.

`default` is an ordinary tenant. User changes include both tenant and ID in the
SQL predicate and never upsert a missing user. Sessions and audit reads include
tenant filters. Refresh tokens, passkeys, TOTP, recovery codes, OAuth identities
and trusted devices use their owning user's tenant. Object IDs and explicit
repository tenant arguments cannot widen this scope.

Admin routes require exact signed permission grants: `users:read`, `users:write`,
`sessions:read` and `audit:export`, as appropriate. `role=admin`, wildcard grants
and database fallback checks do not grant access. Production token issuance loads
explicit permissions from roles and users in the same tenant. Existing admins
without explicit tenant role assignments must receive reviewed assignments and
sign in again before using admin routes. F01 does not assign production roles.
Platform-wide administration has no pilot route or capability.

No new schema migration is required; the existing migrations through version 4
provide the tenant/owner indexes. Credential-version cache keys now include the
tenant; old entries expire and are ignored. Rollback must retain tenant filters
and permission enforcement or disable affected routes.

Run `go test ./...` for local regressions. `tests/tenantboundary` exercises the
production router, middleware, handlers, services and repositories for A, B and
default, including hidden-record responses, permissions, ownership and exports.
Its local SQLite variant is development feedback only.

For required MySQL evidence, provision a dedicated disposable loopback MySQL
instance, set `F01_MYSQL_ADMIN_DSN` to its admin DSN with no database selected,
and explicitly set `F01_MYSQL_ALLOW_CREATE_DROP=1`. Then run:

```text
go test -tags=integration ./tests/tenantboundary -run ^TestF01MySQL$ -count=1 -v
```

The test creates a unique `finnapigo_f01_test_` schema, applies the real embedded
migrations, runs the same matrix and EXPLAIN queries, and drops only that schema.
Missing configuration fails the test. CI supplies a disposable MySQL container;
production database configuration must never be used. Existing maintenance
purge/batch-delivery methods remain internal worker interfaces with no admin HTTP
route; they do not provide platform authority to user tokens.
