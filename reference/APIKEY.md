# Optional modern self-owned API keys

This selected backend composes public native owners. It is not an API-key
authentication session issuer, an administrative UI or complete M21 support.
Organization ownership, legacy import, finite quotas and cache projections
remain separate profiles.

## Configuration and ownership

Start from the supported registration/password/session deployment described in
[the reference README](README.md). Independently set `StoreConfiguration.APIKey`
with an immutable active `apikey.Configuration` selecting modern issuance,
unlimited quota, disabled cache and `PermissionReductionNarrow`. Supply its
deployment policy ID, bounded duration, pepper, retained envelope keys and
protected risk admission/counter custody. Counter schema and policy revision
must match the selected graph; lockout enforcement must be enabled.

The graph derives the actual native session reader/profile/lookup keys,
authorization, request keys, coordinator and counted evaluator. Applications
do not implement domain stores, command journals, migration SQL or handlers.
The pool, outbound sender and configuration callbacks remain caller-owned.
Keep retained keys available while their original commands can be recovered.

Select `PasswordSignin.Native.Transport = password.BearerSignin`, leave its
`CSRFKey` and `Issuance.Cookie` zero, and obtain genuine sessions through
`FeatureSet.PasswordPreAuth()` and `FeatureSet.PasswordSignin()`. The original
password verification issues the bearer; do not reinterpret a cookie session
or remove its stored CSRF. Other explicitly selected cookie issuers can continue
using their original cookie and synchronizer custody. Leave
`HTTPPasswordSignin` nil for this native bearer profile: that HTTP route owns
the distinct browser-cookie response contract.

Native `APIKey` alone enables no HTTP. To select management routes, additionally
configure `HTTPAPIKey` and the strong shared `HTTPRate` backend:

```go
stores.HTTPAPIKey = &reference.HTTPAPIKeyConfiguration{
    Create: true,
    Rotate: true,
    Revoke: true,
    SecretNamespace: secretNamespace,
    SecretKey: secretRateKey,
}
```

`stores` is the deployment's `reference.StoreConfiguration`; the namespace and
32-byte key are deployment secrets, not defaults. Use the same immutable
secret-rate namespace/key as other selected secret integrations when budgets
must be shared. Changing that identity resets budget and debit correlation.
Keep transport limits at least 64 KiB body, 16 KiB decoded data, 72 fields and
depth 2 when Create is enabled; selected scalar-only mutations can use depth 1.

## Explicit migration and startup

Compose stores/providers/workers/features without issuing business effects.
Use the existing `ReferenceMigrationCheck`, `ReferenceMigrationPlan` and
`ReferenceMigrationApply` APIs with `identity/apikey/postgres` in the explicit
module selection, alongside its existing identity/risk/session/effect owners.
The graph contributes the native key history and missing protected-counter and
lockout prerequisites. It does not copy SQL or rewrite installed histories.

Call `FeatureSet.Initialize` after the operator applies the plan. First install
registers the exact selected tenant/configuration. Reconstruction checks an
existing active configuration for an exact match; absent, different or disabled
authority cannot silently be adopted or reset. Selected operations deny before
startup, during graph drain and after `StoreSet.Close`.

## Consumer journey

Use the original freshly authenticated password bearer in `Authorization`.
Every mutation requires exactly one original `Idempotency-Key`; retries retain
the same key and complete input. None of these routes falls back to cookies.

| Route | JSON body | Result |
| --- | --- | --- |
| `POST /v1/apikey/create` | `name`, explicit `permissions` array, absolute RFC3339 `expiresAt` | Committed key metadata and original invocation's secret |
| `POST /v1/apikey/rotate` | `keyID`, `expectedVersion` | Modern successor with unchanged permissions/absolute expiry; predecessor denies immediately |
| `POST /v1/apikey/delete` | `keyID`, `expectedVersion` | Terminal revocation; no secret |

Persist the returned credential only through the application's explicit secret
custody. An original known-committed invocation can reveal once; a retry or
reconstructed graph returns status without the plaintext. Lost response delivery
does not permit another reveal. Unknown commitment remains unknown. No recovery
HTTP route is invented: the guarded native `APIKeys().Recover` observes original
outcome under current authority without reconstructing or rerunning issuance.

Use `FeatureSet.APIKeys().VerifyAndConsume` for actual atomic current-authority
verification and permission narrowing. This is not session authentication.
Current user/configuration/policy and the original sensitive-proof freshness
remain native-owned; retries and recent reads cannot renew that freshness.
Responses are non-cacheable and contain no session cookie or CSRF credential.

## Executable acceptance

The integration test uses real PostgreSQL and the supported public module pins:
registration, captured verification delivery, cookie baseline preservation,
genuine native bearer signin, HTTPS creation, native verification, graph restart,
secret-free original retry, zero-overlap rotation and terminal revocation. It
runs both fresh and populated operator migrations; disabled routes/metadata,
cookie-authority denial and retained-handle shutdown are asserted.

With a task-owned PostgreSQL fixture configured through the existing
`IDENTITY_REFERENCE_POSTGRES_PORT` contract, run the Reference module's
`TestReferencePostgresAPIKeyHTTPS` integration test with race detection. Use
task-owned Go caches and remove the fixture/caches after the bounded run.
