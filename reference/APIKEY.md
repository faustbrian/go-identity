# Optional user and organization-owned API keys

This selected backend composes public native owners. It is not an API-key
authentication session issuer, an administrative UI or complete M21 support.
Finite quotas and cache projections
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
| `POST /v1/apikey/rotate` | `keyID`, `expectedVersion` | Modern successor with unchanged permissions; modern expiry is preserved, legacy expiry is bounded by both original expiry and current modern lifetime; predecessor denies immediately |
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

## Digest-only legacy import

Opt in with `APIKey.LegacyConfiguration`, a distinct verify-only
`AlgorithmLegacySHA256V1` configuration sharing the modern issuer, environment
and audience. Supply `APIKey.ValidateCanonicalKeyID`, a bounded,
concurrency-safe policy that accepts the deployment's canonical historical IDs
unchanged, including ULIDs. It cannot supply owner or import-source authority.
This finite native profile requires absolute expiry, unlimited quota, no cache
and Narrow permission reduction; unsupported alternatives reject rather than
fall back. Leaving the legacy configuration zero retains modern-only behavior.

Re-plan and apply `identity/apikey/postgres` through the same operator APIs.
The selected native legacy migration is version 2 in the existing API-key
namespace; version 1 and populated modern key/account/session history remain
unchanged. Initialization installs or checks both exact selected configurations.
Reconstruction never enables a disabled configuration or replaces its policy.

Use `FeatureSet.APIKeys().Import` with the fresh genuine password bearer, an
original idempotency key, exact typed record, source ID/version and
`LegacyDigest`. Import accepts no plaintext and creates no issuance/reveal.
Native authorization separately checks the current owner, source and grants.
Original/source recovery, conflicts, terminal tombstones and required effects
remain native-owned; reconstructing the graph cannot rerun an original import.

Use `VerifyAndConsume` with `LegacySecret` and the exact server-selected legacy
configuration. Existing bare bytes are hashed unchanged; token text selects no
profile and cannot trigger a fallback. The guarded native API adds no HTTP
import route. The independently selected existing rotation route accepts the
imported canonical ID and creates a modern successor without extending expiry;
the revocation route retains terminal denial for that successor. Current session logout also
denies original management retries. No browser session is issued by key use.

## Organization-owned keys

Configure `Organization` with its real native settings and set
`APIKey.OrganizationOwned = true`. The public `FeatureSet.APIKeys()` handle then
also exposes `CreateOrganization` and `RecoverOrganization`. No organization
repository, workflow callback or SQL is supplied by the application. Current
human management is distinct from the credential's durable organization owner.

Include both `organization/postgres` and `identity/apikey/postgres` in the
operator migration selection, along with existing baseline owners. The plan
applies native organization credential authority and key-owner extensions in
that order after their base histories. Independent optional histories preserve
the installed organization and modern/legacy key prefixes, including populated
user keys. Startup checks the selected sources; it does not implicitly migrate.

Additionally set `HTTPAPIKey.OrganizationOwned = true` to select organization
management on the existing HTTPS routes. Creation then accepts optional
`organizationID` alongside `name`, `permissions` and `expiresAt`; absent owner
input retains ordinary self issuance. Rotate/delete take the original key ID
and expected version and use its immutable actual owner. Actor and tenant still
come exclusively from the genuine password bearer and trusted host. Native
current membership and policy authorize each mutation and its protected work.

Leaving the HTTP flag false retains user-only mutation authority even when
native organization support is selected. This is a native profile restriction,
not merely removal of an OpenAPI property or suppression of committed output.
The ordinary API-key routes remain available for user keys; organization input
is rejected, and an organization key cannot be rotated/revoked through them.

Key verification has no fabricated creator `UserID`. Creator membership removal
preserves the independently owned key while denying that human's management
and original recovery. Another current authorized owner may rotate or revoke.
The native owner's separate credential epoch prevents archive/restore from
reviving older authority. Original evidence deadlines, permission narrowing,
required effects, reveal-once custody and unknown-outcome handling are unchanged.
Retain the target organization with the original input/key for direct
`RecoverOrganization`; status inquiries do not reconstruct plaintext or replay
missing work. Organization keys never issue a user/browser session.

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

`TestReferencePostgresLegacyAPIKeyHTTPS` additionally proves populated modern
migration, source-version-preserving import, unchanged bare verification, graph
reconstruction/original recovery, actual HTTPS rotation/revocation, logout and
disabled-configuration startup denial through the same public owners.

To preserve historical keys with no expiry, explicitly set
`AllowLegacyNoExpiry` in the named verify-only `APIKey.LegacyConfiguration`.
Pass a zero `Record.ExpiresAt` to digest-only import; no artificial deadline is
stored. Use a new immutable configuration rather than editing an installed
finite profile. Default legacy and every modern configuration still require
expiry. This opt-in does not change current owner/policy checks, the original
20-second evidence ceiling, terminal revocation or secret custody. Existing HTTP
rotation creates a finite modern successor using current issuance policy;
there is no new HTTP import route or unbounded issuance option.

`TestReferencePostgresLegacyNoExpiryAPIKeyHTTPS` proves populated modern-state
adoption, native import and unchanged verification, graph reconstruction and
original recovery, followed by HTTPS modern rotation/revocation and logout.

`TestReferencePostgresOrganizationAPIKeyHTTPS` proves fresh selected and populated
user-key upgrades, genuine registration/verification/native bearer signin,
HTTPS organization-key issue/retry, creator removal, independent verification,
other-owner rotation/revocation, native recovery denial and required-audit
rollback. It also proves user-only HTTP cannot mutate an organization key even
while direct organization support is selected. The regression was observed
failing under an intentionally wrong native view and passes with that view
restored. These profiles are not whole M21 or final release qualification.
