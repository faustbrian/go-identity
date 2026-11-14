# API-key Valkey positive metadata

These explicit modern USER and organization profiles store encrypted positive/known-quota
metadata, not credential or quota authority. Every admitted `VerifyAndConsume`
calls the injected real `AtomicVerifier` **exactly once**, including warm NEW
attempts and matching replays. This is not a SQL-speedup or offline-authentication
profile. Existing native `CacheDisabled` configuration remains unchanged.

## Composition and use

Construct the real native primary and its fixed-scope
`NewPermissionReductionStore` first. Supply them as `Verifier`, `Authority` and
`Store` in `apikey.PositiveProjectionConfig`, alongside trusted configuration,
tenant, envelope service, fast clock, namespace/deployment epoch and wrapping-key
reference. Then call `New(ctx, transport, projection)` and defer `cache.Close()`.
No nil/typed-nil source or source-free degraded constructor is supported.

For organization-owned modern keys, compose the real native
`NewOrganizationService` and fixed-scope `NewOrganizationPermissionReductionStore`.
Use `NewOrganization(ctx, transport, projection, primary)`, leaving
`projection.Authority` nil. The separate reader must supply genuine current
organization authority; mixed selection fails. No creator identity or membership
epoch stands in for organization ownership. Distinct organization addresses and
ciphertext purpose bind the exact owner/root and aggregate/credential epochs;
the earliest original native and organization deadline wins. `New` stays USER-only.

Transport selects `Profile: "positive-projection"`, `Topology: "standalone"`, an
explicit `rediss://host:port`, CA trust, username/password and an independent
32-byte `NamespaceKey`. TLS 1.3 and hostname verification cannot be disabled.
`MaximumDuration` (1ms..5s) equals the root bound; `CacheTimeout` (1ms..1s) is
smaller. Payload bounds (1024..262144) must also agree. Maximum concurrency is
1..128. Borrowed sources, crypto and clock must be concurrency-safe and outlive
the adapter. Only owned operation clients/admission are closed.

Use the original supplied attempt unchanged. Check both the error and returned
state/outcome; only a non-nil still-fresh `Result` can support application policy.
Revalidate its original freshness at use, and apply business authorization.
The cache cannot authenticate a human, choose an OAuth client/resource, create a
session or grant application privileges.

## Authority, freshness and failure

The root codec creates same-source opaque admission only after real native
verification and current owner/key/configuration/policy observation. Cache keys
HMAC tenant/config/key/security and owner/global/tenant/user/authorization epochs
under the deployment namespace; no raw key or credential lookup digest reaches
Valkey keys/values. Full ciphertext AAD independently checks that scope if an
address collides. There is no public API to fill from a caller-invented success.

Restoration only narrows the current source grant and absolute deadline. Current
attempt, fingerprint, commit/debit outcome and quota are never replaced with old
metadata. Original positive read-start/deadline are retained on republishing,
bounded to 20 seconds; physical `PXAT` expiry floors that original absolute
deadline. Cache-server time is cleanup, never authorization. The source window
is checked again after publication I/O; an expired principal is not returned.

Current native epochs logically invalidate old addresses on update, rotation,
revocation, account/policy/configuration changes even when every cache event is
lost. Every later verification still calls primary. Missing/corrupt/evicted or
unavailable metadata cannot replace that call; obtained current authority denial
cannot be ignored as an optional miss. Known native debit/history survives a
later denial without a principal. Cache failure never causes another source
attempt, refill or debit.

`possible-debit` and source errors pass through unchanged and publish nothing.
Retain the same original attempt and any disclosed query. Reconciliation delegates
only that original query; it does not verify, debit, refill, promote or renew.
Permission maintenance/recovery similarly delegates to the real scoped Store;
caller decisions and recovered historical records are not fresh authority.

## Transport and operations

Each cache operation owns bounded TLS clients, disables driver retries/caching/
auto-pipelining, and rechecks standalone-primary selection. MOVED/ASK, replica,
cluster/sentinel and transport failures discard the projection. Reads use bounded
`GETRANGE`; there is no scan, list index, script or background subscriber/fill.
Values expire with their ciphertext deadline. No primary expired-record cleanup
or acknowledgement is implied by cache cleanup.

The production ACL needs connection setup (`HELLO`, `CLIENT SETINFO`), `INFO`
cluster/replication, `PING`, `GETRANGE` and `SET` only in the deployment's key
prefix `identity:apikey:p:v1:*`. Credentials/errors/configuration are redacted.
The organization constructor instead uses `identity:apikey:organization:p:v1:*`.
Do not log stable cache addresses or serialize opaque admissions.

Close is idempotent, rejects new operations, cancels/waits for owned clients and
releases borrowed references without closing primary/crypto/clock. No performance
advantage is claimed: the native source still does all authentication/quota work.

## Qualification and retained exclusions

The selected real service is official Valkey 9.1.0 Alpine, immutable image
`valkey/valkey@sha256:c9b77919daeba2c02ad954d0c844cc4e7142069d177b89c5fd771f405daf9e02`,
with valkey-go v1.0.78. Integration tests require explicit owned TLS fixture paths
`APIKEY_VALKEY_CA_FILE`, `APIKEY_VALKEY_PASSWORD_FILE` and `APIKEY_VALKEY_ENDPOINT`.
Run selected tests with task-owned Go caches and `-tags integration -race`.

Real-native composition must additionally prove current primary quota, revocation,
account withdrawal and original recovery; the independent contract fixture does
not claim native authority. Public-only module-consumer proof remains a separate
delivery boundary. Legacy cache profiles, failover/cluster, managed
clients and additional cache topologies remain unselected, not fallback modes.
