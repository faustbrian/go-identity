# SCIM HTTP

## Managed bearer User List

`NewManagedUsersListFeature` selects exactly `GET /scim/v2/Users` using an
issued managed SCIM bearer, not an administrator session. Supply the public
`scimpostgres.ManagedConnectionService` as `Executor`, its matching native
`Limits`, the same HTTPS tenant-host policy as the outer router, and the same
strict atomic protocol backend/namespace/digest key as other SCIM routes:

```go
feature, err := scimhttp.NewManagedUsersListFeature(scimhttp.ManagedUsersListConfig{
    Network: network, Executor: nativeManagedConnections, Limits: nativeLimits,
    Rate: sharedProtocolRate, MaximumDuration: 5 * time.Second,
})
```

The native owner authenticates the issued bearer, resolves its persisted
connection and current organization/policy authority, then supplies only its
configured client and tenant to the single shared `rate.protocol` charge.
The trusted host tenant must match before any debit. Missing, repeated, failed
or ambiguous admission cannot disclose a success; client, full IP and tenant
budgets are atomic, with no local fallback. Every new HTTP read is a fresh
quota attempt. Original native authority/deadlines remain in force afterward.

Supported query parameters are exactly `filter`, `sortBy`, `sortOrder`,
`startIndex`, `count`, `attributes`, and `excludedAttributes`. Scalars decode
once under configured URL/decoded/field bounds; duplicate/case-alias names,
unknown parameters and malformed escapes/UTF-8 or overflowing integers deny
before native work. Signed decimal pagination within Go's native integer range
is forwarded without inventing defaults: the root owner applies RFC 7644
normalization, zero-count behavior, default/maximum page size, filter/sort/
projection semantics and snapshot bounds. This transport does not implement
another filter, pagination engine or response allocator.

Send one explicit `Authorization: Bearer <issued SCIM bearer>` header. Cookies
never supply fallback authority. Bodies, trailers, `If-Match`, content encoding
and every idempotency-key channel are forbidden. Success is the complete bounded
native `application/scim+json` ListResponse, unchanged and no-store/nosniff;
SCIM errors retain their redacted status/type and known rate retry hint.
Errors and invalid/oversized native output disclose no partial page.

No User Get-by-ID, writes, search, Groups or discovery is selected or advertised
by this factory. It retains canonical owner ID `scim`; explicitly combine its
disjoint Operations with other selected SCIM factories under one `NewFeature`
as below. Separate generic authentication middleware is not supported on this
native-owned handler; configure the same network policy and server IO deadlines
on the outer router.

## Managed administrative reads

`NewManagedReadFeature` independently selects exactly
`GET /v1/scim/connection-get?connectionID=<canonical ID>` when `Getter` is
supplied and `GET /v1/scim/connection-list?organizationID=<canonical ID>&limit=1`
when `Lister` is supplied. Omission exposes no administrative route or metadata.
The feature retains canonical owner ID `scim`. To coexist with `NewBulkFeature`,
explicitly combine both factories' disjoint operations into one `scim` feature:

```go
combined, err := identityhttp.NewFeature(identityhttp.FeatureConfig{
    ID: "scim",
    Operations: append(bulkFeature.Operations(), managedFeature.Operations()...),
})
```

Install only `combined` in `FeatureServices`; do not select both original
features separately, which would correctly reject duplicate owner IDs.

Supply the public `scimpostgres.ManagedConnectionService` for either or both
ports, configured with the actual session and organization authorization owners
and its installed `ManagedConnectionsMigrationSource`. No write configuration
is needed. The native owner retains current administrator, `org:scim-read`,
primary-read, cursor scope and final authority checks. Supply that same actual
`SessionService` separately for transport authentication and rate subjects; no
caller-submitted actor, ambient cookie or anonymous fallback supplies authority.

```go
feature, err := scimhttp.NewManagedReadFeature(scimhttp.ManagedReadConfig{
    Network: network,
    Sessions: sessions,
    Getter: nativeManagedConnections,
    Lister: nativeManagedConnections,
    SafeRate: sharedSafeRate,
    Now: time.Now,
    MaximumDuration: 5 * time.Second,
})
```

Use the same network configuration for the HTTPS router, and the same shared
`SafeRateLimiter` as other safe endpoints. Select `WithMiddleware` when real
decode/authenticate/admit/handle phases are needed. The transport admits trusted
IP and the currently authenticated tenant-scoped subject under canonical
`rate.safe`, including its existing bounded, recorded emergency policy only
when the shared rate backend is unavailable. Session authority failure denies
before rate admission; it does not downgrade to anonymous admission.

Send exactly one explicit `Authorization: Bearer <native session>` header.
IDs are exact canonical nonzero 22-character values. List requires canonical
decimal `limit=1..200`, with optional native opaque `cursor` on subsequent pages.
Cursors remain bound to the native tenant and organization; pages are live
primary reads ordered by connection ID, not retained snapshots. Bodies,
trailers, unknown or duplicate query fields and all idempotency-key channels
are forbidden. No Origin or CSRF token is required for this bearer-only read.

Get returns a safe connection projection; List returns `connections` (always
an array) and optional `nextCursor`. Each projection contains `tenantID`,
`organizationID`, `providerID`, `connectionID`, `mappings` (`source`, `target`,
`writable`), `deprovisionPolicy` and `version`. No bearer, digest or reusable
authority is serialized. Failures disclose no partial page. All responses are
no-store/nosniff JSON; owner failures are redacted. This selection does not
enable ConnectionCreate, provisioning writes, credential issue or Bulk.

## Managed connection creation

`NewManagedCreateFeature` selects only
`POST /v1/scim/connection-create` through the catalog's explicit bearer-only
alternative. It does not change the cookie/CSRF default or enable cookie
authority, reads, Bulk, provisioning, rotation or deletion. Supply the native
`scimpostgres.ManagedConnectionService` configured with `Writes`, its actual
session owner, the same shared `organizationhttp.AdminRateLimiter` used by other
administrator routes, native SCIM mapping limits and matching HTTPS network
policy. Install the native managed-connection and existing request-key/audit/
lifecycle histories before selecting the route.

```go
feature, err := scimhttp.NewManagedCreateFeature(scimhttp.ManagedCreateConfig{
    Network: network, Sessions: sessions, Creator: nativeManagedConnections,
    AdminRate: sharedAdminRate, Limits: nativeLimits,
    Now: time.Now, MaximumDuration: 5 * time.Second,
})
```

Send exactly one verified native administrator session bearer and one unchanged
`Idempotency-Key`. Ambient cookies are ignored, never a fallback. The canonical
shared atomic admin budget admits the actual authenticated actor, host-mapped
tenant and trusted full IP on every attempt, including retries. Denials require
the existing auditor to retain `identity.scim.connection-create`; there is no
process-local fallback. The native owner independently enforces current
administrator, organization and `org:scim-write` authority through creation.

The strict `application/json` body contains only `organizationID`, `providerID`
and `mappings` (1..128 objects containing required `source`, `target`, `writable`).
Organization IDs are canonical. Provider IDs retain their exact bounded visible
ASCII spelling without path/query/fragment separators. Mapping paths use the
selected native core-User profile; native fields and write policy still govern
which target mappings are supported. Queries, trailers, duplicate/unknown JSON
fields, caller actor/tenant/command and alternate request-key channels deny.
The supplied network limits bound body, decoded content, fields and depth.

A successful response contains `connection`, using the safe projection above.
Only a newly confirmed native invocation also contains sensitive `bearer`;
retain it securely and never log the response. An exact original-key retry
returns the stable connection without a bearer. The HTTP layer stores no
response or credential and does not reconstruct one on retry. After an uncertain
response, retry the identical intent with the original key, not a new command
or key. Failure, wrong-scope output or unavailable authority reveals neither a
credential nor a partial projection. No-store/nosniff headers apply throughout.

This factory also retains owner ID `scim`; combine its disjoint Operations with
the read/Bulk factories under one explicit `identityhttp.NewFeature` as above.

## Bulk protocol

`scimhttp.NewBulkFeature` selects exactly `POST /scim/v2/Bulk` and
`GET /scim/v2/ServiceProviderConfig`. Nothing is installed by importing the
module. Use the same configured network policy for the feature and the
identity HTTPS router. Every enabled host must resolve to the resource tenant
proved by the native executor before rate admission or work starts.

Pass the configured `scimpostgres.BulkService` as the executor, after
installing its required migrations and bootstrapping its native authority.
Use a shared strict-atomic rate backend, a deployment namespace, a stable
owned 32-byte digest key, a clock and bounded deadlines. Reuse the same quota
settings for both operations and independent HTTP instances; rotating the key
or namespace resets effective quotas. No local fallback exists.

```go
feature, err := scimhttp.NewBulkFeature(scimhttp.BulkFeatureConfig{
    Network: network, // identityhttp.NetworkConfig used by routerPolicy
    Executor: nativeBulk,
    Rate: scimhttp.ProtocolRateConfig{
        Shared: sharedRate, Namespace: "identity-protocol",
        Key: rateDigestKey, Now: time.Now, MaximumDuration: time.Second,
    },
    MaximumDuration: 5 * time.Second,
})
if err != nil {
    return err
}
operations, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{
    Features: []identityhttp.Feature{feature},
})
if err != nil {
    return err
}
handler, document, err := identityhttp.NewRouter(routerPolicy, operations, nil)
```

Configure the real HTTP server's read/write bounds; a context cannot interrupt
an arbitrary caller body reader. These handlers cannot expose separate generic
middleware authentication phases because the native executor owns the only
authentication and holds current authority through the operation. The common
router still owns network admission, exact route selection and optional CORS.

Send a SCIM bearer via `Authorization` and a BulkRequest with
`Content-Type: application/scim+json`. The server limits the raw body to the
executor's advertised size; only identity content encoding is accepted.
`Idempotency-Key` is an optional header alias, not a command identifier. Retry
the same input, and the same header if supplied, after an uncertain result.
The transport never streams partially settled children. Discovery returns
the actual Bulk capability and limits; unrelated CRUD and reconciliation
routes are not installed. Both endpoints consume a fresh atomic quota attempt
even when the executor returns a retained result.
