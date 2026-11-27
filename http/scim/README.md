# SCIM HTTP

## Managed bearer conditional Group PATCH

Select `NewManagedGroupsPatchFeature` for
`PATCH /scim/v2/Groups/{resource_id}` only. Send one issued SCIM bearer, the
original strong `If-Match`, and a bounded `application/scim+json` PatchOp body.
The native owner validates and applies ordered operations, including typed
members, under its configured Group ceiling. It owns exact original-request
replay and atomic version checks; the handler forwards the validated Group,
ETag and Location. A stale version returns `412`; an exact replay does not
apply the patch twice. Group PUT and reads are independently selectable.

## Managed bearer conditional Group Replace

`NewManagedGroupsReplaceFeature` selects only
`PUT /scim/v2/Groups/{resource_id}`. Use `ExecuteManagedAdmittedGroupReplace`
with the existing HTTPS tenant policy, native SCIM limits, explicit member
ceiling and shared protocol quota. Supply the issued Group connection bearer,
the original strong `If-Match`, and the complete `application/scim+json`
Group. Missing writable fields follow native replacement semantics; member
types and references must resolve in the selected connection.

Success returns the native `200` Group with its exact ETag and Location. An
equivalent headerless retry can recover that original result after fresh
authority and quota admission, without a second mutation. Changed input cannot
replay the first write. The transport accepts neither a client retry key nor
cookie authority and enables no other operation.

## Managed bearer Group Create

Select `NewManagedGroupsCreateFeature` to enable `POST /scim/v2/Groups`.
Use the same native connection authority, rate owner and explicit member
ceiling as other selected Group operations. The handler accepts a bounded
Group JSON body and issued bearer; it rejects client idempotency keys and
does not map fields or retry native writes. An authorized creation returns
the native Group with `201`, its strong ETag and canonical HTTPS Location.
Other methods, Group reads, User routes and discovery are not selected.

## Managed bearer Group reads

`NewManagedGroupsReadFeature` independently selects
`GET /scim/v2/Groups/{resource_id}` and `GET /scim/v2/Groups` through
`EnableGet` and `EnableList`. Supply `ExecuteManagedAdmittedGroupRead`, the
native limits and explicit member ceiling, the router's HTTPS tenant policy,
and the same atomic rate backend and key as the other SCIM routes.

Send an issued SCIM bearer. Get allows projection and returns the native
representation and exact ETag. List allows bounded filter, sort, pagination
and projection and returns one native snapshot. Native current authority
precedes quota use and resource reads. Neither route accepts cookies as
authority, conditional or range reads, or a request body.

## Managed bearer conditional User Replace

`NewManagedUsersReplaceFeature` separately selects only
`PUT /scim/v2/Users/{resource_id}`. Supply the native
`ExecuteManagedAdmittedReplace` owner, its matching limits, the HTTPS tenant
policy, and the same atomic rate backend, namespace and key as the other SCIM
routes. Send an issued SCIM bearer, one original strong `If-Match`, and the
complete `application/scim+json` User within the smallest configured body limit.

Native authority owns writable-attribute omission, exact precondition
comparison, protected mutation and original-command replay. Success returns the
native 200 User, ETag and Location. A request with the same original input may
recover that result without a second mutation; failure alone does not prove
rollback. No browser-cookie authority, client retry key, query, trailer,
automatic retry, or neighboring method is selected.

## Managed bearer conditional User PATCH

`NewManagedUsersPatchFeature` selects only
`PATCH /scim/v2/Users/{resource_id}`. Supply `ExecuteManagedAdmittedPatch`,
its effective SCIM limits, the router's HTTPS tenant policy, and the same
atomic rate backend, namespace and digest key as the other SCIM routes.
For example, with those existing owners:

```go
feature, err := scimhttp.NewManagedUsersPatchFeature(scimhttp.ManagedUsersPatchConfig{
    Network: network, Executor: nativeManagedConnections, Limits: nativeLimits,
    Rate: sharedProtocolRate, MaximumDuration: 5 * time.Second,
})
```

Forward the original singleton `If-Match` and a UTF-8 `application/scim+json`
PatchOp within the smallest configured raw, decoded and SCIM bounds. Native
authentication, PATCH validation and authority precede quota admission;
current precondition comparison, the mutation and replay use the original
native command. No caller request key, cookies, query, trailers, or retry
cache is used. A success returns the native 200 User with its exact ETag
and canonical Location. A denial exposes no partial User or version, and
does not itself prove rollback. Other methods remain independently opt-in.

## Managed bearer conditional User Delete

`NewManagedUsersDeleteFeature` selects only canonical
`DELETE /scim/v2/Users/{resource_id}` with an issued managed SCIM bearer.
Supply the public native `ExecuteManagedAdmittedDelete` owner, its effective
SCIM limits, explicit HTTPS tenant policy, and the same strict atomic protocol
backend, namespace and digest key as the other selected SCIM routes:

```go
feature, err := scimhttp.NewManagedUsersDeleteFeature(scimhttp.ManagedUsersDeleteConfig{
    Network: network, Executor: nativeManagedConnections, Limits: nativeLimits,
    Rate: sharedProtocolRate, MaximumDuration: 5 * time.Second,
})
```

The router supplies the exact unescaped resource segment. One `If-Match` value
is forwarded unchanged; the native owner retains required/strong-version
validation (428/400), current comparison (412), deprovision policy and atomic
membership-source withdrawal. Native current bearer/connection/organization/
operation authority and request preflight precede one shared `rate.protocol`
attempt, before command or protected effects. Headerless retries enter the same
native authority and admission window and recover the original tombstone-backed
204 without another mutation. No caller key, command journal or cache is added.

No query, body, trailer, content encoding, other conditional/range header or
Idempotency-Key channel is accepted. Ambient cookies never supply authority;
this bearer-only route needs no CSRF token. Success is exactly empty 204, with
no Content-Type, ETag, Location or cookie. Failures retain bounded redacted SCIM
Errors and existing outer transport envelopes; quota denial includes the bounded
positive Retry-After. No partial output is disclosed, and failure alone does not
prove a native effect rolled back. Original request/native deadlines control.

Importing or omitting this feature exposes no route or metadata. Combine its
disjoint Operations with other selected features under the canonical `scim`
feature ID; it selects no read, other write, search, Groups, discovery or
connection lifecycle. Owners must support concurrent requests. The synchronous
gate borrows its context only for the native call; no invocation is retained,
goroutine started, automatic retry made or local quota fallback selected. The
outer server retains body closure and raw-IO/write deadlines.

## Managed bearer User Create

`NewManagedUsersCreateFeature` selects only `POST /scim/v2/Users` with an
explicit issued managed SCIM bearer. Supply the public native managed owner,
its matching effective limits and HTTPS tenant policy, and the same strict
atomic protocol backend/namespace/key used by other selected SCIM operations:

```go
feature, err := scimhttp.NewManagedUsersCreateFeature(scimhttp.ManagedUsersCreateConfig{
    Network: network, Executor: nativeManagedConnections, Limits: nativeLimits,
    Rate: sharedProtocolRate, MaximumDuration: 5 * time.Second,
})
```

The raw `application/scim+json` body is bounded by the smallest native body,
transport raw-body and decoded-byte limit before forwarding. UTF-8 charset
and identity encoding are supported; other media/encodings fail as SCIM 415.
Native schema decoding owns duplicate/case-collision rejection, writable
fields, extensions, password policy and resource budgets. No transport request
key, client identity, mapper, credential store or command authority is added.
Queries, trailers, conditional/range headers and every Idempotency-Key channel
are forbidden. Cookies never supply bearer authority; this selection needs no
CSRF token or browser session.

The native owner authenticates and authorizes the current connection, then
charges one shared atomic `rate.protocol` attempt before mapping or durable
effects. Each HTTP attempt re-enters that authority/admission window; native
canonical command identity, replay and ambiguous-outcome handling remain its
existing owner's responsibility. No local quota fallback, response cache or
automatic retry exists.

Success returns the exact bounded native resource as SCIM 201 with its unchanged
strong `ETag` and authoritative `Location`, without cookies. The native profile
must use `Provisioning.BaseURL` equal to the canonical effective HTTPS origin
plus `/scim/v2`. The Location must name its canonical native resource ID at
that exact origin/path, agree with `id`/`meta.location`, and its ETag must agree
with `meta.version`; inconsistent or unsafe native output is not disclosed.
Native failures return redacted SCIM Errors, never partial data, Location or ETag;
no-store/nosniff applies throughout. A 503 after a native failure does not prove
that a mutation was rolled back.

Importing or omitting this feature installs no route. Combine its disjoint
Operations with Get/List/Bulk under the canonical `scim` feature ID as below.
It selects no collection GET, User Get, other write, search, Groups, discovery
or managed connection lifecycle route. The server retains raw-IO/write
deadlines and body closure; the feature starts no goroutine or detached work.

## Managed bearer User Get

`NewManagedUsersGetFeature` selects only canonical
`GET /scim/v2/Users/{resource_id}`. Importing this package or omitting the
feature exposes no route. Supply the same public managed native owner, effective
limits, HTTPS host policy and shared atomic protocol quota as User List:

```go
feature, err := scimhttp.NewManagedUsersGetFeature(scimhttp.ManagedUsersGetConfig{
    Network: network, Executor: nativeManagedConnections, Limits: nativeLimits,
    Rate: sharedProtocolRate, MaximumDuration: 5 * time.Second,
})
```

The canonical router supplies the real `resource_id` path value: one unescaped,
case-sensitive resource segment, never a query-selected ID, alias or broad
prefix. Only `attributes` and `excludedAttributes` query scalars are accepted;
each decodes once under the transport limits. Native schema/projection rules,
current bearer/connection/organization/policy authority and the final disclosure
fence remain native-owned. One shared atomic `rate.protocol` attempt occurs
after native authorization and before the resource read. Missing, denied,
repeated or ambiguous admission cannot disclose a resource or version.

Success preserves the complete bounded native `application/scim+json` resource
and exact strong `ETag`; the version can be used unchanged by a later supported
mutation. The native document retains its own `meta.location`; GET does not
add a redundant `Location` header. Errors disclose no partial resource or ETag.
No-store/nosniff applies throughout. Send exactly one explicit issued SCIM
bearer; cookies never supply fallback authority. Bodies, trailers, content
encoding, idempotency keys, conditional reads, ranges and `If-Match` are not
supported by this leaf. It does not retry requests or select a collection read,
write, search, Groups or discovery. Combine disjoint operations under the
canonical `scim` feature ID as below; retain server raw-IO/write deadlines.

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
