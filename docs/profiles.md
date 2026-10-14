# Self-service profiles

`NewProfileService` composes current upstream authorization, the existing typed
field policy and storage-neutral `UnitOfWork`, plus consistent primary profile
reads. This is an explicit-command core boundary; session verification, HTTP
CSRF and keyed admission remain required transport/composition work. Never decode
the trusted `authorization.DecisionContext` from a client body.

## Ownership and safe projection

The target is always the current human subject. Resource ID must equal that
subject and tenant/action/revision must match exactly. API-key and workload
actors are denied even if their policy would otherwise Allow. Active status is
required for self-service; blocked, deleted and absent subjects return the same
forbidden outcome. Authentication itself is not permission.

`ProfileRecord` binds hidden lifecycle state and `UserProfile` to one consistent
aggregate. `UserProfile` has ID, tenant, version, display name, image and typed
additional fields, never email, status, roles or credentials. Read admission
precedes the repository call; disclosure additionally authorizes trusted current
status/version. Caller-supplied phase/status/version/field metadata is replaced.
One clock sample is reused through operation and field decisions.

The immutable schema controls additional-field output eligibility. Redaction
must exactly partition the requested safe fields at the current registered
policy version/reason. ID, tenant and version must remain visible; name/image
and individual additional fields may be withheld. Invalid partitions withhold
the entire result. All returned collections are privately copied. Implicit
profile formatting is redacted; explicit authorized response serialization is
the consumer's responsibility.

## Writes, retries and recovery

Name is at most 256 UTF-8 bytes. Image is at most 2048 bytes and must be a
normalized HTTPS URL on one of 1..32 exact configured origins. Wildcards,
userinfo, fragments (including an empty `#`), opaque URLs and unselected ports
are denied. Configuration accepts only canonical origins without path, query
or fragment. Images are never fetched; there is no network or SSRF callback.
Empty name/image mean omitted, not clear. Zero/false/empty additional values
remain explicit whole-value replacements; omitted fields/defaults stay unchanged.

At most 64 input-enabled additional fields may change. Each requires a declared
self write class and exact current operation/field Allow. Core name/image fields
also require explicit self-field Allow. Email/status/role/credential/identifier
fields are forbidden rather than routed through profile writes. Configuration
cannot alias a core profile field through an additional-field declaration.

Preserve command ID, expected version and logical request on retries. Future
expected versions are rejected before an authoritative attempt, preventing
older-state authorization from admitting newer state. The durable owner checks
command replay before locked version/active-status CAS, commits one next
aggregate version, profile, immutable receipt and `identity.user.update` audit,
and returns the original result on exact replay. Changed same-ID intent conflicts.
`InvalidationVersion` is that aggregate version; it is not an acknowledgement
that session projections have already refreshed.

Known outcomes survive cancellation, dependency failure and output denial.
Withheld output has zero User/InvalidationVersion, while Committed stays known.
Unknown remains Unknown and requires `RecoverProfileUpdate` with the same ID
under current subject authorization/redaction. Recovery never executes again;
wrong tenant, actor, purpose or malformed receipt cannot disclose a result.
Historic recovery is not current authentication authority.

## Adoption and remaining work

Implement the public primary read and command ports in the named PostgreSQL
adapter, not in application glue. The synchronized test owner proves core
semantics only, not SQL locks, reservation, crashes, durable audit or migration.
The compiled command example demonstrates bounded structural construction,
which never grants authorization or URL-policy authority by itself.

Full Service/typed-catalog integration, session/CSRF/keyed transport, actual SQL,
and final coverage/mutation/release proof remain unfinished. Name/image clearing
is intentionally not represented by the current empty-string-as-omitted API;
the published API must preserve this distinction when adding such an operation.
