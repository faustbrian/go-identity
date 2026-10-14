# Administrative typed-field updates

`NewUserUpdateAdminService` composes an authoritative `UserQueryRepository`, the
existing storage-neutral `UnitOfWork`, the exact upstream authorization service,
redaction and the same immutable schema/normalizer/value policy used by creation.
It performs no construction-time I/O and owns no stores, transactions or workers.

`UserUpdateAdmin` is currently an **explicit-ID core boundary**, not a finished
HTTP keyed endpoint. Trusted admission retains a random command ID, canonical
user/tenant, positive expected aggregate version, exact schema version, logical
fields and correlation across retries. ExpectedVersion cannot be uint64's
maximum because the required next version would overflow. Supply 1..64 declared,
input-enabled fields, under the existing aggregate bound. Each supplied field is
a whole-value replacement; omitted fields and creation defaults are unchanged.

## Authorization and concurrency

The exact action is `identity.user.update-admin`, resource `identity.user`,
with the target user, tenant and current policy revision. This is not permission
inferred from an actor kind, role name or authenticated principal. The existing
upstream policy must explicitly Allow both read admission and field application.

Before reading current state, the service clears owned status/version and field
metadata, sets `identity.command.read-admission=true` and
`identity.command.recovery=false`, and authorizes the scoped read. After the
authoritative read, `read-admission=false` and trusted status/version replace
caller metadata. The shared field processor authorizes the complete operation
and each field, with its registered write class and sensitivity. It normalizes
only explicit changes and samples no additional clock. One trusted clock sample
is reused throughout admission and field decisions.

Terminal deleted/anonymized rows are never eligible. Updating display fields
on a suspended/banned account does not restore it or make it login-eligible.
The adapter must lock and validate current status/version before applying a
new mutation; pre-read policy is not a substitute for that race fence.

The core rejects expected versions newer than the authoritative read, without
attempting Execute: policy cannot authorize a future state using an older row.
Older expected versions remain eligible for Execute. Durable replay must first
check the global command claim and exact canonical intent: the original commit
has already advanced the version. Only a genuinely new stale command conflicts.
Changed intent under the same ID conflicts without another mutation or audit.

## Command, audit and outcome ownership

`NewUserUpdateCommand` freezes a structurally bounded command with a typed
`UpdateUser` accessor returning private copies. It is not proof of authorization,
canonical-ID validation or field-policy approval. The closed command union
returns false for an accessor belonging to another operation. Formatting remains
redacted and command JSON serialization remains forbidden.

For a new command, the durable owner atomically applies just the supplied fields,
advances the version once, writes the immutable command result and the required
`identity.user.update` audit record. Replay returns that original receipt. No
core or consumer owns a raw transaction or a separate audit/command ledger.

A committed update receipt binds the exact operation, tenant, target, actor,
policy/schema and command correlation, contains the original expected version,
and has user version exactly ExpectedVersion+1 with a stable audit event ID.
Malformed/mismatched receipts remain Unknown. Noncommitted/conflict/unknown/
in-progress variants contain no user, audit ID or expected version.

Valid known outcomes survive dependency failures, cancellation and redaction
failure. User/Version are withheld on output failure; Committed never becomes
rollback. Before an authoritative attempt, Invalid means no command outcome
observation, not proof that an earlier same-ID attempt did not commit.

## Recovery and remaining work

`RecoverUserUpdateAdmin` authorizes current scoped result access and queries the
primary owner without new fields or a second Execute. It verifies the original
update purpose; creation recovery likewise rejects update receipts. Historic
policy/schema bindings are retained while current policy/redaction control
disclosure. Its user/version are the original committed snapshot, not current
status or authentication authority.

The synchronized test owner proves core replay/version/output behavior only.
PostgreSQL reservation, crash recovery, canonical keyed fingerprints, durable
audit, real uniqueness and release certification remain required adapter work.
Full Service/catalog integration and keyed admission are pending. Self-service
profile Name/Image and its distinct status-excluding projection remain required
separate work; do not expose this administrative projection as a profile API.
Credential, identifier, role and lifecycle mutations have their own owners and
must not be represented as additional-field writes.
