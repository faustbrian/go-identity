# Creation and command recovery

`NewUserCreationService` composes one storage-neutral `UnitOfWork`, the exact
upstream authorization service, shared read redaction, and explicit
`UserCreationConfig`. It freezes policy reasons/schema defaults and performs no
I/O. Dependencies are caller-owned, concurrency-safe and context-bounded.

## Current API and adoption

`UserCreate(ctx, UserCreateRequest)` is the current **explicit-ID core boundary**.
Trusted admission supplies a random `CommandID`, an injected-policy-validated
canonical `UserID`, exact tenant, schema version, typed fields and authenticated
`ActorScope`. Never decode that scope from client JSON. User IDs, including
existing ULIDs, are preserved rather than reformatted as SubjectIDs.

Generate a command ID once with `NewCommandID`, or reconstruct it with
`ParseCommandID`. It is exactly 22 canonical unpadded base64url bytes encoding
128 nonzero random bits. Do not derive it from personal data. Every retry retains
that ID, user ID, logical fields, correlation and policy/schema binding. An
omitted correlation defaults to the command ID. Neither identifier is authority.

Initial status is active, aggregate version one. Restrictions/destructive states
belong to their own versioned lifecycle commands, not initial creation. Supply
at most 64 explicit fields. The shared field processor may apply up to 128
declared defaults, under the same aggregate bounds and per-field authorization.
Its self-write rule still requires the actual user actor to match the target;
an administrative schema must explicitly select administrator/system write
classes and policy must Allow them. A role string never grants permission.

The service binds action `identity.user.create`, resource `identity.user` and
the exact tenant/target/revision. It replaces reserved status/version and
`identity.command.recovery=false` metadata. The field implementation is reused,
not duplicated. A single trusted clock sample supplies decision time across
the operation and all fields; the bounded context controls elapsed work.

`Command` is immutable and closed, with a typed `CreateUser` accessor returning
private copies. Its constructor validates structure; **it is not an authority
issuer** and does not prove authorization or schema validation. Trusted service
composition prepares inputs before the adapter port. Formatting redacts all
verbs; JSON serialization fails rather than silently producing `{}`. Adapters
must never log accessor payloads or use them as diagnostics/secret snapshots.
The compiled example demonstrates construction, not permission to execute it.

## Required durable owner

`UnitOfWork.Execute` owns the global command-ID claim, scoped idempotency,
canonical keyed fingerprint under retained versions, uniqueness/tombstones and
one atomic user + command-result + required `identity.user.create` audit commit.
The adapter allocates stable audit IDs under that same command authority.
It must reject changed intent without another mutation and replay the original
redacted receipt. It cannot resurrect a tombstone, split audit into a later
commit, use a projection as authority or silently implement a second ledger.

Only the PostgreSQL adapter maps commands into its concrete coordinator and
registered contributors. Core exposes no transaction, work handle, callback,
participant registration, commit or rollback. Command fingerprint/authority
fencing and all common transaction requirements remain adapter obligations;
the current core tests do not certify their durable implementation.

## Outcomes and output

The adapter returns `CommandResult` with exact command/tenant/target/actor and
policy/schema binding. A committed creation must include the immutable original
version-one user and stable required audit ID; other outcomes contain no user
or audit ID. InProgress has a positive delay no greater than one minute.
Malformed, cross-scope or contradictory receipts remain Unknown, never success.

Before an authoritative attempt, `UserCreateResult.CommitOutcomeInvalid` means
**no durable outcome was observed**. Denying a retry or cancelling before this
call writes cannot prove an earlier same-ID attempt rolled back. After entry
into the adapter, errors/panics without a valid receipt remain Unknown. Unknown
errors carry the same command ID and may also unwrap a redacted standard context
error. Dependency details never cross the service boundary.

A valid known outcome remains intact even when later output fails: committed
plus cancellation/redaction error means committed with no user disclosed, not
rollback or another creation attempt. Current redaction runs after every replay
and recovery; historic permission decisions never authorize new disclosure.
The returned user is a creation receipt, **not current status or login authority**.
Authentication must obtain current authoritative state independently.

## Recovery, FAQ and pending integration

`RecoverUserCreate` accepts the original command ID, tenant, target and current
trusted actor scope. It authorizes current result access before primary lookup,
sets `identity.command.recovery=true`, and passes only scoped `RecoveryQuery`.
It does not execute, replace fields, mint IDs or expose globally claimed foreign
commands. Historical policy/schema binding stays unchanged while current policy
controls output. Authoritative abort/absence is NotCommitted; a failed lookup,
transport loss, cancellation or lease timeout alone is not absence evidence.

**Is this a complete signup service?** No. Password/session/identifier ceremonies
and hooks are separate remaining work. This is authorized backend creation.

**Who maps HTTP Idempotency-Key?** The platform's transport/PostgreSQL composition
must atomically map a scoped keyed digest to one preallocated command/user
identity before mutation. That public keyed-admission API is still pending,
along with full Service/Repository/PolicySet and typed-catalog reconciliation.
Consumers must not be asked to build their own ledger or identity workflows.

**Is PostgreSQL ready?** No. The synchronized in-memory test owner demonstrates
core orchestration, one logical replay effect and current disclosure policy;
it does not prove SQL isolation, crash recovery, reservation, durable audit,
canonical CBOR, key rotation or interoperability. Those and all applicable
module release/coverage/mutation gates remain mandatory before verification.
