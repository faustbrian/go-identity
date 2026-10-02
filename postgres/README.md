# Identity PostgreSQL

Experimental Go 1.27 module implementing `identity.UserQueryRepository` using
the owned `go-postgres` pool. Tenant and user IDs are matched exactly; lifecycle
states and the full uint64 version range are preserved. Reads are primary-only,
bounded and uncached. Configure primary endpoints explicitly.

Construct with `NewRepository(pool, Config{MaximumDuration: time.Second})`, then
compose it through `identity.NewUserQueryService` for policy and redaction.
The caller owns pool shutdown. No globals or background goroutines are created.
Driver errors are discarded rather than exposed through `errors.As` or logs.
Cancellation and deadline classifications remain observable.

## Current development boundary

`MigrationSource{}` owns `identity.users` with `tenant_id`, `user_id`, `status`
and `version`. Compose the source with the existing `go-migrations/v3` Runner
and PostgreSQL backend before constructing the repository. The source creates
no private ledger or migration runner. Initial install requires an unoccupied
`identity` schema and runs atomically. Replayed migrations preserve populated
data; destructive downgrade is unsupported. Future changes append history.

It is not yet an adoptable complete durable identity adapter. Do not
write application-owned identity tables or transactions to bridge that gap.
Commands, snapshots, attributes, imports, lifecycle cascades, audit/outbox,
reconciliation and the shared transaction coordinator remain unfinished.

The appended command-claim migration installs the global ID claim and scoped
journal foundation. Private admission runs inside the Coordinator's
transaction, never commits independently, and does not grant mutation authority.
Exact replay selects the stored fingerprint-key version; missing retained keys
or missing scoped rows fail closed. Retired IDs conflict permanently. The owned
retirement policy and scoped recovery still require implementation; the later
migrations provide leases, terminal receipts and frozen plans.

The private codec maps all seven current core command variants, including
account link/unlink and all identifier actions, through typed accessors. It uses the closed
`identity-command-v1` deterministic encoding profile, framed HMAC-SHA-256
digests for all private fields, and stored-key regeneration on rotated-key
replay. Directory IDs retain their exact validated representation, including
ULIDs; random command IDs become fixed-width byte strings. Attribute times
must be microsecond-exact within PostgreSQL years 1..9999; no rounding is
performed. Equivalent whole-field replacement ordering does not change intent,
but list ordering does. No raw command, name, image or attribute value enters
persisted collision fields. Invalid command values fail closed.
Provider subjects/issuers, identifier values and the complete authenticated
capability authority are represented by framed keyed digests. Capability owns
its canonical payload representation; the adapter never JSON-serializes core
commands or consumes a proof during encoding. Proof header/key metadata, all
version fences, link modes, credential references, provider-revocation choice
and session/pre-auth continuations are included. A changed authenticated proof
is changed intent, not an implicit recovery credential. The claim phase does
not yet reserve or finalize proof use with a domain mutation.
The encoder follows [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949.html);
full protocol interoperability and release evidence remain pending.

The third forward migration extends the existing command journal with private
pending ownership, positive generation/attempt counters and database-time lease,
heartbeat and creation/update fields. Matching live reservations return bounded
retry delays; expired reservations acquire a new generation inside their caller's
transaction. Heartbeats cannot renew expired or stale ownership. A takeover is
not public apply authority: all declared participants must still be rebound in
that same transaction before the future Coordinator can commit it. No private
helper owns commit/rollback or infers a terminal result from lease expiry.
Foundation-only rows keep NULL ownership metadata and remain readable by older
claim code; the new reservation path rejects them until authoritative recovery
can prove their history. This migration does not fabricate ownership, classify
them as aborted or enable terminal rows without complete safe receipts.

The fourth migration enables committed/aborted rows only with a positive
supported receipt version, bounded body, database terminal time and closed
classification. Private terminalization locks and rechecks live generation and
owner; it never commits independently. Exact replay returns the original typed
receipt, not current user authority. Core `CommandResult.Validate` owns receipt
invariants; the private version-1 JSON storage representation rejects unknown
fields, duplicates, alternate spelling, lossy values and trailing input by
requiring exact re-encoding. JSON is not used for command fingerprints.
Retained attribute instants are encoded from an owned UTC copy and must be
microsecond-exact within PostgreSQL UTC years 1..9999. Second-offset time zones
cannot lose offset seconds in JSON, and caller-owned receipt values are untouched.
Receipts may retain authorized profile/attribute snapshots and private identifier
intent digests; treat this restricted replay storage as identity data under
retention/access policy, never logs, metrics or transport responses. Encoding
validates bounded core values before allocation; decode rejects bodies over
8 MiB. Required audit/participant staging and public scoped recovery are not yet
implemented, so private terminal SQL is not a conforming composed mutation API.

### Domain begin admission

Private domain-begin admission now revalidates the retained-key global claim,
locks the scoped pending journal and verifies generation, owner and lease using
database time read after lock waits. A key rotation with the retained original
key preserves admission; changed intent, stale/foreign/expired ownership and
terminal rows never become apply authority. Missing history or keys fails
closed. The future Coordinator owns rollback on every failure and bounds Work
by the remaining lease; this private snapshot neither renews validity nor
begins/commits/rolls back a transaction or invokes participants. Public Work
issuance and complete Begin orchestration are still unavailable.

### Restricted Work execution

`Work` now provides `Scope`, `Exec`, `Query` and `DatabaseTime` for trusted
compile-time enlisted adapters. Its constructor is private; application code
cannot acquire valid Work until the complete Coordinator is available. All
aliases share generation, scope, deadline, failure and closure. Work/WorkRows
are serial, not concurrent APIs. The deadline starts before the authoritative
clock read roundtrip, cannot restart on construction, and is never renewed by
DatabaseTime. The coordinator must invalidate aliases/active rows before closing
its transaction and retain sole commit/rollback ownership.

SQL must be a trusted compile-time SELECT/INSERT/UPDATE/DELETE/WITH statement
up to 64 KiB with no more than 64 closed scalar parameters/1 MiB total. Inputs
do not admit driver options, query rewriters or custom marshalers. Extended
protocol executes the exact SQL through a fixed owned binary scalar profile,
even without parameters; prepared-name aliases and caller-installed codecs
cannot replace it. Multi-statements are rejected by PostgreSQL. Initial execution
errors are resolved before returning rows. `WorkRows` exposes no driver or connection and permits only closed
typed scan destinations, not RowScanner or custom scanners. It returns at most
256 rows, 64 columns and 1 MiB raw result bytes. Close rows before another
query, inspect Err, and discard all destinations after a Scan error. SQL/scan/
budget/cancellation failures poison further execution; diagnostics are redacted.
Empty byte parameters remain non-NULL and are copied before I/O.

This is not a sandbox for malicious adapter SQL, a tenant query rewriter, or a
bound on server-side query work. Contributors must use scoped/indexed statements
and cannot invoke functions changing transaction ownership/isolation or external
state. No raw transaction, connection, nested transaction or closure API exists.
Audit/effect writers, typed participant phases and complete Coordinator issuance
remain required next; this partial execution surface is not full command authority.

### Kernel audit admission

`AuditPlan`, `AuditBindingDigest` and `Work.StageAudit` now implement the kernel
staging boundary. Coordinator-private admission freezes the plan before SQL;
the current kernel mapping requires exactly one action for its command, including
the canonical user action for profile/admin aliases. It rejects empty, duplicate,
late or rebound plans. No public method can enlist an audit or obtain valid Work.
Records must match the declared index/action/schema, command, tenant, actor,
target aggregate, policy and correlation. Exactly one immutable record is staged
per index; missing or duplicated staging fails closed. Invalid staging poisons
Work. Record/aggregate bounds may lower the 16 KiB identity security ceiling.

The current kernel profile accepts privacy-processed no-change/redacted records,
closed aggregate/version/reason attributes, safe opaque context IDs and bounded
producer tokens. Free descriptions, raw network/user-agent data, unknown
attributes, arbitrary structured changes and delegation are unsupported and
rejected. Feature-specific fields, composed multi-action mappings and the typed
complete `IdentitySecurityEventV1` builder remain required implementation.
The identity profile requires 128-bit-or-stronger opaque IDs: configure
`audit.Builder` with a trusted random generator, such as `identity.NewSubjectID`,
before `Build`. The primitive default UUID has fewer than 128 random bits and
is not selected by this profile. Staging preserves IDs; it never derives them
from a command or replaces them. Canonical base64url 128-bit and lowercase hex
128-bit ID profiles are accepted; format validation cannot attest randomness.

This is owned in-memory staging, not persistence, an independently committable
audit transaction or complete command authority. The registered audit contributor
must persist each canonical record and its command/index binding through the
same Work; the future Coordinator must enforce completeness before commit and
retain denial/unknown recovery evidence. Those durable paths are not yet present.

### Contributor registration

`CommandPlan.Lifecycle` adds one typed kernel notification plus the exact
`outbox/postgres` `identity.lifecycle` v1 contributor. `Work.StageLifecycle`
constructs a safe scalar-only record with a stable command/class/index ID;
`StagedLifecycle` returns an owned snapshot only after successful required audit
staging agrees on its target and before/after versions. It accepts no arbitrary
payload, identifier value or bearer. The trusted adapter obtains occurrence
time from `Work.DatabaseTime`; staging itself does not perform I/O. Closed or
failed Work cannot produce notifications. Mismatches poison the Work.

The open `LifecycleContributor` will persist these records through the same
Work, not a separately committable transaction. Persistence, cascade consumer
snapshots/checkpoints, encrypted delivery/provider effect profiles and complete
Coordinator invocation are still pending. Older audit-only admission remains
compatible, but cannot satisfy a successful future mutation commit. The deletion
notification is `identity.deletion_requested.v1`, never proof of completed erasure.

`AuditContributor` supplies the open durable audit phase.
`Work.StagedAudits` exposes owned declaration/record pairs only when every
required slot is staged. The registered audit adapter uses this snapshot to
write canonical records and immutable command/index bindings through that same
Work. It cannot retain Work or own transaction closure; success is staging,
not commit. Complete Coordinator phase invocation remains under development.

`CommandPlan` declares ordered contributor descriptors, required audit slots
and a digest. `KernelPlanDigest` binds the current kernel-only profile to the
exact command scope and authoritative fingerprint using deterministic CBOR.
Admission snapshots the slices against the exact registry; later input mutation
cannot change admitted work. Audit binding rejects foreign-registry Work,
different commands and late/repeated enlistment before SQL.

This intermediate profile supports exactly one domain and one audit contributor.
It does not accept feature, risk, capability or OTP contributors without their
typed inputs; it cannot substitute for their atomic reservation. The Coordinator
must resolve retained-key fingerprints before plan admission. Public command
issuance, durable audit delivery and complete participant phases remain pending.

Contributor identities can now be composed with
`NewContributorRegistry([]Contributor{...})`. The registry snapshots 1..64
trusted compile-time adapter descriptors once, preserves composition order,
rejects nil/typed-nil, duplicate contract IDs and conflicting versions, and
allows only exact registered descriptors in private command admission. Owners
are bounded lowercase printable ASCII; contract IDs are bounded printable ASCII;
neither admits whitespace or normalization. Composition roots own canonical
IDs and contributor lifetimes. Returned `Descriptors()` slices are caller-owned
copies and registry reads are concurrent-safe. Implementations remain open to
independent modules. This is identity admission only: no transaction phase,
typed participant input, Work issuance, late registration or commit API is
provided by registration. Unsupported phase combinations and foreign plan rejection remain
part of the forthcoming complete Coordinator, not guarantees of this constructor.

### Command reservation

`NewCoordinator(primaryPool, registry, CoordinatorConfig{...})` owns bounded
reservation transactions. Configure positive operation/lease durations no longer
than one minute, a microsecond-exact lease, and 1..32 retained nonzero 32-byte
fingerprint keys with an explicit current version. Keep the pool primary-only
and caller-owned. Configuration/Coordinator diagnostics hide keys and reject
JSON serialization. Registration is immutable; contributor resources stay
owned by the composition root.

Use `PrepareCommandPlan(binding, typedCommand, plan)` to obtain an owned digest
with the current key, then `ReserveCommand(ctx, binding, typedCommand, plan)`.
The initial public profile requires user creation, one required audit slot and
the matching lifecycle declaration with typed audit/outbox contributors.
One-time and cascade profiles are rejected before SQL. Services must authorize
commands first; preparation is not authentication or authorization.

Migration 5 adds a bounded immutable canonical plan to the existing journal.
It leaves historical rows NULL, not invented participant history. A matching
replay uses the stored key version and fingerprint; key rotation cannot rewrite
the declaration. Changed scope, intent or plan conflicts; missing retained
keys, NULL historical plans and corrupt history fail closed. Plan replacement
is rejected by a SECURITY INVOKER trigger, not a defense against privileged
administrators or DDL owners. Cleanup remains the retention owner's obligation
and must preserve global non-reassignable claims.

A new or expired reservation returns opaque generation ownership and
`InProgress`. Busy replay has no ownership; terminal replay retains the exact
historical receipt, not current authority. A proven reservation commit is never
a user commit. Failures before durable observation or after proven rollback
return a zero result, not fabricated `NotCommitted`. Any commit-attempt failure
or unproven rollback returns `Unknown`; no automatic retry or rollback follows
a commit attempt. The detached rollback budget is finite and earlier operation
deadlines win. No contributor callback executes during reservation.

### Creation execution (development profile)

`Coordinator.Begin(ctx, reservation)` consumes exact ownership once and opens
one bounded primary transaction. Reservation copies cannot issue another Work.
The original lease is checked after command locks; waiting never renews it.
Kernel mutations also take a transaction-scoped tenant lock. Work and its
cursors are serial-use; every path must close through Commit or Abort, including
panic (normally with deferred Abort). No closure goroutine is started. An idle
transaction timeout limits abandoned server locks but does not substitute for
releasing the caller-owned pool connection.

`Repository.ApplyUserCreation(ctx, work, command)` requires the exact registered
repository and frozen creation command. It inserts an active version-1 user;
the returned user is provisional until Commit. Nonempty attributes currently
fail closed, not silently disappear. Repeated apply poisons the transaction.
Stage the required successful audit with redacted structural changes and the
declared lifecycle record before `Coordinator.Commit(work, result)`. Commit
checks the caller result against the actual mutation, invokes the registered
audit then lifecycle persistence phases through the same Work, terminalizes the
journal and commits once. Missing evidence, open cursors, changed results or a
phase failure roll back all prefixes. All aliases close before transaction
closure. Any error after commit starts is Unknown, never automatically retried.

`Coordinator.Abort(work, cause)` proves rollback before a separate bounded
terminal transaction. A complete matching pre-staged denial/failure audit is
required for a known NotCommitted result; terminal audit and receipt commit
together. Missing evidence or lost ownership leaves pending/Unknown for recovery,
not fabricated success or denial. Detached cleanup remains bounded after caller
cancellation; driver and caller error text is never exposed.

This is **not yet an adoptable identity.UnitOfWork**: complete attribute storage,
other domain commands, the owned service bridge, classified retries and scoped
query/recovery remain required. The integration suite proves actual PostgreSQL
transaction behavior with typed audit/lifecycle SQL seams, not production
audit/outbox adapter interoperability. Do not supply application-owned identity
transactions or stores to bridge the unfinished profile.

### FAQ

- Can I use a replica? No; the repository's primary consistency contract is
  required for security composition.
- Are reads authorization? No; use the identity query service.
- Can I request extra fields? Only `id`, `tenant_id`, `status` and `version`
  are supported; unknown or duplicate fields are rejected, not ignored.
- Is the pool closed by the adapter? No; the application retains ownership.
- Is this released? No. Full adapter implementation and release gates remain pending.

## Integration testing

`go test -tags integration ./...` requires `IDENTITY_POSTGRES_TEST_DSN` pointing
to an explicitly disposable loopback PostgreSQL cluster with database
`identity_test` and database-creation permission. Each invocation creates and
removes its own random database; it never drops the supplied seed database.
Missing infrastructure fails the selected lane rather than skipping it.

PostgreSQL `numeric` with scale/range checks preserves all uint64 versions and
rejects fractional values; a scale-constrained type would round before checks.
See [PostgreSQL numeric semantics](https://www.postgresql.org/docs/18/datatype-numeric.html).
