# Identity PostgreSQL

## Durable user-status admission

Opt in with `StatusMigrationSource{Base: MigrationSource{}, Version: allocated}`
and the owned migrations runner. Allocate its version after every composed
kernel/session migration; do not renumber installed history. Migration defaults
persist user-security epoch 1 and no legal hold while preserving every existing
status, aggregate version and identifier epoch. They also keep prior creation
and ordinary field writers compatible. A database missing this migration fails
closed; readers never invent security versions.

`Repository.GetStatus(ctx, identity.UserStatusQuery{TenantID: tenant, UserID: user})`
implements the core primary status port. `User.Version` is aggregate CAS;
`AuthorityVersion` is the independent user-security epoch. Profile and ordinary
administrative field edits advance only aggregate CAS. Suspend/ban and
restore/unban advance both, so restoring eligibility cannot restore old vectors.
Expired restrictions remain blocked until a fresh audited restore/unban.

Construct `NewStatusUnitOfWork(coordinator, repository, config)` with the exact
enlisted repository and typed audit/outbox contributors, then pass it and the
repository to `identity.NewUserStatusService`. That service supplies current
authorization, policy admission and redaction; calling the adapter directly is
not an authenticated endpoint. Configuration contains the same explicit status
policy/reasons as the service, a positive status-policy revision, finite cascade
deadline and reviewed version/fingerprint for every exact manifest consumer.
These are deployment metadata, not consumer stores or callbacks. Every change
to that configuration needs a new status-policy revision. The owner durably
rejects conflicting definitions for an already-used tenant/revision.

One shared commit persists status, reason/absolute expiry, both successors,
random cascade ID/generation 1, exact manifest and ordered consumer contracts,
trigger event/version, deadline, current legal-hold state, audit, lifecycle and
original receipt. Row locks precede the final primary-time expiry check. Exact
replay precedes current CAS and retains original IDs, timestamps and consumers,
even after restoration or a composition change. Preserve command identity and
use `Recover` after unknown closure; recovery never reexecutes the mutation.
Retain cascade admission rows alongside non-reassignable command evidence;
current user state or pruned payloads cannot substitute for retained evidence.

The returned cascade is **pending**. This admission path does not acknowledge
consumers, complete cleanup, manage legal holds, or implement cascade closure.
Those remain distinct generation-bound phases. Nor does a primary status read
alone establish authenticated session issuance or the shared-issuer 30-second
cache/resource guarantee; actual proof consumption and all authority owners
must still be composed. All epochs retain full unsigned 64-bit precision;
exhaustion denies a successor rather than resetting or wrapping.

Experimental Go 1.27 module implementing `identity.UserDirectoryRepository` using
the owned `go-postgres` pool. Tenant and user IDs are matched exactly; lifecycle
states and the full uint64 version range are preserved. Reads are primary-only,
bounded and uncached. Configure primary endpoints explicitly.

Construct with `NewRepository(pool, Config{MaximumDuration: time.Second})`, then
compose it through `identity.NewUserQueryService` for policy and redaction.
The caller owns pool shutdown. No globals or background goroutines are created.
Driver errors are discarded rather than exposed through `errors.As` or logs.
Cancellation and deadline classifications remain observable.

## Feature operation registration

Durable feature adapters may implement `FeatureContributor` alongside the
existing `Contributor`. The same immutable registry snapshots their compile-time
`identity.FeatureOperation` descriptors once, including all supported schemas,
explicit record policy and exact adapter owner. Each core owner maps to its
`<owner>/postgres` adapter; each operation belongs to one exact contributor
across schema versions. Duplicate/conflicting schemas and foreign ownership
fail construction before any transaction opens. Limits are 64 declarations per
feature contributor and 1024 total. Legacy contributors need no new methods.

`ContributorRegistry.FeatureOperations` returns an owned scalar projection for
trusted composition; it performs no callbacks. This is **not** enabled-feature
discovery, registration of codecs, authorization or execution readiness.
Kernel command plans remain closed. Native non-one-time feature execution uses
the same coordinator; production session issuance remains in development.
Do not advertise routes from these declarations or substitute private journals.

The existing private command codec also maps immutable `identity.Command`
feature inputs for future owned phases. Exact owner/record policy and every
named scalar kind/value affect the keyed fingerprint; all scalar values are
conservatively digested before canonical encoding. Scope remains separate from
private intent, and retained-key replay regenerates the original fingerprint.
This is not schema validation or execution readiness.

`CommandPlan.Feature` selects one exact frozen registration. Public
`PrepareCommandPlan` copies the matching contributor order, 1..64 strictly
ordered required audit slots and lifecycle declaration, and computes
`FeaturePlanDigest` using the current retained-key command fingerprint. The
preparation profile requires identity, audit, lifecycle/outbox and the exact
feature contributor; audit/outbox contributors must implement their typed phases.
Each audit slot has exactly one record, schema 1, positive retention version and
at most 16 KiB record/aggregate bounds. Required record lifecycle versions are
one checked successor; record-free declarations keep both zero. Feature-owned
adapters remain responsible for exhaustive native schemas and action policy.
Feature capability/cascade inputs fail rather than being silently discarded.

An empty `CommandPlan.SubjectType` retains the historical v1 structural-only
profile and cannot reserve. For native execution, select a valid subject type
and explicit `AuditPlan.RetentionClass` (`standard` or `protected`) for every
slot. These fields are bound into canonical feature-plan-v2 bytes. The native
adapter must implement `FeatureExecutionContributor`, exhaustively validate the
immutable command and full security plan before reservation, and inspect retained
effects during recovery. Every selected participant must implement recovery.

Use `FeatureAuditBindingDigest` for exact feature scope, subject and actor binding.

Native adapters call `Work.FeatureScope(themselves)` during Apply and
`RecoveryWork.FeatureScope(themselves)` during recovery to verify the exact
registered instance, active invocation and frozen version transition. Matching
descriptors or a still-open Work after Apply returns are not native authority.
The check performs no IO and returns owned scalar scope declarations.
Then `PrepareCommandPlan`, `ReserveCommand`, `Begin`, `ApplyFeature` and `Commit`
execute through the sole coordinator-owned transaction; always defer `Abort`
after a successful `Begin`. The native phase owns current authority checks and
its domain mutation, never kernel-table writes, audit/lifecycle staging, external
IO or transaction closure. The coordinator binds the provisional receipt to the
frozen transition and stages all audit/lifecycle effects. Only a successful
`Commit` proves durability; ambiguous commits return unknown and never locally
retry or reveal a bearer. Exact replay returns the original safe receipt.

Historical feature plans and command scopes are decoded as bounded, canonical
records. Authorized `QueryCommand` returns an owned `CommandRecord.Feature`
descriptor for feature history; it remains nil for kernel history. The stored
scope, frozen plan and terminal receipt must agree on owner, operation, schema
and record policy. Observation does not consult today's contributor registry,
replay commands, renew authority or expose native response/credential payloads.
Missing, wrong-scope and denied callers retain the same policy/read shape.

`RecoverCommand` observes live/terminal history. Expired native v2 commands can
take a new generation only with the exact frozen typed participants. Unanimous
retained non-commit evidence permits failure auditing and an aborted receipt in
one transaction. Unknown/conflicting evidence stays pending; success is never
reconstructed from current rows. Audit recovery can obtain an owned copy of all
slots through invocation-scoped `RecoveryWork.AuditPlans`; the existing singular
getter still rejects multi-slot plans. Historical v1 remains observation-only
and never takes over. Capability, risk and OTP-consuming profiles remain disabled
until their atomic typed phases exist; this is not a working session issuer.
Kernel digest bytes and the kernel-only scope decoder remain unchanged.

## Stable status-filtered listing

Compose the same repository through `identity.NewUserDirectoryService` for
collection/row authorization, redaction and authenticated wire cursors.
`List` materializes structural IDs, statuses and versions atomically in the
primary database; it is not a live OFFSET query or an authorization cache.
Migration 7 creates the owned snapshot/row tables without changing users or
migrations 1–6. Existing get-only consumers keep their APIs and configuration.

Ordering is bytewise ascending canonical user ID. Filters are an exact closed
status set. Continuations require the original tenant, status set and expiry,
and survive repository replacement and live insertion/update/deletion.
Expiry retains nanosecond identity, lasts at most 15 minutes and cannot be
renewed; primary time plus a shortened local deadline bounds each operation.
Snapshot status is historical directory data, never current identity authority.
The public service must reauthorize every page and each scanned row.

`Config.ListSnapshots` defaults to 10,000 users and 32 retained snapshots per
tenant. Explicit profiles require both positive limits, at most 100,000 users
and 32 snapshots. Pages are at most 100 rows. Each status branch uses the
existing tenant/status/user index and bounds candidates before materializing.
Quota or size pressure is `identity.UnavailableError`, never a partial snapshot
or silent truncation. Mismatched/expired continuations are redacted invalid
input; database failures disclose no diagnostics. An ambiguous snapshot commit
returns no page/cursor and remains bounded by retention/quota.

New snapshot admission removes at most one expired snapshot. Trusted platform
maintenance must also call `PruneUserListSnapshots(ctx, tenant, maximum)` for
inactive tenants, with `maximum` in 1–32; primary expiry and SKIP LOCKED keep
active/in-use snapshots intact, and removal cascades to their rows. The library
starts no worker and never closes the caller's pool. These storage APIs confer
no tenant permission. Grant the selected storage role the snapshot-table CRUD
and existing user SELECT permissions; no DDL or table ownership is required.

**Remaining scope:** exact identifier filters require the remaining identity-
owned identifier lifecycle store and fail closed today. Arbitrary attribute
search, complete fields, privacy/lifecycle snapshot erasure and full domain
commands remain unfinished. Do not create a list-only identifier authority or
application-written domain store to fill those gaps.

## Current development boundary

### Consistent self-profile reads

The repository also implements `identity.ProfileRepository`. Select it explicitly
with `Config.ProfileSchema: ProfileSchemaRef{ID: "fields", Version: 1}` and
declare that same schema in `Config.AttributeSchemas` and
`identity.ProfileConfig.Fields.Schema`. Zero leaves profile reads disabled.
The selected schema must contain at most 123 additional fields, without aliases
for name/image, credentials, identifiers, roles or other privileged core fields.

`GetProfile` observes the user, name/image and typed attribute document in one
primary SQL statement. The stored schema key and immutable definition must match
the selected declaration exactly. A missing structural user is `ErrUserAbsent`;
an incompatible/corrupt stored document is `Unavailable`, with no partial output.
The whole document is validated even for a narrow projection. Empty requested
fields select all output-readable fields; explicit fields must be unique and
known, with schema output permission. Structural ID/tenant/version remain bound
to the aggregate; unselected values are not returned. Returned collections own
their memory. Existing false/zero/empty values and full versions remain exact.

Forward migration 8 adds the owned `identity.user_profiles` name/image table.
It preserves migrations 1–7, structural-only users and old writers. Missing rows
produce empty name/image, not invented additional-field defaults or backfills.
No independent profile version or authority is created. Grant selected storage
roles SELECT on profile, attribute and schema tables along with user reads.

Compose through `identity.NewProfileService` for current-human self scope,
active status, authorization, schema output filtering and current redaction.
Storage reads confer no caller authority. Database image strings are bounded,
never fetched, and still require the public service's exact HTTPS origin policy.
The existing creation UnitOfWork can supply the service's dependency for reads;
select the profile composition below to enable mutation and recovery. Indexed/
secret storage and privacy erasure remain required platform work, not
application-written repositories or SQL workflows.

### Durable self-profile mutations

Use `NewProfileUnitOfWork(coordinator, repository, CreationUnitOfWorkConfig{
RetentionPolicyVersion: revision})` as the `identity.NewProfileService` command
dependency. It requires the exact registered repository, selected ProfileSchema
and typed audit/outbox phases. The existing creation owner remains creation-only.
This is an opt-in composition of the same Coordinator, not another transaction,
claim, receipt or recovery engine. No caller-written plans or SQL are needed.

`ProfileUpdate` admits current self scope and per-field policy before SQL.
The storage owner resolves exact command replay before CAS, then requires an
active user at the expected aggregate version. Name/image omissions preserve
existing values; explicit additional false/zero/empty values replace only their
named fields, preserving all omitted values without default backfills. Selected
schema definitions must agree exactly. Name/image, the canonical typed document,
one full-uint64 version increment, privacy-safe `identity.user.update` audit,
`identity.updated.v1` outbox event and original receipt commit atomically.

`RecoverProfileUpdate` and exact retries preserve the original result after
later mutations; current authorization/redaction still control its disclosure.
A changed command conflicts; stale or blocked new writes close with audited
NotCommitted and no domain/outbox prefix. Participant failure/panic rolls back;
unproved or ambiguous closure remains Unknown. Expired pending recovery requires
all frozen participants' negative evidence. The domain's original unchanged
version is negative evidence under the journal and tenant fences; a missing or
changed aggregate remains unknown, never inferred success. No fresh authority,
session, provider call or background worker is created.

Storage roles need UPDATE on users and SELECT/INSERT/UPDATE on profile/value
tables, with SELECT/INSERT on immutable schema definitions and the existing
command, audit and outbox permissions. Migration 8 already supplies profile
storage; migrations 1–8 and existing structural writers are unchanged.
The remaining kernel lifecycle profiles are unfinished.

### Durable administrative attribute updates

`NewUserUpdateUnitOfWork` supplies the existing `UserUpdateAdminService` with
the sole Coordinator's command protocol. Register the exact Repository and
typed audit/lifecycle phases as for creation. Select frozen `AttributeSchemas`;
the independent `ProfileSchema` feature is not required. Current operation and
per-field authorization remain in the core service, not role labels or direct
adapter calls. The current audit actor profile supports human and service
accounts; API-key actor composition remains unsupported and fails closed.

`ApplyUserUpdate` locks the authoritative aggregate and replaces individual
whole typed values, preserving omissions, explicit zeros, output-denied stored
fields, and the existing lifecycle status. Deleted/anonymized users cannot be
updated. The expected version fences exactly one full-width successor. Neither
name/image storage nor credentials, identifiers, roles or authority versions
are changed. Each command uses its exact registered schema ID/version; stored
definition mismatches and corrupt documents fail without a partial result.

One transaction persists the values, protected `identity.user.update` audit,
`identity.updated.v1` lifecycle and original structural receipt. Exact replay
precedes current-state CAS; a live parallel retry can return InProgress and
must retain the same command ID. Recovery observes the original receipt under
current core authorization/redaction. Expired pending commands close only with
the unchanged original aggregate version and negative evidence from every
frozen participant; missing/changed evidence remains unresolved. No second
transaction owner, callback inside SQL or migration is introduced. Storage
roles need the existing user and attribute/schema read/write permissions;
administrative updates do not require writes on the self-profile table.

Focused real PostgreSQL tests exercise these adapter semantics through the
public service with typed SQL audit/outbox test phases. Updated production
audit/outbox administrative composition and complete lifecycle/release gates
remain pending; the self-profile production composition is separately proven.

### Owned creation service composition

`NewCreationUnitOfWork(coordinator, repository, CreationUnitOfWorkConfig{
RetentionPolicyVersion: revision})` supplies the core `identity.UnitOfWork`
dependency for `identity.NewUserCreationService`. The exact repository instance
must already be registered with typed audit and lifecycle contributors. The
adapter owns plan construction, privacy-safe audit records, primary time,
reservation, execution, closure and scoped receipt lookup. Consumers do not
implement a domain store or supply Work, audit-record builders or command plans.

This is a trusted storage seam, not a transport endpoint: only the core service
provides current caller authorization, field preparation and output redaction.
Creation supports human and service-account actors; API-key actor audit mapping
remains unsupported and fails before reservation. Failure evidence is built
before domain writes and staged after proven rollback, never by unpoisoning SQL
Work. No success prefixes survive participant failure. A failed failure-audit
commit or ambiguous transaction remains Unknown. Replay preserves the original
receipt and audit ID, including after retained fingerprint-key rotation.

Recovery returns historical creation, not current user status. Live pending
returns InProgress without changing ownership. Expired creation can take a new
generation and atomically abort with failure auditing only when every exact
frozen contributor supplies `RecoveryContributor` and proves non-commit.
Missing, unknown or conflicting evidence remains pending. Existing users never
become reconstructed success receipts. Other command profiles, recovery-deadline
alerting and transaction retry policy remain unfinished. Existing test SQL
contributors prove coordinator atomicity, not production audit/outbox adapter
interoperability; that composition remains required before package completion.

`RecoverCommand(ctx, query, caller)` uses current `QueryPolicy` authorization
and returns metadata only; owned core recovery uses the trusted storage seam
without synthesizing caller identity. `RecoveryWork` is invocation-bound, exposes
only scope, bounded evidence queries and the participant's frozen declaration,
and cannot stage mutations or close transactions. Contributors read retained
bindings even when payloads have been pruned. QueryCommand remains observational.

### Primary command lookup

`CoordinatorConfig.QueryPolicy` optionally enables `QueryCommand(ctx, query,
caller)`. Configure the existing `authorization.Service`, a trusted `clock.Clock`
and positive current `PolicyVersion`; nil keeps lookup disabled. Policy callbacks
run before the single primary read, never under an open transaction.

Trusted authenticated composition supplies the `authorization.DecisionContext`:
the actor/kind, tenant, original operation and `identity.user` resource targeting
the query's user must match at that current revision. Do not decode caller
identity or authorization attributes from client overrides. Every historical
query field—including optional record ID and link mode—must match the stored
command. Current policy permits disclosure but never rewrites old policy/schema
versions or correlation. Reserved `identity.command.*` attributes are rebuilt
from the exact query: ID, record ID, decimal link mode and recovery/read-admission
flags cannot be replaced by caller attributes. Missing, wrong-scope and denied requests all perform
the bounded decision/read shape and expose zero receipt plus ForbiddenError;
this is not an identical wall-clock latency guarantee.

Pending, including an expired lease, remains InProgress. `CommandRecord` exposes
only historical scope, outcome and retry metadata, never stored profile,
attribute, account or credential payloads. It is not current user status or fresh
authentication authority. Protected replay values stay inside owned core
recovery and its current field-redaction policy. Orphaned,
legacy/incomplete or corrupt history fails closed. Lookup neither locks for
mutation nor changes a lease, generation or contributor. `RecoverCommand` and
the owned UnitOfWork service bridge remain unfinished; callers must not implement
their own transactions or participant recovery to replace them.

## Identifier and verification partitions

Apply forward migration9 before calling `GetIdentifierState`. It adds the
positive `identifier_version` authority dimension to users (initial version1)
and identity-owned identifier/verification rows. Existing users retain their
aggregate versions; structural writers that omit the new column remain valid.
The migration takes PostgreSQL DDL locks and validates the new user constraint;
run it through the bounded migration Runner during a reviewed migration window.
No destructive downgrade or application-written backfill is supported.

`GetIdentifierState(ctx, identity.IdentifierQuery{TenantID: tenant,
UserID: user, MaximumIdentifiers: 128})` implements the existing public storage
port. One indexed SQL statement returns the complete ordered partition or an
error with no partial state. The limit must be1..128; oversized partitions are
unavailable, not truncated. Missing users return `ErrUserAbsent`. The configured
repository budget and any earlier caller deadline bound pool acquisition and
query execution. Returned slices own their memory; the pool remains caller-owned.

Canonical values are exact, case-sensitive, at most512 UTF-8 bytes with no C0/C1
controls. Optional display values have the same bounds but may be empty. IDs
preserve the existing validated directory-ID profile. Record and canonical-value
uniqueness is tenant-local; canonical uniqueness also includes kind. A user has
at most one verified primary identifier of each kind. Verification state and
identifier flags share a row and database constraints; pending has no timestamp,
verified requires one, revoked may retain the original timestamp. Reads reject
future or otherwise inconsistent verification timestamps and preserve uint64
versions without signed-bigint truncation. Neither snapshots nor structural
validation grant authorization or prove a challenge.

This is the storage foundation, not a complete identifier workflow. Use the
existing `IdentifierService` for admission once coordinated identifier writes,
atomic capability/risk participants and retirement tombstones are implemented.
Do not supply application-owned SQL or transactions to bypass those requirements.

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

`CommandPlan.Capability` can now freeze one scalar, single-use capability input
for deterministic digest preparation and bounded historical decoding. It binds
the exact signed ID, purpose, expiry/use bound, independently keyed replay digest
and retained key version, and immutable proof fingerprint. The enclosing command
fingerprint binds target/version intent. Existing audit-only and lifecycle plan
bytes are unchanged. Formatting redacts this input and JSON export is rejected.
This declaration is not proof validation. Exact identifier commands can now
prepare/reserve when the registry supplies a `CapabilityReservationContributor`.
The coordinator freezes owned inputs, checks signed ID/expiry/use and target
versions, and invokes Reserve or exact-predecessor Rebind under the same claim,
journal and tenant locks. Failure, panic or unfinished rows rolls back every
prefix; returned invocation handles and rows cannot outlive the phase. Retained
fingerprint keys remain authoritative on replay. Contributors never own closure.
`Begin` still rejects these reservations before consuming their opaque handle:
domain/session/risk/apply/finalize phases and the production
capability store are pending. No capability use or complete workflow is claimed
by a reserved journal. Existing creation/profile/admin composition is unchanged.

Expired identifier-attachment commands additionally support primary recovery
when every frozen contributor supplies `RecoveryContributor` and the capability
participant supplies `CapabilityReleaseContributor`. Missing targets and exact
reserved capability bindings are negative evidence, never sufficient alone.
Only unanimous non-commit evidence under journal and tenant exclusions grants
`CapabilityReleaseWork`; it CAS-releases the prior generation to a terminal
state with the new recovery generation. Failure audit, terminal capability and
aborted receipt commit together. Missing, conflicting or unknown evidence and
callback errors/panics roll back the entire takeover. Capability expiry does not
release an unknown outcome; terminal repeat returns the original receipt. These
SQL fixture tests prove coordinator atomicity, not production capability-store
composition. Other identifier operations and successful consumption remain open.

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
the returned user is provisional until Commit. Declare up to 32 copied,
versioned `Config.AttributeSchemas` for ordinary scalar/list storage. The exact
tenant/schema/version definition becomes immutable in the same transaction;
different definitions under that identity conflict. Undeclared fields/kinds or
unsupported indexed/secret profiles fail closed, not silently disappear.
Repeated apply poisons the transaction.
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

Attributes use a private bounded version-1 canonical CBOR document, preserving
present false/zero/empty values, int64 extrema, ordered string lists and UTC
microsecond-exact instants without float conversion or JSON escaping growth.
They are private stored values, never diagnostic snapshots. Recoverable secret
fields require the future owned secret-envelope profile; there is no plaintext
fallback. Indexed fields need explicit field migrations, not arbitrary search.
Migration 6 adds schema/value tables without inventing values for old users;
old structural writers/readers remain supported. Definition update/delete/
truncate is rejected for ordinary writers, not hostile DDL/database owners.
Public reads still return structural fields only; field authorization,
redacted projection, attribute updates/backfills and secret/index profiles
remain required.

This is **not yet an adoptable identity.UnitOfWork**: remaining attribute profiles,
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
