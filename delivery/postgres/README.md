# Identity delivery PostgreSQL

**Under development.** This module does not yet expose a production Queue.
It exposes public durable admission through `NewEnqueueService`, authenticated
preparation, immutable migration history and original-command staging. Admission
is not a complete durable Queue or provider integration.

## Public admission

The optional `MigrationSource.ReconciliationVersion` extends receipt storage
with immutable, generation-scoped query checkpoints. It requires `ReceiptVersion`
and a version above it and any selected `ReceiptCommandVersion`; cancellation
and receipt-command profiles are not prerequisites. Earlier migration checksums
remain unchanged. The private borrowed effect phase serializes checkpoint CAS
with receipt state/erasure, preserves original results on replay, denies active
worker leases and stale progress. Cursor exhaustion ends a query sequence, not
an unresolved effect: a fresh poll can restart only at the exact latest step.
Original earlier polling requests cannot reopen it. Only keyed cursor
digests persist in this projection. Public reconciliation, recoverable cursor
custody and provider querying are supplied by the separately selected feature
below. Safe retry
admission remains distinct from provider observation.

### Opt-in provider reconciliation

Install `ReconciliationCommandVersion` above `ReconciliationVersion`, then
`ReconciliationQueryVersion` above the command extension. The latter adds
immutable original-query commitments and separately erasable encrypted cursors;
all earlier migration bytes remain unchanged. Set `StateTracking` and
`Reconciliation` in `EnqueueConfig`; nil keeps this feature disabled and does
not require its migrations. Configure one bounded `OutcomeQuerier` for each
selected tenant/provider-version/service-account actor. The callback must
authenticate provider evidence, support original-key lookup and honor cancellation.
This is a provider seam, not permission to implement a domain store or workflow.

Create a trusted binding from `ReconcileOperation()` and current actor policy.
`ReconcileCommandRequest` binds the original intent, generation, observed status
version and checkpoint step. The initial step is zero with an empty checkpoint.
Subsequent requests use the previous opaque result checkpoint and next step;
status versions advance once per committed observation. Never refresh fences or
replace a command ID to retry an unknown/pending command. A new poll is a distinct
authorized operation, not retry recovery of a previous command.

`EnqueueService.Reconcile` queries exactly once outside SQL ownership and before
kernel reservation, using the original persisted provider key rather than its
new command ID. A restart decrypts retained cursor custody in exact scope.
Historical exact replay returns its original result without lookup even after
terminal erasure; current authorization is always required. Query failure,
panic, timeout and `TransientFailure` produce no observation/progress and grant
no resend permission. Transient settlement/retry hints are deliberately unsupported
by this query operation rather than silently classified as rejection or dropped.
UTC observation time is normalized to PostgreSQL microsecond precision.

`RecoverReconciliation` uses the original command ID and exact authenticated
scope, never a provider poll. Live pending remains pending; an expired reservation
is marked not-committed only after the original coordinator's unanimous retained
participant proof and failure audit. The selected query composition defaults
its recovery `QueryPolicy` to the same current authorization service; an explicit
configured policy remains authoritative. A known terminal failure record may
accompany a classified error. Recovery never issues replacement commands or
implicitly resets the generation/step; use exact replay to obtain a committed
query's original domain result.

Unknown observations retain uncertainty and encrypted payload/cursor custody;
cursor exhaustion permits later polling only at the latest step. Definitive
settlement erases cursor custody atomically, including settlement through other
receipt/cancel paths. Retain envelope and digest keys while referenced. The
deployment namespace key fixes opaque progress identity and cannot be rotated
as a way to reset history. Expired message bearers do not prevent lookup of an
unresolved provider effect. This public operation is not complete Queue worker
composition, safe automatic retry admission or vendor interoperability evidence.

`NewEnqueueService` composes the owned primary directory, renderer, native enqueue
phase, audit, lifecycle, custody and original kernel coordinator from one borrowed
PostgreSQL pool. Supply retained configuration, templates, the envelope service
and bounded authorization; no consumer-written domain store or transaction
orchestration is needed. Install the public kernel, audit, outbox and delivery
migrations through `MigrationSource.KeyedVersion` before construction.

`EnqueueCommandRequest` is trusted typed workflow input, not HTTP JSON or proof
of authentication. Supply the authenticated binding/scope, exact identifier ID,
message with **no recipient**, retained provider version, original expiry and
bounded idempotency key. Admission authorizes before discovering the canonical
recipient and rendering, then rechecks policy before atomic persistence. Keep
all logical inputs unchanged across retries; candidate command IDs may differ.
Changed input conflicts; matching scoped keys preserve the original intent.
Retain referenced provider/template/policy versions and custody keys.

Exact retries after the original expiry observe the historical kernel outcome
under current authorization, without allocating, encrypting or reserving a new
send. Expired new keys are rejected. An allocation without authoritative command
history remains unknown, not proof of noncommit. Historical observation defaults
to the supplied authorization service, system clock and current policy version;
an explicit `Coordinator.AdmissionPolicy` remains authoritative when supplied.

Committed `Queued` means durable admission, never provider delivery. Unknown or
in-progress outcomes require exact-request recovery, not a new key or send.
`AdmissionUnknownError` carries only an actually known original command; allocation
uncertainty returns `ErrOutcomeUnknown` without inventing a command identity.
Constructor policy/namespace registration is bounded and independently committed;
an exact retry safely resumes a partial constructor without creating an intent.

Trusted enumeration-safe workflows may use `NoOpEquivalent` with no identifier.
It preserves the queued result shape without sendable ciphertext. Never expose
that internal bit to clients. The service starts no goroutines or sender work;
the caller retains ownership of the pool and dependencies. Full public
cancellation, authenticated receipt/reconciliation and worker composition remain
under development.

## Public processing

Call `EnqueueService.NewWorker(WorkerConfig, Sender)` once per configured
tenant/worker/provider profile. Supply a trusted authenticated service-account
`Scope`, action `identity.delivery.process`, resource type
`identity.delivery-worker` with the exact worker name as its ID, a correlation
ID and the service's current policy revision. This is deployment composition,
not HTTP input or permission to authenticate by an ID. Current authorization
must explicitly permit the worker; the adapter adds reserved `delivery.provider`
and `delivery.provider-config-version` attributes. Caller overrides are rejected.

The worker uses the selected provider's **retained** retry policy, callback
timeout and concurrency limit, not the latest policy. Multiple provider versions
may share a retry policy but cannot claim or complete one another's effects.
`Worker.ProcessOne(ctx)` runs at most one committed lease/send/complete cycle.
Capacity is acquired before leasing; the Sender receives the immutable original
rendering, expiry and effect idempotency key outside SQL transactions/locks.
Acceptance is not delivery. Transient no-success evidence schedules a bounded
retry; ambiguous invocation remains unknown and is never blindly resubmitted.

`Worker.Claim` and `Worker.Complete` expose the same authorized direct-worker
boundary. A direct caller owns bounded provider invocation and must retain the
exact worker/intent/generation/evidence for completion replay. Prefer ProcessOne
unless that explicit scheduling boundary is necessary. Missing current policy
or uncertain completion acknowledgement is not proof of provider failure.

Authorization is reevaluated before leasing, after opening committed custody
and before completion. Denial after leasing prevents Sender and records bounded
owned no-invocation cleanup when possible; cleanup uncertainty leaves the lease
recoverable, not sendable. No background retry loop is created. Keep pool,
authorization, envelope keys, retained profiles and Sender alive while using the
worker. Production policy rejects a missing or capture Sender.

This public processing composition completes an owned worker path, not the
remaining all-method `delivery.Queue` facade or package release gates.

## Authorized status

`EnqueueService.StatusGet` accepts the core status request, an exact target user
and trusted authenticated authorization context. Use action
`identity.delivery.status-get`, the configured current policy revision and
`identity.user` resource targeting that user. The service binds the requested
intent as a reserved `delivery.intent` resource attribute before policy, then
reads exact deployment/tenant/intent/owner metadata from the primary database.
Caller-supplied `delivery.*` attributes are rejected; IDs are not authority.

Results contain only state, generation, terminal classification and whether the
latest attempt has a provider reference. No recipient, message, reference bytes
or receipt body is loaded or returned. A live lease is attempting; provider
acceptance is not delivery; a lost lease is unknown, not retry authorization.
Queued expiry is effective expiration, without mutating/erasing custody in a
read. Missing and foreign targets share `ErrNotFound`; no-op intents expose the
same queued/expired shape rather than their private custody-free cancellation.
This method does not start workers, decrypt payloads or call a provider.

With `StateTracking=true`, `VersionedStatusGet` returns `StatusSnapshot` containing
that same metadata and its database-owned `StatusVersion` from a single primary
statement. It uses identical current authorization and isolation; legacy profiles
return `ErrInvalidInput`, and failures disclose no snapshot. Retain the version
and attempt generation unchanged when forming or retrying a protected mutation.
Do not reread and silently replace a previously frozen command's fences. The
version is not authority or a freshness guarantee: effective expiry and lease
classification can change without an intent update. This query is the owned
precondition seam for cancellation, not a cancellation endpoint.

## Custody and security

Select `EnqueueConfig.Cancellation=true` with `StateTracking=true` and install
`MigrationSource.CancellationVersion` after `StateVersion` to enable
`EnqueueService.Cancel`. The constructor checks selected schema before policy or
namespace registration. Default false preserves existing admission/status use.
This is trusted workflow composition, not client-decoded authentication input.

Build a `CancelCommandRequest` with a fresh kernel command ID, exact cancel
operation/schema binding and current authenticated actor policy targeting the
owner. Use `Request.TenantID`/`IntentID` matching the binding, and freeze both
generation and `ExpectedStatusVersion` from `VersionedStatusGet`. Keep all input,
including command ID and bounded non-PII reason, unchanged on every retry. IDs
and snapshots grant no authority. Caller `delivery.*` attributes are forbidden;
the service supplies the target attribute to policy. Reasons are never persisted
or serialized, only domain-separated HMACed under the retained namespace key.

Cancellation stages through the existing kernel coordinator, with protected
audit/lifecycle and immutable original-command result in the same transaction.
It selects the target's retained policy under its intent lock. Separate operation
registries keep installed enqueue plan identities unchanged when enabled; both
handles share the same kernel journal and authority, not independent workflows.
Unsent/retry custody is erased; no-op stops preserve the same public result.
Submitted sends remain outcome-unknown, with local cancellation preventing resend
but preserving live attributable completion. No provider is called or remote
cancellation claimed. Exact committed replay returns the original cancellation
result even after later delivery evidence changes current status.

`ErrOutcomeUnknown` (including live pending) requires retrying the exact command,
never generating a replacement to bypass uncertainty. A changed input conflicts;
a stale snapshot needs a deliberate new command only after the previous command's
terminal outcome is established. Current authorization precedes reservation and
result disclosure. Errors return no fabricated stop result; a post-commit denial
or failed read does not roll back a durable cancellation. Full core Queue
composition and provider cancellation/reconciliation remain unfinished.

Select `MigrationSource.StateVersion` strictly after `KeyedVersion` and set
`EnqueueConfig.StateTracking=true` to read immutable no-op local-stop checkpoints.
The constructor rejects an absent selected schema before policy/key registration;
it does not install migrations. False preserves legacy admission/status behavior.
The forward migration leaves all installed checksums and queued custody intact.
Every intent UPDATE, including old-worker writes and metadata-only updates,
advances its database-owned uint64 status version atomically; clients cannot
assign a different version. Version exhaustion fails closed. A no-op local-stop
checkpoint is write-once with database occurrence time, preserving cancelled or
expired status across retries and later expiry without exposing recipient state.
Application roles must not own tables/triggers or DDL; this invariant does not
protect against a privileged operator disabling enforcement. The migration takes
a bounded table lock and validates new nullable metadata under its transaction;
lock/statement timeout rolls it back for an exact retry, never partial success.
State tracking alone does not enable cancellation or a full Queue.

`MigrationSource.CancellationVersion`, selected strictly after `StateVersion`,
adds immutable, redacted cancellation results tied by foreign key to the
original kernel command and delivery intent. Zero preserves installed history.
The private native cancellation participant stages the stop, version CAS and
result in that same coordinator Work; protected audit and lifecycle must commit
with them. A lifecycle failure restores custody and status. Original replay
returns its retained receipt without another stop or version increment.
These cancellation records contain no raw operator reason or provider evidence.
Application roles must not own DDL or trigger controls. Public local cancellation
is explicitly selected through `EnqueueConfig.Cancellation`; provider cancellation
and full Queue composition remain unfinished.

### Provider-receipt persistence foundation

The opt-in receipt operation implements an explicit Golib callback
profile, not a vendor-signature compatibility layer. Immutable configuration
binds each 32-byte nonzero HMAC key and key ID to deployment, tenant, provider,
positive provider configuration version and provider actor, with mandatory
UTC validity intervals. Both signing time and current verification time must
fall in that half-open interval. Envelopes expire after five minutes and allow
at most thirty seconds of future signing skew; a fresh signature can report a
delayed observation without extending a retired credential's validity.

The v1 signature is HMAC-SHA256 over the literal domain
`identity-delivery-receipt-hmac-sha256-v1`, an eight-byte big-endian length and
UTF-8 string array encoded by Go's `encoding/json.Marshal` (including HTML
escaping), `[deployment,tenant,provider,decimalVersion,keyID,signedAtRFC3339Nano]`,
then an eight-byte big-endian body length and exact raw
body bytes. Authentication precedes parsing. Body limits are 256..65536 bytes
of configured maximum; exact closed scalar fields are `tenant_id`, `provider`,
`event_id`, `intent_id`, `generation`, `status`, and `observed_at`. Duplicate,
unknown, missing or case-aliased fields and trailing JSON are rejected; status
uses the core receipt classifications and observation time is canonical UTC
RFC3339Nano. No callback idempotency field owns kernel command identity.
Select `EnqueueConfig.Receipts` with `ReceiptAuthenticationConfig` and enable
`StateTracking`; install `ReceiptVersion` and `ReceiptCommandVersion` first.
Nil leaves callbacks disabled and preserves installed enqueue plan identity.
Selected missing schema or a key profile absent from the retained custody
provider versions fails closed before deployment registration. Configuration
copies credentials, supports overlapping keys, and needs no consumer verifier.

Callbacks automatically select receipt-aware status. To retire callback keys
while continuing to read retained acceptance/bounce evidence, set `Receipts`
to nil and `ReceiptTracking` to true. This metadata-only selection requires
`StateTracking` and `ReceiptVersion`, grants no callback authority, and fails
closed before registration when the schema is absent. Status and its version
come from one database snapshot; generation-scoped evidence does not rewrite
original worker completion results or override later durable terminal states.
Nil callbacks with tracking disabled retain legacy schema requirements.

`EnqueueService.RecordReceipt` accepts `ReceiptCommandRequest`: trusted binding
and current actor policy plus untrusted `SignedReceiptCallback` and the original
status-version fence. The signature selects the configured provider service
account, not arbitrary human authority. Tenant/effect/user, retained provider
version and current policy must match before kernel reservation. Caller
`delivery.*` attributes are rejected; owned provider/version/generation/intent
attributes reach policy. Receipt effects, protected audit and lifecycle commit
atomically under the existing kernel coordinator. No Sender or provider query
runs in this operation.

Retain command identity, body and fences on retry. A freshly signed identical
body can recover the same original result; signing time/key rotation is not
another domain event. Raw callback/signature/event IDs never persist in the
command journal. Changed evidence conflicts. Exact committed replay returns
the immutable original result, not a later provider state, after current key
and policy checks. Unknown/in-progress returns `ErrOutcomeUnknown`, never
permission to fabricate another command. A post-commit authentication/policy
denial returns no result; retry the same command after authority is restored.
The 1..5-second service timeout covers the whole operation; the caller's earlier
deadline wins. Public configuration/callback/request diagnostics are redacted
and JSON serialization is rejected. This is not yet complete Queue processing
or provider-specific callback interoperability.

`MigrationSource.ReceiptVersion` optionally appends immutable redacted provider
event checkpoints after `StateVersion` and any selected `CancellationVersion`.
Cancellation is not a prerequisite; zero preserves all installed migration
bytes. The migration creates a provider-bound unique index on populated intents
and a bounded evidence table with attempt/effect foreign keys. It takes schema
locks and scans the existing intent index under 5s lock/30s statement timeouts;
plan an appropriate migration window. It performs no custody backfill and has
no destructive down migration. Application roles must not own DDL or disable
its immutability triggers.

The private borrowed effect phase uses the deployment's existing immutable
namespace key, HMAC event/evidence identities, and intent-before-processing
locks. It applies the core receipt policy atomically with erasure and an
immutable event result. Identical events under another kernel command replay
their original redacted state, not the later current delivery state. Changed
evidence conflicts. No raw event ID, callback body, recipient or provider
reference is retained. Evidence fingerprints preserve exact authenticated
timestamps; comparisons normalize to PostgreSQL microseconds. Conflicting
states within one microsecond fail closed rather than invent an event order.

Definitive acceptance/terminal observations fence competing workers; unknown
observations retain the unchanged live owner so its attributable completion
can still settle the effect. Neither path renews leases or resubmits work.
Recorded worker completion replay remains unchanged after later receipts.

`MigrationSource.ReceiptCommandVersion` adds original-command result projections
after a selected `ReceiptVersion`; cancellation remains optional. It does not
rewrite earlier migration bytes or queued custody, and has no destructive down
migration. The private native participant binds event/evidence HMACs, provider,
generation, normalized observation and status version in a closed kernel command.
Raw callback IDs never enter that command. Its result, event checkpoint,
protected audit, lifecycle, worker fencing and custody erasure commit together.
Earlier or duplicate observations still record one protected version transition;
exact kernel-command replay never reruns that transition. Recovery inspects the
immutable original-command binding, not current delivery state. Result records
have neither a lease nor independent execution/replay authority.

The native participant is not itself a public endpoint; `RecordReceipt` owns
authentication, current policy and original-result disclosure. Receipt-aware
public status projection, reconciliation and retention/role/release proofs
remain unfinished. Checkpoints cannot presently be deleted;
retention/lifecycle completion must be resolved before production adoption.

`PrepareEnqueue` derives the native command's primary effect ID; its
`EnqueueCommand` freezes every safe effect field and confidential logical digest,
without exporting ciphertext or rendered content. `NewEnqueueContributor`
supplies the native execution phase. Enlist it before audit and lifecycle,
and enlist its exact borrowed ciphertext `Contributor` separately and last.
Both phases use the same kernel coordinator Work. Stage the original preparation
through the exact registered ciphertext contributor before commit: missing
custody rolls back all delivery and lifecycle effects. The native phase validates
its borrowed descriptor/profile, not cross-phase pointer identity; a distinct
configuration-compatible custody instance is accepted by this trusted seam.
The eventual Queue must construct both phases with the same custody instance.
The kernel retains a classified failure audit after proven rollback, never a
successful enqueue audit. This trusted composition seam does not authenticate
callers or implement Queue admission; the eventual owned Queue must supply that
orchestration rather than require consumer-written workflows.

The private owned enqueue executor now builds that protected declaration,
reserves the original command, invokes the native phase, stages custody and
commits through the same coordinator. It requires current authorization for
the exact actor, tenant, user resource, action and configured policy revision
before any reservation, including committed replay. Policy failures and panics
fail closed without leaking diagnostics or reserving a command. It starts no
provider work or automatic retries. This component accepts already-prepared
custody; recipient discovery, authorization before encryption, scoped keyed
admission and retained versioned policy still belong to the unfinished Queue.

Its private `Admit` path now validates and snapshots explicit owning-workflow
inputs, requires every referenced retained provider/policy, and derives bounded
recipient-scope, purpose, exact template-version and provider-policy attributes.
Caller attributes cannot shadow the reserved `delivery.` namespace. Current
exact-scope authorization is required before encryption and rechecked before
reservation, including replay. A policy change during preparation leaves no
command claim. These explicit inputs are trusted workflow output, not client
JSON or proof that an address belongs to a subject. Recipient discovery, scoped
keyed deduplication and complete public Queue/result composition remain pending.

The owned workflow will authorize and prepare rendering before opening the
original identity transaction. Recipient, locale, subject, body and content
type are encrypted through `go-secret-envelope`; this module does not implement
an encryption algorithm. Canonical non-secret AAD binds deployment, original
command, tenant, human/service actor, user/resource, command schema/policy,
effect/index/purpose, template version, provider configuration, delivery policy,
original expiry, no-op classification and retained fingerprint-key version.

A domain-separated HMAC binds the confidential logical payload independently
of randomized ciphertext. A separate HMAC domain attests the exact envelope
and frozen scope, allowing the enlisted persistence phase to validate prepared
custody locally without invoking KMS or a provider under transaction locks.
Neither attestation nor shape validation authorizes a workflow or a recipient.
Decryption is performed outside the lease transaction, under a bounded context
whose deadline cannot exceed the original expiry. Key-provider cancellation
and prompt entropy completion are required by the upstream service contract.

Inputs are bounded before encoding/cryptography: plaintext encoding is at most
262144 bytes and persisted custody at most 524288 bytes. The private versioned
DTO is explicit sensitive persistence input, not diagnostic serialization.
Temporary plaintext byte buffers are cleared after use; immutable Go strings
and caller-owned copies are not claimed to be securely erased from memory.

Envelope and fingerprint keys are versioned independently. Retain every referenced
key while ciphertext or replay evidence needs it. Missing retained keys fail
closed; they do not authorize regeneration, altered plaintext or a new command.
Rotation cannot change the retained template/locale snapshot or expiry.

Worker recovery reconstructs the original scope from the installed 28-field
`identity-delivery-payload-v1` AAD profile, rather than introducing a second
command authority. The reader is bounded to 16KiB and requires the exact
canonical field set, numeric spelling, digest and expiry. Its framing is pinned
to `go-secret-envelope` revision `22fc4a2d925d`, `context.go`; a canonical rebuild
through that module's public `NewContext` must match byte-for-byte. Changes to
that upstream encoding require an explicitly versioned persistence migration,
not reinterpretation of installed rows. Restored scope is authenticated locally
against retained custody before decryption; parsing alone grants no authority.
Restart and key rotation cannot renew original expiry. This recovery foundation
does not acquire a worker lease or permit provider work.

## Public composition

Construct `NewContributor(ContributorConfig, *secretenvelope.Service)` with
retained nonzero fingerprint keys, the active envelope key, a bounded preparation
timeout and retained provider/policy profiles. The contributor borrows the
secret-envelope service; callers own its lifetime. Configuration is copied,
concurrent preparation is supported, and each original Work remains serial-use.

Install `MigrationSource{Base: identitypostgres.MigrationSource{}, Version: 10}`
through the public go-migrations Runner/PostgreSQL backend in the kernel's same
migration ledger. If other owned migrations already extend that history, supply
the complete base and an unused higher version instead. Existing kernel SQL and
checksums are preserved. Install audit/lifecycle/outbox dependencies through
their owned migration sources; this module supplies no destructive down SQL.

Select `WorkerVersion: 11` (or an unused version above `Version`) to append the
delivery-domain attempt extension. Zero preserves the previous admission-only
history and its checksums. The extension creates bounded lease/generation and
confidential outcome checkpoints; it does not activate a complete public Queue.
Migration lock/statement budgets are 5s/30s and failure rolls back atomically.

An owned authenticated workflow calls `Contributor.Prepare` before opening the
original transaction. `PreparedDelivery.Plan` returns independent safe metadata
for `CommandPlan.Delivery`; enlist the exact contributor pointer last. After the
coordinator begins the original Work, `Contributor.Stage` copies frozen ciphertext
into it. Commit invokes this participant and persists intents and safe outbox
handles atomically with the original domain mutation, audit and lifecycle effect.
On any staging failure, the workflow must abort rather than commit a prefix.

Preparation accepts 1..16 strictly increasing effect indices, validates the whole
batch before key-provider work and enforces a 1MiB aggregate budget. The earlier
caller deadline, configured timeout or original expiry wins. Preparation does
not authorize a caller/recipient, discover an address, render a template or issue
a token. These remain owned feature-workflow responsibilities, not consumer-written
stores. Foreign preparation owners or original bindings are rejected; a successful
Stage is provisional, not an enqueue receipt or provider outcome. Public config,
input and preparation diagnostics are redacted and serialization is forbidden.

## Persistence and remaining implementation

The private owned identifier-admission path authorizes before reading the owned
primary directory, selects an exact canonical email or phone record, and derives
its recipient scope digest. Caller addresses cannot replace that record.
Pending identifiers are eligible only for address-verification purposes; revoked
identifiers and inactive owners deny. The native command freezes identifier and
authority versions, then checks them under share locks in the original kernel
transaction before encrypted custody commits. Rename, removal and blocking
between discovery and application cannot enqueue a stale recipient. Existing
explicit trusted-workflow preparations retain their original encoding.
This is not yet a public Queue or authentication endpoint; complete public
scope acquisition, status, cancellation and provider lifecycle are still pending.

Select `KeyedVersion` strictly above `PolicyVersion` to append scoped request-key
to original-command mappings. The private owned admission path authorizes before
allocation, then encrypts/stages under the selected original coordinator command.
Concurrent matching candidates and restarts retain one command; changed content,
scope metadata, expiry or correlation conflicts instead of creating a second
delivery. Mapping allocation is not an enqueue receipt or execution evidence.
Only digests and safe random command IDs are stored; no raw key, recipient or
body is indexed. Lost allocation acknowledgement is unknown and resolves using
the same key. The immutable deployment lookup-key identity rejects settings
that would split the namespace. Online namespace-key rotation and retention
retirement remain pending; envelope and existing confidential custody keys keep
their separate rotation contract. Allocation MAC-binds the original custody
fingerprint-key version: restart with a new current version uses the retained
original key for coordinator replay; a missing original key fails closed rather
than changing the command fingerprint. Recipient discovery and full public Queue
composition are still unfinished, not application-written store responsibilities.

Select `PolicyVersion` strictly above a selected `WorkerVersion` to append the
immutable deployment/version policy fingerprint registry. Zero preserves the
old admission/worker history byte-for-byte. The private owned composition
registers a copied, bounded set of retained runtime settings atomically;
same-version reinterpretation conflicts, including changes to operation or
lease budgets. Rotation adds versions without changing old retry decisions.
Workers selected by retained version cannot claim, complete or renew another
version's effect, even when the settings happen to match. Missing versions
fail closed. Database guards reject ordinary update, delete and truncate of
policy identities; privileged DDL/bypass is not covered by those guards.
The complete Queue must still select and require that original registry entry
before encrypted admission and recover its exact version during processing.
This registry does not enable a public Queue or provider integration.

The owned intent table references the original kernel command and retains its
complete canonical non-secret AAD and confidential logical digest. Prepared
ciphertext is authenticated locally before any SQL. Effect IDs are deterministic
under deployment, tenant, original command and class/index. The outbox writer
is consumed through its public immutable `PrepareInsert`/`Statement` API and
the original Work; this adapter never opens or closes a second transaction.
Outbox messages carry only safe handles, not another copy of ciphertext.

Concurrent matching admissions converge on one retained intent/outbox entry;
new encryption randomness does not change logical identity. Changed frozen
inputs conflict. Terminal states require ciphertext/key-reference erasure in
the same update and cannot become sendable again. An expired submitted or
outcome-unknown effect may erase custody without fabricating a terminal provider
outcome. The database records an immutable erasure checkpoint, keeps replay
evidence and denies restoring ciphertext. No-op intents are terminal
cancelled rows without custody, with the same safe-handle admission path;
workers must recognize these as non-sendable. Retained intent bindings, not
prunable outbox payloads, supply contributor recovery evidence. The schema
currently prohibits deleting/truncating replay bindings; final retention and
legal-hold retirement remain unfinished. Recovery does not reconstruct a
kernel success receipt or perform provider work.

Private processing now claims one tenant-bound effect with database-time
skip-locked fencing, commits its attempt before decryption and invokes no Sender
under a transaction. Lost leases become outcome-unknown, never blind retries.
Completion reuses the public bounded retry policy, generation-CASes scheduling
and erasure together, and fingerprints private evidence for exact replay.
The first attempt pins the runtime retry/lease configuration digest; later
claims/completions reject changed settings rather than reinterpret its policy.
Admission-time retained policy registration still belongs to the unfinished
authenticated Queue composition, not this private worker seam.
Private heartbeat uses database time and the same intent-before-processing lock
order as completion. It renews only the exact live worker/generation with the
retained policy; credential expiry and the original attempt's 60-second maximum
remain absolute bounds. It never creates another attempt or resets its start.
Cancellation requests stop renewal. A lost renewal acknowledgement is unknown,
not permission to keep invoking a provider. Explicit worker release records an
uncertain invocation for reconciliation and replays its original result; it
never schedules a retry. Proven no-invocation uses the existing completion path.
Neither method creates a background heartbeat goroutine or replaces the generic
workflow/outbox lease APIs. Public worker composition is still unfinished.
Acceptance is retained as acceptance, not delivered; original expiry erases
custody without fabricating provider failure. The private store is not an
application-provided adapter or a usable public Queue. The generic workflow and
outbox remain their public owners; this extension owns only delivery effects.

The complete owned Queue, authenticated workflow admission,
workflow-level idempotency scope, public worker lifecycle, receipt-aware status,
reconciliation, complete Queue cancellation and final retention are unfinished.
Real PostgreSQL owner-level tests cover transactional rollback, concurrent
duplicate admission, randomized-custody replay, original-command FK isolation,
outbox failure rollback and terminal erasure. They do not yet prove full public
Queue processing, recovery invocation or provider interoperability. Real public
coordinator tests additionally cover installed-history replay, atomic commit,
no-op custody erasure, foreign binding denial and delivery-failure rollback with
the actual owned audit/lifecycle adapters. Quick-start/API examples will accompany the usable
public adapter, not ask consumers to implement its missing stores or workflow.

Exact coverage/mutation, complete PostgreSQL composition, provider interoperability,
clean-consumer and remaining release checks are pending.

`MigrationSource.ReconciliationCommandVersion` optionally extends
`ReconciliationVersion` with immutable original-command results. It must be
strictly greater; zero retains every installed checksum. The private protected
participant applies already-authenticated evidence under the sole identity
coordinator, with generation/step/status fencing and atomic receipt, progress,
erasure, audit and `delivery.reconciled.v1` lifecycle effects. Exact kernel replay
returns its historical result; abandoned command recovery consults primary
participant evidence. This is not a public reconciliation endpoint or an
independent journal. Provider querying, recoverable raw-cursor custody and
authenticated public Queue composition remain unfinished.
