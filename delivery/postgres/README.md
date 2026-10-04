# Identity delivery PostgreSQL

**Under development.** This module does not yet expose a production Queue.
It exposes public durable admission through `NewEnqueueService`, authenticated
preparation, immutable migration history and original-command staging. Admission
is not a complete durable Queue or provider integration.

## Public admission

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

## Custody and security

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
workflow-level idempotency scope, public worker lifecycle, authenticated receipts,
reconciliation, public cancellation and final retention are unfinished.
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
