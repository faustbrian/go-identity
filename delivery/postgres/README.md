# Identity delivery PostgreSQL

**Under development.** This module does not yet expose a production Queue.
It currently exposes authenticated preparation, immutable migration history and
original-command staging through the kernel's exact enlisted delivery contributor;
it must not be selected as a working durable store or provider integration.

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
