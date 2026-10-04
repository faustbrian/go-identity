# Identity delivery PostgreSQL

**Under development.** This module does not yet expose a production Queue.
It currently implements private authenticated payload custody and original-command
intent/outbox admission through the kernel's exact enlisted delivery contributor;
it must not be selected as a working durable store or provider integration.

## Custody and security

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

## Remaining implementation

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

The owned Queue, authenticated workflow admission, public migration installation,
workflow-level idempotency scope, lease/generation fencing, attempts, authenticated
receipts, reconciliation, cancellation and terminal erasure are unfinished.
Real PostgreSQL owner-level tests cover transactional rollback, concurrent
duplicate admission, randomized-custody replay, original-command FK isolation,
outbox failure rollback and terminal erasure. They do not yet prove full public
Queue/coordinator composition, lease processing, recovery invocation or provider
interoperability. Quick-start/API examples will accompany the usable
public adapter, not ask consumers to implement its missing stores or workflow.

Exact coverage/mutation, PostgreSQL composition, provider interoperability,
clean-consumer and remaining release checks are pending.
