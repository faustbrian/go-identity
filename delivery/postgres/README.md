# Identity delivery PostgreSQL

**Under development.** This module does not yet expose a production Queue.
It currently implements its private authenticated payload custody boundary;
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

The owned Queue, authenticated workflow admission, original-command outbox
insertion, migrations, dedupe, lease/generation fencing, attempts, authenticated
receipts, reconciliation, cancellation and terminal erasure are unfinished.
No provider delivery, database durability or interoperability is claimed by
the custody unit tests. Quick-start/API examples will accompany the usable
public adapter, not ask consumers to implement its missing stores or workflow.

Exact coverage/mutation, PostgreSQL composition, provider interoperability,
clean-consumer and remaining release checks are pending.
