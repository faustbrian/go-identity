# Privacy snapshot V1

This profile implements the snapshot/fragment integrity requirements of the
identity-platform lifecycle specification. It is not a portable export server.
Source snapshots are immutable integrity evidence, not current eligibility.

## Signed request intent

`PrivacyExportRequestCommand` is the distinct kernel command for full-subject
`identity-portable-json-v1` admission. It freezes all 23 ordered contributor
projection declarations, expected identity/authority/privacy versions, exact
human/session binding, policy/schema/correlation and artifact limits. It accepts
1 MiB..1 GiB and whole-second TTLs of 15 minutes..7 days. No caller checkpoints,
export ID, custom scope or format are accepted: the locked durable owner must
allocate the export and next privacy epoch and capture the cuts.

`PrivacyExportIntentDigest` hashes the domain
`identity-privacy-export-request-v1`, zero byte and a definite CBOR array of 20
items: command/tenant/user/actor IDs, actor kind, operation, policy ID/version,
schema ID/version, correlation ID, expected identity/authority/privacy versions,
session ID/version, maximum bytes, artifact TTL seconds, fixed format, and an
array of `[contributor ID, projection ID]` pairs. Integers use shortest unsigned
encoding; strings use definite UTF-8 text. Record ID and link mode must be empty.

`BuildPrivacyExportProofPayload` prepares, but does not sign or authorize, a
non-bearer one-use capability with exactly one audience and one caveat,
`intent_digest` in lowercase hexadecimal. Subject/resource are the exact user;
tenant/operation are literal bindings. Its whole-second validity interval is
at most five minutes. Only trusted composition may issue after current policy
and fresh human/session checks. `NewPrivacyExportRequestCommand` checks the
verified grant's exact metadata and copies inputs; it does not establish issuer
trust, time validity, freshness or consume anything.

This command currently has **no execution mapping or admission service**.
The constructor cannot fabricate original opaque proof custody. Snapshot V1 wire IDs remain
strictly canonical 128-bit; imported directory ID mapping is an unfinished
admission prerequisite, not permission to rewrite imported identity IDs.

## Queued admission receipts

`CommandResult.PrivacyExport` is the exclusive committed request receipt branch;
nil is omitted from JSON to preserve every prior receipt representation. It
retains the complete snapshot record so JSON replay does not lose the opaque
snapshot's data. `CommandResult.Validate` checks the exact request binding,
complete structural snapshot, positive authority version, overflow-safe next
privacy epoch, bounded artifact policy and nonzero intent/integrity digests.
It rejects other kernel/feature payloads and any request status except queued.
The immutable request result must never become ready when a worker later finishes.

`ValidatePrivacyExportRequest` additionally matches every request binding,
captured identity version, authority/privacy fences, artifact policy, projection
profile and intent digest, then verifies the snapshot with its retained evidence
key. Its returned snapshot owns copied metadata. Known not-committed, conflict,
unknown and in-progress outcomes return no snapshot and do not need an unused
evidence key; they still require exact binding and a clean outcome shape.
Grant verification is not repeated here: recovery matches the original intent
after proof expiry without consuming it. No caller may treat either validation
method as proof of authorization, actual commit, cut provenance or publication.
Those facts still require the platform-owned service and locked durable adapter.

## Adoption

Trusted secret composition supplies `NewPrivacyExportEvidenceKey(version,
material)` with an independent random 32-byte key and positive version. The
constructor copies bytes, rejects all-zero material, and does not prove entropy
or provenance. Keys are redacted, immutable and concurrent-safe. Their retention
owner must retain old versions for every surviving snapshot/evidence record;
never re-sign an old snapshot during rotation. Go cannot guarantee zeroization
of all copies; this API makes no such promise.

The identity command's primary-authority transaction must construct the entire
`PrivacyExportSnapshotSpecV1`: exact scope, random export/command IDs, positive
identity version/privacy epoch/lifecycle sequence, UTC Unix microseconds and
every ordered contributor cut. `SealSnapshotV1` validates, copies and authenticates
it. It performs no IO or authorization and cannot prove the caller captured
the cuts correctly. Persist its `Record` in that same transaction; a commit
whose outcome is unknown must not start an export or allocate a replacement ID.
Reconstruction uses `VerifySnapshotV1` with the **recorded** retained key version;
unknown keys or any modified metadata deny, not default or upgrade.

V1's lifecycle wire profile requires canonical nonzero 128-bit IDs encoded in
22 unpadded base64url characters for export, tenant, subject and command.
This restriction does not rewrite or normalize imported canonical directory IDs.
The imported-ID/export-scope reconciliation remains required before enabling
privacy export for a directory profile outside this wire representation.
No existing directory API is restricted by this additive construction API.

## Registered closed cuts

`PrivacyExportContributorsV1` returns all 23 semantic owners in ASCII order,
including `identity/i18n`. Storage adapters are not additional contributors.
The entire set is required even when a contributor has no data. Missing/extra/
duplicate/out-of-order members fail before evidence construction.

Contract, checkpoint and fragment schemas are fixed at 1.0; manifest is 1.
`subject-journal-v1` names a contributor-owned append-only full-subject cut;
`staged-subject-fragment-v1` names an immutable full-subject fragment staged in
the request transaction. These are storage-neutral registered enums, not SQL
names. Each projection commits an initial empty position **1**, then advances
monotonically with its subject-scoped authoritative mutations. Zero is invalid.
No timestamp, aggregate CAS, replica position or current read substitutes for
the checkpoint. Each contributor must implement its chosen projection and
exact-cut visibility/retention before composing runnable export admission.

The V1 closed scope selector is `["subject"]` for every contributor; the tuple
also explicitly binds tenant, subject and semantic contributor. It selects all
exportable subject data in that contributor, not an arbitrary named resource.
New selectors/projection semantics require an explicit versioned profile change.

## Canonical bytes

The codec implements only these closed tuples, not a general CBOR parser. It
uses RFC 8949 definite arrays, shortest integers/lengths, UTF-8 text for canonical
IDs/enums and byte strings for fixed digests. No maps, floats, tags or arbitrary
fields are admitted. Tuple order is fixed and meaningful.

Scope HMAC input is ASCII `identity-privacy-export-scope-v1`, one zero byte and
CBOR `[tenant_id, subject_id, contributor_id, ["subject"]]`.

Snapshot HMAC input is ASCII `identity-privacy-export-snapshot-v1`, one zero byte
and the 13-item CBOR tuple:

```
[schema_major, schema_minor, export_id, tenant_id, subject_id, command_id,
 identity_version, privacy_epoch, lifecycle_sequence, manifest_version,
 requested_at_unix_microseconds, contributor_bindings, evidence_key_version]
```

Each binding is the exact eight-item array:

```
[contributor_id, contract_major, contract_minor, projection_id,
 scope_key_digest, checkpoint_major, checkpoint_minor, checkpoint_position]
```

The snapshot digest itself is omitted from MAC input. Verification checks all
versions, IDs, positions and recomputed scope digests before the snapshot MAC;
MAC comparisons use `crypto/hmac.Equal`. Metadata is under 4 KiB for this closed
profile. Caller mutation during a call is forbidden; afterward every snapshot
and returned record is independently owned. There are no locks or goroutines.

## Fragment boundary

`ValidateFragment` requires the same export/tenant/subject/command, privacy epoch,
key version, snapshot digest, contributor/contract, projection/scope digest,
requested and observed checkpoint, fragment schema, classification, actual byte
length and SHA-256 of actual canonical content. The explicit byte maximum must
be positive and at most 1 GiB; bounds precede synchronous hashing. Callers own
the bounded bytes and must not mutate them concurrently. This pure function
does not perform streaming IO and does not hide retries or cancellation work.

`data` requires nonempty content. `not-applicable` requires exactly zero bytes
and SHA-256(empty), but remains an assertion requiring the contributor's exact-
cut absence proof. Silence, missing keys, timeout or unavailable projections
cannot be converted into absence. Metadata/digest checks do not prove canonical
JSON, content schema, redaction or actual checkpoint visibility; each registered
contributor and composed coordinator must prove those independent obligations.

Typed snapshot/spec/record/fragment/key formatting is redacted. Exported metadata
is pseudonymous personal data intended for controlled persistence and must not
be logged. The final artifact is still the specified bounded uncompressed
redacted UTF-8 JSON, never this CBOR integrity tuple.

## Verification and remaining scope

Tests exercise complete manifest admission, tampering, copied storage, numeric/
timestamp boundaries, official RFC integer/length examples, an independently
encoded scope tuple, exact fragment metadata/content and absence classification.
Fuzz tests exercise hostile scope/cut reconstruction. This does not certify
general CBOR interoperability, durable reads, atomic admission, final epoch
rechecks, contributor privacy schemas, object encryption, downloads, erasure,
retention/holds or composed lifecycle closure. Their implementation and exact
release/coverage/mutation gates remain required.
