# ID contracts

## API and ownership

`SubjectID` and `PreAuthTransactionID` are distinct comparable string types with
invalid empty zero values. Their constructors (`NewSubjectID` and
`NewPreAuthTransactionID`) read exactly 16 cryptographic-random bytes and reject
all-zero entropy. A failure returns no ID and the corresponding stable entropy
sentinel, without retaining bytes or exposing the provider diagnostic.

`ParseSubjectID` and `ParsePreAuthTransactionID` are bounded reconstruction
boundaries: exactly 22 unpadded base64url characters, exactly 16 decoded bytes,
and at least one non-zero bit. Padding, whitespace, invalid alphabet and alternate
unused-bit encodings are rejected, not normalized. Errors never contain inputs.
`FormatSubjectID` and `FormatPreAuthTransactionID` return an empty string for
invalid values, including invalid explicit string conversions.

`CompareSubjectID` and `ComparePreAuthTransactionID` order decoded bytes and
return -1, 0 or 1. Encoded ASCII order is different and must not replace this
comparison in cursor/storage contracts. Either invalid operand returns the
type-specific invalid-ID sentinel. Values are immutable and concurrency-safe;
these functions start no goroutines and retain no resources.

## Adoption and security

Parse stored/wire values before use; do not treat a Go conversion as validation.
Keep subject IDs distinct from pre-authentication attempt IDs. Neither parsing,
generation nor possession authorizes access, authenticates a person, reserves
a capability or opens a transaction. Bind attempts to the exact tenant,
operation and continuation at the consuming workflow boundary.

These fixed codec contracts do not define the injected owner-ID/import policy
for the shared-issuer directory. Existing canonical identifiers such as ULIDs
must be preserved by that separate policy and mapping boundary; do not force
imported owners through the subject codec or replace their IDs.

## Operations and tradeoffs

Generation uses the process cryptographic-random source, not a counter, wall
clock or pseudorandom fallback. Entropy failure denies generation. There is no
timeout or cancellation parameter in these exact constructor contracts; entropy
availability remains an operating-system concern. The generated representation
is stable but carries no timestamp, tenant or authority information.

## FAQ

- **Can I use a zero ID?** No. Parsing/comparison reject it; formatting returns
  an empty string.
- **Can I compare encoded strings?** Not for decoded numeric/byte order. Use
  the corresponding Compare function.
- **Are IDs bearer secrets?** No. Authorization and replay consumption belong
  to explicit workflow contracts, not these values.
- **Does this implement directory import or login?** Not yet; those remain
  required implementation work in the identity platform.

## Login identifier records and transitions

`IdentifierID` preserves canonical record IDs (including imported ULIDs), not
login values. `Identifier` and `Verification` implement the catalog's separate
record and verification ownership: exact user, closed email/phone/username/
provider-subject kind, bounded canonical/display values, explicit verified and
primary states, and positive independent versions. Tenant scope comes from the
enclosing authoritative `User` partition. Never infer that partition from a
globally-looking user or identifier ID.

`Identifier.Validate` is structural: it does not trim, case-fold, validate email
syntax, normalize phone numbers or prove provider subjects. Feature composition
must use the selected fixed-table, versioned canonical policy before admitting
a value. Canonical and display values are independently bounded to 512 UTF-8
bytes with no C0/C1 controls. Exact provider-subject spaces remain unchanged.
All record/state/change/mutation formatters redact diagnostic output; explicit
data serialization still requires the owning operation's authorization and
field redaction. No bearer or challenge payload appears in these records.

`ApplyIdentifierChange` is the identity-owned pure apply step for a complete
locked primary partition (maximum 128 records, strict ascending ID order,
matching verification order). It returns independent copied collections or
zero mutation on error. Inputs must not be mutated concurrently with a call.
No goroutine, resource, callback, network operation or clock read is started.

- Attach creates pending verification, never primary/verified. Duplicate IDs or
  same-kind canonical values in the partition conflict.
- Verify transitions pending to verified only after the feature owner proves
  the exact subject/value/version-bound challenge. This action is intent, not
  proof. Verification time uses the owner's sampled UTC instant, truncated to
  microseconds; zero/out-of-range persisted instants and future observations deny.
- MakePrimary requires verified state and atomically unsets the previous primary
  **of that kind**, advancing each changed record without renewing verification.
  Email primary and phone primary are independent; primary is not default login
  permission. It is valid to have no primary for a kind.
- Replace preserves record ID/kind and requires a different canonical value.
  It resets verification and primary, advances both record versions, and
  returns original retirement metadata for the old-value reuse decision.
- Remove returns version-advanced, non-primary/unverified retirement metadata
  and revoked verification, then removes the exact pair from the copied state.

All changes advance the user aggregate and identifier authority dimension once,
not the separate user-authentication authority dimension. Exact aggregate,
authority, identifier and verification fences reject stale work and overflow.
Repeated verification/primary selection is a conflict; exact command replay
belongs to the sole durable command owner before apply, not to this function.

### Required durable and feature integration

This is not a public workflow or a durable adapter. Platform-owned PostgreSQL
commands must lock the complete partition and the tenant/kind canonical uniqueness
index, apply current authorization, canonicalization, verification/session/risk
proof and final usable-access policy, then atomically persist apply output,
old-value reuse tombstones, exact lifecycle events, audit and original receipt
with one-use evidence consumption. Lost commit replies require scoped recovery.
Cross-user/cross-command races, tenant uniqueness, cooldown/reuse and account
access are not proven by checking one `IdentifierState` alone.

Retirement metadata is **not** a plaintext tombstone: the adapter must derive a
scoped keyed non-reversible canonical digest and use the configured retention/
reuse policy. It must retain removed record/version authority so callbacks,
imports and old proofs cannot resurrect retired state. Replacement's retired
pair describes the old value; the new record already has the next version.
Legal storage and encryption of current directory values remain separate policy.

Email/phone/username/provider owners must call the platform-owned commands, not
write a second identifier store or require consumers to invent workflow glue.
Their real normalization/challenge/final-access behaviors, feature/pre-auth,
transport and SQL composition remain unfinished integration work.

## Signed current-human commands and recovery

`IdentifierService` admits all five identity-owned transitions through the
existing sole `UnitOfWork`, after current owner authorization and configured
capability signature/issuer/audience/freshness verification. It reads one full,
consistent primary `IdentifierState` of at most 128 records and reauthorizes
against current aggregate/authority versions. A future fence fails before the
owner; a current aggregate is checked by the pure apply function. Older intent
may reach only the durable owner, which must check exact fingerprint replay
before CAS; an older version is never permission to mutate stale state.

These are internal identity commands, not new HTTP routes. The closed command
purposes are `identity.identifier.attach`, `.verify`, `.make-primary`,
`.replace` and `.remove`, each bound to its matching `IdentifierAction`. The
feature APIs retain their catalog operations and exact security/lifecycle event
names; neither a command purpose nor a receipt invents a new external event.
Full Service and typed/protocol/acceptance catalog composition remains pending.

`BuildIdentifierProofPayload` is an unsigned structural builder, not a proof
ceremony or an authority issuer. Trusted feature composition must validate the
actual session, current credential-specific reauthentication, versioned fixed
canonicalization policy, exact value and real verification challenge where
applicable before the configured signer issues. Its spec must never be accepted
as a client claim. Pre-auth registration/verification paths remain required
feature integration; this service exposes only the explicit current-human path.

The signed non-bearer proof is single-use, has exactly one configured audience,
and binds tenant, user, identifier resource, exact action and six caveats:
`intent_digest`, `command_id`, `actor_id`, `session_id`, `session_version`,
`policy_version`. Issued instants have whole-second UTC representation,
exclusive expiry, and at most five-minute lifetime/age (configuration may
shorten it). Verify is read-only: only the owning protected transaction may
reserve/consume/finalize it atomically with risk, state and other participants.

`IdentifierIntentDigest` uses SHA-256 over the UTF-8 domain
`identity-identifier-change-v1` plus a NUL, followed by eleven exact UTF-8
fields, each prefixed by its four-byte big-endian byte length:
tenant ID, user ID, decimal action, identifier ID, kind, canonical value, display
value, expected user version, expected identifier-authority version, expected
identifier version, expected verification version. Decimal integers have no
alternate encoding. This is a signed-intent digest, not permission or a safe
private-value/reuse index. Keyed non-reversible tombstones remain adapter-owned.

Admission and recovery discard all caller `identity.*` resource attributes and
set the exact typed `identity.identifier.id` and action before current policy.
Record-specific denial prevents receipt reads; recovery checks original command,
tenant/user/actor/record/action bindings before disclosure. It never executes or
consumes proof. `IdentifierReceipt` retains the original intent digest in its
protected immutable storage and carries the admitted authority version advance,
not raw identifiers, provider/challenge success or completed cascade. Execute
refuses a returned receipt for a different signed intent; public results never
expose the digest, and diagnostic formatting redacts it.
The immutable `CommandBinding.RecordID` is required even for failed, pending
and unknown receipts. `RecoveryQuery` carries exact operation and record ID,
and the owner and service both match the original scope for every outcome.
Missing historical record scope fails closed; it must never be reconstructed
from the caller's requested record. Non-record command variants omit record fields.
Lost replies/panics after owner entry remain unknown; preserve the command ID
and recover. Cancellation, dependency failure or denied output never reclassify
a known commit as rollback. No goroutines, database transaction or second journal
are created. Dependencies honor bounded contexts and concurrent calls; callers
must not concurrently mutate inputs. Typed command accessors return value copies.

The current test owner proves the non-durable orchestration seam only. SQL must
implement locked state/tombstone history, uniqueness and final signin/recovery
access, replay/crash/unknown recovery, fresh evidence, lifecycle and privacy
participants; consumers must not provide these missing stores or workflow glue.
