# Changelog

## Unreleased

- Separate explicit recovery fence initialization/renewal from per-record
  restoration. A disappeared live fence now denies restoration without writes
  or acknowledgement instead of silently reinstalling it. Initialization
  retains configured scope and current primary checks before and after IO;
  it does not authorize resumed applied progress or public activation.

- Require the exact independently retained confirmed marker before native
  debit or replay; reject historical epoch-only requests. Bracket each effect
  with bounded read-only primary/noeviction/run-identity checks, retaining the
  original eviction baseline and denying after observed profile loss even if
  old metadata returns. Preserve attributable committed outcomes on later
  profile failure while denying admission. Credentials now require INFO.
  These private checks do not complete reset continuity or public activation.

- Confirm only an exact existing published native cut after configured primary
  recorded-confirmation checks. Preserve every original field, counter and
  exclusive expiry; matching retries do not write and missing markers are not
  repaired. Ambiguous effects never trigger resend. This private checkpoint
  does not establish all-counter continuity, public activation or readiness.

- Publish exact primary-covered cuts under an existing original native replay
  fence, preserving keyed cut identity, applied position, coverage and expiry.
  Matching retries do not rewrite state; stale, lost or conflicting fences and
  ambiguous effects expose no publication custody. Bare epoch and merely
  published markers cannot debit. The private mutation engine requires a
  structured, non-expired confirmed marker; paired primary confirmation and
  the production writer of that marker remain unimplemented.

- Reconstruct native restore plans from owned authenticated original history,
  including retained aliases and dimension-addressed snapshots, without a new
  command or raw attempt. Reject unresolved history and missing retained keys.
  Read through the configured public journal verifier rather than a private
  cross-module import; foreign, unconfigured and stale ownership exposes no plan.
  Private native recovery retains its own issuance, derives the matching journal
  verifier, and acknowledges committed history only after exact fenced restore
  and a final primary ownership check. Failed effects expose no acknowledgement.
  Explicit noncommit requires fenced native absence: conflicting/unresolved
  attempt roots or retained directory linkage deny without writes or TTL renewal.
  Public activation and joint primary/native healthy publication remain pending.

- Use the core stable replay identity matching retained PostgreSQL attempt
  bytes, independent of preparation time and dimension-key rotation. The new
  private `irv2` layout rejects old markers rather than silently treating them
  as reconstructible history. Original-intent conflicts remain non-debiting;
  authenticated recovery composition and public activation remain unfinished.

- Add private native recovery fencing and committed-snapshot restoration.
  Exact owner/generation and logical expiry reject stale recovery effects;
  restoration preserves cumulative counts, original windows and replay expiry
  without debit or healthy publication. Journal composition remains pending.

- Wire the private standalone counter transport to the native client with
  verified TLS, bounded physical connections, pre-allocation response framing,
  cancellation and joined shutdown. Ambiguous outcomes never trigger resend;
  acknowledged cancellation errors preserve outcome without leaking diagnostics.
  Public activation, recovery and real-server interoperability remain pending.

- Add private bounded RESP2 framing that rejects hostile length declarations and
  partial frames before an allocating client parser can receive their headers.
  Native client wiring and real-server proof remain pending.

- Add the private native multi-dimension fixed-window Lua debit: preserved
  logical roots across retained digest versions, original replay snapshots,
  exact window boundaries, bounded replay capacity and pending-result fencing.
  Offline script execution is covered; real Valkey and recovery remain pending.

- Add private bounded dispatch classification: no retry after ambiguous transport
  outcomes, preserved commit truth after cancellation, and no positive admission
  from unhealthy epochs. Real Valkey transport and mutation remain unfinished.

- Add bounded preparation for native ephemeral risk commands: exact retained
  key/policy custody, keyed same-slot tenant partitions, immutable replay
  identity and strict post-mutation reply validation. Native counter mutation,
  journal-fenced recovery and public store construction remain unavailable.
