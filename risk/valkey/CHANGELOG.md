# Changelog

## Unreleased

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
