# Changelog

## Unreleased

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
