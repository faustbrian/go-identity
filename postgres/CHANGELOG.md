# Changelog

## Unreleased

- Persist versioned terminal command receipts with generation/owner/lease
  fencing and immutable committed/aborted replay. Unknown remains a caller
  observation. This private journal phase does not provide the unfinished
  public Coordinator, mandatory audit or atomic participant orchestration.

- Add durable pending command leases with database-time heartbeats, rollback-safe
  generation takeover and stale-owner fencing. Foundation-only rows retain
  unclassified metadata and fail closed. Full participant rebinding, terminal
  receipts and the public Coordinator remain unavailable.

- Complete typed canonical encoding of account link/unlink and identifier
  mutations, binding version fences, proof authority and continuation choices
  while keeping provider/identifier values and private proof caveats digested.
  Encoding does not consume proofs or provide the unfinished Coordinator.

- Add private deterministic command encoding for creation, field updates,
  profile changes and status transitions, with framed private-field digests
  and stored-key regeneration during replay. Remaining command variants and
  the public Coordinator are not yet available.

- Add the global command-ID claim and scoped journal foundation with retained-
  key replay checks, scope collision rejection and retired-ID tombstones.
  This private admission step is not yet a complete Coordinator or command API.

- Supply immutable forward-only user schema migrations through `go-migrations`,
  enforcing tenant/user uniqueness, bounded case-sensitive IDs, registered
  lifecycle states and full-width positive integer versions without rounding.

- Add bounded primary tenant/user reads with lossless uint64 version decoding,
  strict projection validation and redacted failure classifications. This
  initial development adapter does not yet include its durable mutation
  coordinator and is not ready for adoption.
