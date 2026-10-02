# Changelog

## Unreleased

- Add bounded decoding of immutable historical command scope for primary
  recovery composition, preserving original policy/schema versions and exact
  identifiers. Alternate or corrupt encodings fail closed; public command
  lookup and reconciliation remain under development.

- Persist declared versioned scalar/list attributes atomically with user
  creation, preserving empty values, full int64 values and exact UTC instants.
  Registered schemas are copied and immutable within a tenant/version; changed
  definitions and undeclared fields fail closed. Migration 6 preserves old
  structural users without fabricated defaults. Indexed/secret profiles and
  public field projection remain pending, never plaintext or silent fallbacks.

- Add single-use Coordinator.Begin, enlisted structural user creation and
  Commit/Abort. Successful creation commits the user, required audit, lifecycle
  effects and terminal receipt together; failed prefixes roll back. Forged
  receipts, missing evidence, foreign handles and expired ownership fail closed.
  Known denial requires matching atomic audit evidence; commit ambiguity stays
  Unknown. Full attributes, recovery and the UnitOfWork bridge remain pending.

- Add primary Coordinator reservation for user creation with mandatory typed
  audit/lifecycle plans, retained-key replay and opaque generation ownership.
  Forward migration 5 freezes the exact canonical plan in the command journal;
  changed plans conflict and legacy NULL plans fail closed. Reservation never
  claims a user mutation; domain execution and scoped recovery remain pending.

- Add typed lifecycle staging, stable command/class/index effect IDs and
  outbox phase admission. Safe scalar-only events must match the successful
  audit's aggregate/version transition; no payload secrets or external-success
  claim is admitted. Durable outbox/Coordinator execution remains pending.

- Expose complete owned audit-staging snapshots and an open AuditContributor
  persistence phase for same-transaction adapter composition. Snapshot access
  never conveys commit authority or a durable receipt.

- Add bounded kernel CommandPlan digest and private registry-bound admission.
  Command scope, authoritative fingerprint, ordered contributors and every
  audit declaration are frozen before execution; changed inputs and foreign
  Work are rejected. Typed feature inputs and public Coordinator remain pending.

- Add pre-SQL required kernel audit plans and Work.StageAudit with exact
  binding, profile, byte-budget, duplicate and lifetime enforcement. Builder
  event IDs and outcome classifications are preserved. This stages owned
  records only; durable contributor delivery and Coordinator commit enforcement
  remain unfinished.

- Add generation-bound Work SQL execution with owned result cursors, exact
  scope, conservative lease deadlines, closed scalar parameters/destinations,
  bounded results and failure poisoning. Extended-protocol execution rejects
  multi-statements without exposing raw connections or transaction closure.
  Work issuance, mandatory audit/effect staging and the public Coordinator
  remain under development; this is not yet an adoptable command pipeline.

- Add private domain-begin fencing against the exact retained-key command,
  pending generation and lease owner. Database time is read after lock waits
  so expired, stale and terminal reservations cannot reenter domain work.
  Complete public Work/Coordinator and participant staging remain unfinished.

- Add immutable, bounded contributor identity registration with exact-version
  admission, duplicate rejection and owned descriptor snapshots. The open
  interface is implementable by independently owned adapters; transaction
  phases and the public Coordinator remain under development.

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
