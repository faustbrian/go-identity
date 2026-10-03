# Changelog

## Unreleased

- Add opt-in native consuming-command preparation authenticated against the
  installed issuer's complete original recovery scope and provider configuration.
  Mismatched policy or retained signing/linkage keys fail setup. Raw scope remains
  only in the opaque in-memory command, not the signed plan or journal; historical
  check times and expiry are preserved. This does not activate domain execution;
  current-counter checks and atomic journal finalization remain required.

- Recheck original protected-counter charge custody and locked current windows
  before domain mutation and final commit. Expired original evidence, missing
  snapshots, changed key history or missing original aliases deny without a new
  charge or allowance reset. Exact takeover and retained-key rotation preserve
  current admission. Lockout/override policy remains separate unsupported work.

- Add opt-in native protected-command counters with primary-time fixed windows,
  saturating counts, retained-key rotation continuity and original command-linked
  snapshots. Replay and exact owner takeover never charge again; denied attempts
  remain charged with their failure audit and receipt. Charge linkage supports
  noncommit reconciliation without claiming a domain commit. Install the additive
  `CounterMigrationSource` after evidence reservation history. Domain admission,
  lockout policy, key retirement and bounded pruning remain pending.

- Reconcile native initiation reservations and terminally release them only
  after unanimous authoritative noncommit proof through the shared coordinator.
  Exact historical custody survives policy changes and expiry without granting
  new use; unknown or mismatched evidence stays reserved. Release, failure audit
  and aborted receipt commit together. Upgrade the coordinator dependency before
  enabling recovery; domain apply/finalize and phone orchestration remain pending.

- Add native initiation reservation and exact-generation takeover through the
  sole identity coordinator. Signed use, current risk policy, complete stored
  linkage and post-lock primary expiry are checked before ownership; missing or
  conflicting custody cannot create a journal or durable command prefix.
  Historical issuance replay preserves its original response after legitimate
  reservation/terminal states. Install the reservation migration and upgrade
  the executor before enabling this profile. Protected domain execution and
  completion's OTP/capability phases remain unsupported.

- Add the forward-only reservation-state migration after the existing issuance
  history. Populated legacy and opaque evidence retains its original encrypted
  response and expiry; ownership is initially absent and is constrained to one
  complete same-tenant command/fingerprint/generation binding. This provides
  the journal schema, not executable reservation or consumption authority.

- Accept the canonical production audit contributor alongside the original
  explicitly supported v1 composition identity. Foreign contracts, owners and
  versions remain rejected; production audit/outbox effects share native
  issuance, rollback and original-response recovery.

- Add the official authenticated issuance executor and private primary original
  response resolution. Same-Work issuance, exact-intent replay and retained-key
  rotation preserve original references and expiry; conflicting, pending,
  denied and corrupt histories cannot restart providers or disclose candidates.
  Consumption and complete risk-service behavior remain unfinished.

- Add the native issuance contributor: database-time issued evidence and
  encrypted original-response custody commit atomically with required protected
  audit, lifecycle and command receipt. Locked recovery preserves pending state
  on positive or inconsistent native evidence instead of inferring rollback.
- Use opaque command IDs for new evidence aggregate identities so audit and
  lifecycle projections do not reveal private keyed intent digests. Append the
  issuance-identity migration while preserving existing install bytes and
  legacy encrypted rows; new compositions select the complete forward history.
- Add the signed native evidence-issuance command schema and exact-intent record
  mapping, preserving original evaluation validity and purpose separation.
- Add scope-bound encrypted original-response custody with retained wrapping-key
  rotation, plus the forward-only issued-evidence migration source. Durable
  execution, recovery and one-use consumption remain in development.
