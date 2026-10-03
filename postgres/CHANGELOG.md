# Changelog

## Unreleased

- Release exact risk custody during proved nonretryable owner rollback in the
  same guarded transaction as its failure audit and aborted receipt. Live-owner
  release preserves generation, including after takeover; recovery still
  requires unanimous noncommit and a successor. Failed release retains pending
  custody without a durable audit prefix. Domain apply/finalize remains pending.

- Add typed reset-initiation risk recovery and terminal release. Every frozen
  participant must prove noncommit before release, failure audit and aborted
  receipt commit together. Missing phases or unresolved custody retain pending
  ownership; expiry alone never releases evidence. Domain consumption remains
  unsupported until its complete native apply/finalize checks are present.

- Freeze signed reset-initiation risk declarations and enlist exact native risk
  reservation/rebind phases in the command reservation transaction. Failures
  roll back ownership together; existing feature plan profiles remain unchanged.
  Phone domain execution and mutating recovery remain disabled until their
  complete one-use phases are implemented.

- Add separately opt-in, current-authorized primary command admission
  observation for native adapters. Only a genuinely absent global claim is
  reported absent; ordinary lookup retains its enumeration-resistant behavior.
  Historical metadata grants no reservation, rollback proof or native replay
  authority. Adapters still match their retained intent and protected result.

- Add an explicit denial-only credential compromise phase to the existing
  coordinator. Native verifier disablement, reference disablement, independent
  user/credential version successors, protected audit, lifecycle metadata and
  the original replay receipt commit together. An allocated forward migration
  retains kernel recovery evidence; missing or conflicting evidence cannot prove
  noncommit. Credential activation and password set/reset remain unsupported.

- Read exact credential references and independent user credential epochs from
  one bounded primary snapshot, preserving full-width versions and blocked,
  disabled and expired states. Explicit forward `CredentialMigrationSource`
  retains installed history and initializes only the new epoch for old writers.
  Adopt the committed core eligibility port; mutations and proof consumption
  remain separate unfinished phases.

- Persist suspend/ban and restore/unban through the existing coordinator, with
  a separate user-security epoch, locked owner policy, exact pending consumer
  contracts, audit, lifecycle and replay receipts. Primary `GetStatus` never
  derives security authority from profile versions or auto-restores expiry.
  Explicit forward `StatusMigrationSource` preserves installed history and
  initializes epoch 1 without changing existing status or aggregate versions.
  Admission does not claim consumer acknowledgement or completed cleanup.

- Add invocation-only feature scope checks for native adapters and recovery.
  Matching descriptors cannot substitute another enlisted instance, and a
  returned phase cannot reuse its scope to authorize a later native mutation.

- Execute typed native non-one-time feature mutations through the sole command
  coordinator, atomically persisting domain effects, every required audit slot,
  lifecycle and exact replay receipt. Bind subject type and explicit retention
  into a new canonical plan profile; preserve kernel and historical v1 bytes.
  Forged receipts, callback failures and cancellation cannot commit a domain
  prefix. Abandoned recovery requires unanimous retained non-commit evidence;
  ambiguous commits remain unknown. Expose owned multi-slot audit declarations
  only during audit recovery. Production session issuing and one-use proof
  consumption remain separate unfinished phases.

- Observe feature-owned historical command receipts through authorized primary
  queries, preserving their exact owner, schema and record policy while exposing
  no native payload. Reject scope/plan/receipt substitution and malformed history.
  Kernel observations remain unchanged. Unsupported expired feature recovery
  stays pending without takeover; this does not enable feature execution.

- Reconstruct bounded canonical feature-plan history with exact binding,
  fingerprint, contributor order, audit slots and lifecycle versions. Malformed
  history fails closed without returning a partial plan. Historical decoding
  does not enable feature reservation, receipt disclosure or recovery execution.

- Prepare exact registered feature plans through the existing coordinator,
  binding ordered contributors, bounded required audit slots, lifecycle and
  keyed command intent. Match safe receipts to their exact feature descriptor
  and include feature owner policy in collision-check scope. Kernel plan bytes
  remain unchanged; feature reservation, native policy and execution stay disabled
  until their typed phases and historical recovery are implemented.

- Map immutable feature command scalars into the existing keyed command codec,
  preserving full-width versions, UTC instants, exact kinds and owner policy.
  Digest all values conservatively and retain prior-key replay semantics.
  Adopt the committed feature command contract; feature execution admission
  remains disabled pending its owned schema, receipt and lifecycle phases.

- Freeze optional feature operation declarations in the existing contributor
  registry with exact adapter ownership, supported schemas, record policy and
  bounded conflict checks. Legacy contributors remain unchanged; registration
  does not enable feature execution. Adopt identity's additive operation-binding
  contract as the adapter dependency baseline.

- Recover abandoned identifier-attachment reservations through frozen primary
  participant evidence. Only unanimous non-commit proof grants terminal capability
  release; release, failure audit and aborted receipt commit together. Unknown,
  missing or conflicting evidence and callback failures retain the reservation.
  Capability expiry alone never grants release or reactivation. Domain execution
  and the production capability adapter remain unfinished.

- Atomically reserve or CAS-rebind a registered capability participant with
  exact identifier intent and the command journal. Invocation-bound SQL handles
  preserve original fingerprints/generations and expire on return; participant
  failure or panic rolls back all reservation prefixes. Capability domain Begin
  remains disabled until the remaining workflow phases exist. Existing kernel
  mutation and historical plan contracts are unchanged.

- Freeze typed one-use capability inputs into command-plan digests and bounded
  historical codecs without changing existing audit/lifecycle bytes. Unsupported
  execution rejects the input rather than silently omitting it. Atomic capability
  reservation/consumption phases remain pending; this declaration grants no
  workflow or transaction authority.

- Add primary identifier/verification partition reads and forward migration9.
  Reads preserve canonical values, full uint64 versions and tenant scope,
  returning no partial state when limits or consistency checks fail. Database
  constraints enforce tenant-local canonical and record-ID uniqueness, verified
  primary selection and consistent verification state. Existing structural
  users and writers receive initial identifier authority version1. Coordinated
  identifier mutations, proof consumption and retirement remain pending.

- Add opt-in durable administrative typed-field updates through the existing
  UserUpdateAdminService and sole Coordinator. Exact schema/version fencing
  preserves omitted and output-denied values, lifecycle status and original
  replay/recovery receipts. Protected audits and lifecycle effects commit with
  the mutation; failed/panicking phases leave no domain prefix. Terminal users
  cannot be updated, and missing or changed recovery evidence stays unresolved.
  Self-profile and creation APIs retain their separate opt-in boundaries.

- Add opt-in durable self-profile updates through the existing ProfileService:
  active/version-fenced name, image and partial typed-field replacements commit
  with mandatory audit, lifecycle and immutable replay/recovery receipts. Current
  disclosure policy still applies to historic results. Failure/panic leaves no
  domain prefix; unknown outcomes retain conservative frozen-participant recovery.
  Handle concurrent command-claim insertion through either existing unique key
  without losing exact scope/intent checks or returning spurious unknown outcomes.

- Add opt-in, schema-bound self-profile reads through the existing public
  ProfileRepository/ProfileService. Primary aggregate snapshots preserve typed
  fields and respect output selection without fabricated defaults; incompatible
  schemas and corrupt documents fail without partial disclosure. Forward
  migration 8 stores bounded name/image values while preserving old users and
  writers. Profile writes and lifecycle erasure remain under development.

- Add durable status-filtered user listing through the existing public directory
  service. Snapshot pages retain exact bytewise IDs, statuses, full versions
  and original expiry across live changes and process replacement. Finite
  per-tenant size/quota limits fail without truncation; explicit primary-time
  cleanup removes expired snapshots. Forward migration 7 preserves history
  and populated users. Identifier-filtered listing and field projection remain
  pending the owned identifier and attribute read profiles.

- Add primary creation recovery with exact frozen participant selection,
  generation takeover and invocation-bound typed evidence queries. Proven
  absence closes with required failure auditing and an aborted receipt in one
  transaction; partial/unknown evidence stays pending. Other command profiles,
  recovery-deadline alerting and production participant integration remain open.

- Reject malformed, noncanonical or misbound frozen participant plans before
  returning primary command outcomes. Historical audit-only plans remain
  readable without today's contributor registry or retained key selection.
  Observation does not acquire execution ownership or reconcile participants.

- Add owned creation UnitOfWork composition for core creation and historical
  recovery without caller-written plans, audit builders or transaction glue.
  Required failure auditing survives poisoned SQL Work without reviving writes;
  ambiguous closure remains unknown. Pending recovery is observation only.

- Add opt-in, current-policy-authorized primary command lookup with exact
  historical scope and receipt preservation. Missing, wrong-scope and denied
  callers receive the same protected response and decision/read work shape.
  Pending lease expiry never becomes rollback proof; queries do not acquire
  ownership or renew authority. Frozen-plan reconciliation remains pending.

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
