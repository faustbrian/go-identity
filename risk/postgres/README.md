# Risk PostgreSQL adapter

Experimental, Go 1.27. This module is being built as the durable owner of risk
evidence and decisions. It is **not yet an executable durable risk service**.

## Implemented boundary

- `VelocityMigrationSource{Base: counterHistory, Version: laterAllocation}` adds
  the PostgreSQL recovery journal for the separate ephemeral Valkey lane. It
  stores scoped keyed attempt digests, original per-dimension snapshots and up
  to four retained aliases, without a protected-command foreign key or raw
  request facts. Boot epochs start unavailable; installation inserts no rows.
  Covered interval and lease constraints are storage invariants, not proof of
  replay or publication. Sequence positions are not commit-order evidence.
  Native journaling, fenced reconciliation, full snapshot validation and atomic
  Valkey healthy publication are not implemented by this migration. There is no
  pruning or operator-bypass API. Valkey remains ephemeral mutation authority;
  PostgreSQL is the durable recovery journal, not a second counter engine.

- Optional `Config.UseIssuer` installs pure use preparation only after matching
  the issuer's exact current policy and entire retained signing/linkage key set.
  `PrepareEvidenceUse` accepts a core precheck, original trusted request and
  native phone initiation feature spec. It freezes the exact phone, pre-auth,
  attempt and subject dimensions inside the opaque in-memory command; the
  returned signed plan and durable journal contain no raw scope or bearer.
  Caller-selected `risk.intent`/`risk.use.*` fields deny. Non-risk fields remain
  the phone owner's responsibility, including equality with its domain target.
  `ValidateRiskEvidenceCommand` reconstructs the original intent under installed
  provider configuration without callbacks or IO. It uses the signed historical
  check time, rounded upward to microseconds, without rewriting that time or
  expiry; it does not establish current validity. Nil preserves existing setup.
  Native current counters, same-domain row checks and finalization remain
  required; this partial method does not enable `RiskExecutionContributor`.
- `MapIssue` accepts only an opaque successful core evaluation and matching
  trusted identity binding. `IssueOperation` fixes its closed native schema.
- The native decoder verifies every signed field and current configured policy.
  Its record target is the canonical opaque command ID; the private retained
  intent digest never becomes audit/lifecycle aggregate metadata. A committed
  response resolver must compare that digest separately after authorization.
- The internal response codec uses the existing secret-envelope AES-256-GCM
  implementation and a concrete copied local keyring. Original times and exact
  scope are authenticated; rotation preserves retained responses without
  renewing freshness. It cannot invoke network key providers inside Work.
- `MigrationSource{Schema: "identity_risk", Version: allocation}` provides a
  dedicated, forward-only issued-evidence schema. Allocate its version in the
  composition's single history after the identity kernel. Never renumber an
  applied version or adopt unmanaged objects.
- `IssuanceIDMigrationSource{Base: originalSource, Version: laterAllocation}`
  appends the opaque command-ID profile without changing the original history
  or retained legacy ciphertext/AAD. Install this complete history for new native
  issuance. Legacy digest-target rows remain retained, not silently rewritten.
- `ReservationMigrationSource{Base: issuanceHistory, Version: laterAllocation}`
  adds nullable, all-or-none command/fingerprint/generation ownership and the
  six one-use journal states. It preserves installed migration bytes, legacy
  and opaque record IDs, original expiry and encrypted response custody. Its
  composite command foreign key binds ownership to the same tenant and exact
  recovery phase. Allocate a new version after the issuance-ID migration; the
  source returns the complete history and is safe to apply again. Schema
  availability is not reservation or terminal-transition authority. Existing
  issuance binaries may continue inserting ownerless `issued` rows; consuming
  compositions require the replay-compatible executor and native participant.
- `NewRepository(Config{...})` supplies the native issuance contributor. Enlist
  that exact instance with the identity repository, audit and lifecycle adapters
  in one coordinator registry. It inserts through the coordinator's active Work,
  materializes at database time and returns only a provisional structural receipt.
  The coordinator commits evidence, protected `identity.risk.decide` audit,
  `risk.evidence_issued.v1` lifecycle and command result together.
- Recovery examines native linkage only during the locked coordinator invocation.
  Positive or inconsistent evidence keeps the command unresolved; native absence
  can contribute to unanimous negative evidence because this initial journal
  never prunes rows. Neither expiry nor a private pool lookup permits release.
- `NewExecutor(ExecutorConfig{...})` implements the core `EvidenceExecutor`
  contract through the real primary coordinator, with the exact native repository
  internally enlisted alongside kernel, audit and lifecycle participants. It
  authorizes before provider admission and before execution, and privately
  compares retained intent before decrypting an original committed response.
- The repository implements `RiskReservationContributor` for native phone-reset
  initiation. It authenticates every signed core use field under retained key
  pairs, matches current risk policy and consuming command scope, locks the
  exact already-issued row, and samples primary time after any lock wait.
  The original issuance command must be committed; retained positive linkage
  from a foundation or unresolved history cannot confer new ownership.
  Missing, terminal, expired and mismatched evidence returns one redacted
  conflict. Command and evidence ownership commit in the same coordinator
  reservation transaction. Takeover CAS requires the same command/fingerprint
  and exact prior generation, preserving the original expiry and reservation
  time. There are no private transactions, provider callbacks or bearer reads.
  The immutable precheck binds omitted raw recovery scope and provider evidence;
  reservation does not re-evaluate providers or authoritative counters. Apply
  must recheck these before any protected mutation. The current coordinator
  deliberately denies domain execution for this profile until complete
  apply/finalize phases exist. Completion also requires
  purpose-bound OTP and capability participants and remains unsupported.
- `RiskReleaseContributor` implements consuming recovery and terminal release
  for initiation. The exact-instance `RecoveryWork.RiskBinding` authenticates
  historical signed custody and matches the committed original issuance, all
  immutable row linkage and the reserved command/fingerprint/prior generation.
  Missing, terminal, corrupt or foreign rows remain unknown, never noncommit
  proof. No current-expiry check or policy change can invent reuse authority.
  The coordinator excludes old writers and requires independent noncommit from
  the phone, kernel, audit and lifecycle participants before invoking release.
  Its bounded release handle CASes only `reserved` to terminal `released`, with
  the recovery generation, in the same transaction as failure audit and aborted
  command receipt. Original expiry, reserved time and response custody persist.
  Unknown phone/domain outcomes and audit/SQL failures retain the reservation;
  retries and cleanup do not reactivate it. No raw recovery/provider scope is
  reconstructed and no domain authority is enabled by this recovery profile.

## Adoption and security

The official executor owns plan construction, authorized primary resolution and
exact original-response replay. Application code must not supply a private
transaction, journal or workflow substitute.
Mapping and encrypted bytes establish neither durability nor protected recovery
authority. No bearer may be exposed until the sole coordinator proves commit.
Expiry, missing metadata or a failed read never establish rollback.

Trust actor kind, policy and correlation from server composition, not transport
input. Record IDs, digests, native commands and encrypted response material are
internal custody data, never operation results or log fields. Retain wrapping
keys for every retained encrypted result. Go cannot guarantee memory erasure.

### Issuance composition

Migrate the kernel followed by the complete `IssuanceIDMigrationSource` history.
Construct the native repository with the issuer's retained evidence keys and
retained local wrapping keys. Supply the caller-owned primary pool and owned
audit/lifecycle adapters to `ExecutorConfig`; both effect adapters must support
the coordinator's typed recovery phase. Supply a verified `Caller` decision
context for the exact actor, tenant, `identity.risk.evaluate` action and
`identity.user` resource. It is copied, not derived from request Actor text.
Both opt-in coordinator policies must use the caller's current revision.

The owned audit contributor uses `audit/postgres`, `identity.security_audit`, v1.
The original explicit `identity.audit` v1 composition identity remains accepted
for compatibility; other contracts, owners and versions are rejected. The owned
outbox contributor uses `outbox/postgres`, `identity.lifecycle`, v1. Install all
audit migrations with their fresh-install preflight and generic plus identity
outbox migrations before use.

Pass the executor to `risk.NewPhoneEvidenceIssuer`. Missing is returned only
after authorized global claim absence. Prior pending, failed, foreign and corrupt
commands never enable provider reevaluation. Committed replay preserves the
original reference and timestamps, even after expiry and retained-key rotation.
Independent evaluations racing under one command ID may observe Unknown while
the winner is pending; `Recover` converges to the original committed response
without providers. A commit error initially discloses no reference. No result
grants one-use consumption authority. Pools/adapters remain caller-owned; no
background goroutine or Close method is introduced.

Original committed issuance remains replayable in all six legitimate later
journal states while retained ciphertext is available. This preserves the same
reference and interval, not reuse authority: native reservation independently
rejects terminal evidence or another owner's reservation. No replay evaluates
providers, repairs missing ciphertext or renews the original expiry.

The PostgreSQL integration suite withholds an actual successful domain COMMIT
acknowledgement at the socket boundary for both phone-reset purposes. The initial
result stays reference-free Unknown; a new primary executor recovers the original
reference and timestamps without provider work or duplicate effects.

## Remaining work

Domain apply/finalization and completion's additional participants;
durable lockouts/overrides, counter retirement and pruning; CAPTCHA participants;
investigation, retention and anonymization; complete
public examples/API baseline and package/release verification remain pending.
There is no supported login or phone recovery workflow from this module yet.

## Protected command counters

Set `Config.CommandCounters` to an explicit core `CommandCounterPolicyConfig`
with the same risk policy version and 1..4 newest-first retained digest keys.
Nil retains issuance-only setup. Install `CounterMigrationSource` after the
evidence reservation history; prior migration bytes and evidence remain intact.
The coordinator and risk dependencies must include the committed protected-counter
contracts pinned by this module. No private transaction or consumer-written
counter store is required or supported.

The native feature owner passes its opaque command, trusted canonical subject
and primary preparation time to `PrepareCommandCounters`, then declares the
returned `CommandCounterPlan` in the coordinator plan. The native owner validates
its own fields plus the reserved `counter.*` fields. The exact registered risk
instance reconstructs tenant/operation/attempt, bound subject or actor/resource,
session/network dimensions, policy bounds and original retained-key projection
before SQL. Raw network/session inputs stay in the in-memory opaque command;
only bounded keyed projections and structural command linkage persist.

`ReserveCommandCounters` is invoked only under coordinator ownership. A fixed
window begins at primary time, resets at exclusive expiry, and never wraps its
uint64 count. All retained digest aliases share one logical window. Durable
tenant/operation key history rejects omitted or changed unretired versions;
adding a strictly newer key preserves active counts. This initial history is
append-only: retiring keys or pruning windows/snapshots is not yet supported.
An active incompatible window configuration fails closed instead of resetting
allowance. No lockout duration or policy is inferred from these attempt limits.

Every charge retains its original four dimension snapshots and observation time.
Allowed SQL is provisional until the coordinator commits pending ownership;
denied charges commit with failure audit and aborted receipt. Exact replay does
not call the mutation phase. Takeover transfers only the exact predecessor and
reuses its original allowed decision, never a new count or fresh observation.
Historical recovery checks the retained predecessor charge without treating it
as domain commitment; only unanimous independent noncommit evidence can abort
the owning command. Recovery never refunds a charged attempt.

Native PostgreSQL tests exercise threshold denial, hot-key contention, replay,
takeover, rotation, missing retained keys, preparation expiry, window expiry,
saturation, failed snapshot rollback and charged noncommit reconciliation. The
feature owner in these tests is a seam; no password mutation or login journey is
claimed. Native current fixed-counter admission now implements the coordinator's
opt-in `CommandCounterAdmissionContributor`. It locks the original current-
generation charge, validates all original snapshots and retained key history,
then locks each current logical window. Only afterward does it sample primary
time and validate the original preparation and earliest window expiry. Both
pre-mutation and pre-commit checks use the same domain Work; no counts, aliases,
key history, observation times or expiry are changed by a current check.
Missing original aliases, divergent roots, changed windows or excess current
counts deny. New retained keys may coexist with the original aliases without
recharging a takeover. A delayed domain operation that outlives its original
evidence rolls back all provisional domain effects but retains its charged
attempt and classified failure receipt.

This is current fixed-counter allowance, not a complete risk verdict or domain
authorization. The native feature owner must check its current user, credential,
factor and organization authority. No lockout/override policy is supported by
this configuration; those remain required implementation work. RiskEvidence
consumption/apply/finalize, real password/session workflows and release gates
remain pending. Tests use a SQL effect seam, not a production password adapter.
