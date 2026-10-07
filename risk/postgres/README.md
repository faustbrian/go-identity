# Risk PostgreSQL adapter

Experimental, Go 1.27. This module is being built as the durable owner of risk
evidence and decisions. It is **not yet an executable durable risk service**.

## Implemented boundary

- `MapCaptchaUse(use, protectedSpec)` preserves the protected feature schema,
  binding and all domain target/version fields, appending closed token-free
  consuming custody. The verified actor, command, tenant, subject/anonymous flow
  and action must match the original precheck. Feature owners reserve the
  `captcha` field namespace and include the returned `CaptchaEvidencePlan` in
  their shared coordinator plan. Risk and authorization policy versions remain
  separate. `Repository.ValidateCaptchaUseCommand` authenticates that exact
  declaration under selected current verifier configuration without callbacks
  or IO. These pure boundaries grant no durable use or mutation permission;
  feature owners must independently enforce domain-time current authorization;
  reservation alone is not usable login or protected-use permission.

- `Repository.ReserveCaptchaEvidence` and `RebindCaptchaEvidence` implement the
  coordinator's sealed native consuming-reservation contract. Install
  `CaptchaUseMigrationSource` before choosing consuming plans. The owner locks
  the exact keyed evidence from committed original issuance, compares signed
  native facts and checks primary expiry after exclusion. First reservation
  binds one command/fingerprint/generation; takeover conserves the original
  interval and transfers only its exact predecessor, atomically with the command
  and every declared participant. Missing, terminal, foreign and divergent
  ownership deny; no provider callbacks, private transaction or time-based
  release run.

- `Repository.CheckCaptchaEvidence` and `FinalizeCaptchaEvidence` implement the
  sealed coordinator consuming phases. They authenticate complete admitted
  signed input under the selected current profile, lock exact committed-original
  and reserved consumer custody, compare original facts and recheck primary-time
  expiry. Finalization CASes the current generation in the same transaction as
  protected effects, audit, lifecycle and result. Native feature owners still
  enforce their own target/user/session/factor authority. No provider runs here.
  `ReleaseCaptchaEvidence` terminally releases only coordinator-proven rollback
  or unanimous primary noncommit, preserving original validity and reserved time.
  Historical cleanup works after expiry or current verifier/policy removal;
  missing, terminal, corrupt or divergent custody remains unknown. A shared
  native risk owner also proves every selected counter/phone role before release.
  These phases are not a complete password/login service or provider interop.

- `CaptchaUseMigrationSource{Schema, Version}` adds consuming-command custody
  after the existing CAPTCHA journal, with a permanently allocated forward
  migration version. It preserves original issuance, aliases, expiry and
  encrypted responses. Consuming states require complete same-tenant journal
  linkage, distinct command identity, full-width positive generation, signed
  binding, and original exclusive expiry. Unknown legacy consuming states fail
  the atomic upgrade rather than being reset or assigned invented ownership.
  Erasing a terminal response does not erase consuming custody. These storage
  constraints do not grant permission, prove noncommit or enforce transitions;
  select the native coordinator phases above to enforce those transitions.

- `NewCaptchaExecutor(CaptchaExecutorConfig{Executor: composition, Flow: flow})`
  supplies the real `risk.CaptchaEvidenceExecutor`. Compose immutable
  `CaptchaEvidenceCustody` first, select it in `Config.CaptchaCustody`, construct
  the repository and executor, then supply the executor to
  `risk.NewCaptchaEvidenceIssuer`. No dummy callback or consumer-written store
  is necessary. Caller and flow come from verified server composition, never
  decoded client metadata. The executor binds the exact tenant/target namespace
  and administrative actor and freezes all challenge, session, pre-auth and
  request dimensions. Changing any dimension requires a new correctly verified
  composition. Current admission/recovery policies receive trusted
  `identity.captcha.{flow-kind,operation,pre-auth,session,actor,challenge,request}`
  attributes and must enforce current authority; historical permission is not
  enough. The separately configured policies cannot be omitted.
  Unknown commit discloses no candidate; recovery returns only the authenticated
  original encrypted response without provider verification or expiry renewal.
  This is issuance, not protected-use authority. Production-effect composition,
  complete cleanup/retirement, protected workflow composition and release gates remain
  unfinished for CAPTCHA.

- `Config.CaptchaCustody` selects bounded immutable core verifier profiles with
  the exact risk policy and retained evidence-key set. Empty preserves existing
  setup. The native participant authenticates signed input against a selected
  profile before reservation, claims all token aliases in the coordinator's
  reservation transaction and transfers only the exact predecessor generation.
  Domain work rechecks sealed current ownership and every alias, samples primary
  time after locks, then inserts encrypted evidence in the same Work as command,
  audit and lifecycle commitment. Participant recovery classifies only exact
  primary custody; missing owners or corrupt response encryption remain unknown.
  Public issuer execution/recovery is supplied by `NewCaptchaExecutor` above.
  Complete rotation/key-retirement safeguards, protected workflow composition and the
  canonical risk service are still unfinished.

- `CaptchaScopeMigrationSource{Schema, Version, Custody}` must follow the CAPTCHA custody
  migration before selected native reservation. Its forward upgrade backfills
  exact provider-scope key retention without rewriting prior history. First
  claims lock that scope before checking at most seventeen indexed key rows;
  omission or secret replacement of any referenced version denies. For populated
  histories, supply the original reviewed retained core custody for every
  installed scope; token-free old aliases cannot infer their original secrets.
  Missing or conflicting custody fails the upgrade atomically. Freeze those
  migration inputs permanently along with the allocated history version.
  Historical owner takeover can use a newer complete retained profile without
  expanding its original aliases or expiry. No retirement API is supplied yet.
- `CaptchaMigrationSource{Schema, Version}` independently installs replay
  winners, scoped aliases, referenced key versions and native evidence storage
  after the kernel and existing risk namespace. Allocate its permanent version
  after the composition's installed history; phone/counter/lockout upgrades are
  not bootstrap dependencies. It preserves existing tables and adds no private
  transaction owner. Alias uniqueness excludes key version so rotation or reuse
  of a key secret cannot create a second winner. Evidence payload deletion does
  not delete the independent replay tombstones or their key-retirement linkage.
  This schema does not select runtime CAPTCHA execution or implement cleanup or
  key retirement; select runtime custody separately.

- `MapCaptchaIssue` maps signed core issuance custody without a raw provider
  token. `CaptchaIssueOperation` selects distinct user and anonymous-flow native
  schemas. Supply the separately verified command actor; administrator flows
  must match their signed actor. Mapping neither verifies a provider nor commits
  evidence. Strict native restoration retains original aliases, configuration
  commitment and exclusive validity without creating new authority. Original
  response encryption uses a separate CAPTCHA profile and authenticates exact
  command scope and retained record metadata. Mapping alone does not enable
  durable execution; explicitly selected native custody is separate from these
  preparation contracts. `NewCaptchaExecutor` supplies public issuance and
  recovery; protected-use phases use the consuming contracts above.

- `Config.EnforceLockouts` selects current durable restriction enforcement for
  protected command counters. Install `LockoutMigrationSource` after counter
  history. Admission reads restrictions on the original logical keyed roots
  under the owning domain transaction; retained-key rotation and window resets
  cannot erase an active restriction. Counter locks fence a concurrent new row
  through its immediate foreign key; existing restriction rows are share-locked
  until domain commit/abort. Primary time is sampled after all locks. Expiry is
  exclusive, future-start or unavailable authority denies, and older policy
  versions do not reset a restriction. No retry-after or account-existence
  metadata is returned. Missing migration fails closed when selected.
  False retains the earlier counter-only development profile. Selection requires
  native command counters; it does not enable ephemeral or authentication-only
  evaluation. This read boundary never creates, extends, deletes or caches state,
  infers a trigger/duration from velocity, or permits identifier-only attempts
  to lock an account. Native start/end/CAS is separately selected through
  `LockoutMutations`, described below, with the owned `LockoutExecutor` workflow.
  Consumers must not
  supply their own lockout mutations or SQL. Full canonical Service remains
  unfinished; this profile is not production risk-service permission.

- `VelocityJournal` records an authenticated pending ephemeral attempt and every
  exact keyed target/alias in one primary transaction, before external work.
  Select a caller-owned `go-postgres.Pool`, exact coordinator policy/key custody,
  stable deployment namespace and separately retained HMAC journal key. Replacing
  that key is unsupported; retain it for all unresolved attempts. Install
  `VelocityIntentMigrationSource` after velocity history: it backfills existing
  targets and separates pending intent from post-mutation snapshots without
  rewriting prior migration SQL. Receipt issuance proves only an intent commit,
  never dispatch permission, allowance or counter/epoch health. Matching pending
  replay is unavailable; changed intent conflicts without overwriting history.
  Ambiguous journal commits return no receipt and do not authorize redispatch.
  `RecordResult` retains an explicit complete adapter declaration atomically;
  terminal outcomes, including unknown, are immutable. Exact replay is idempotent.
  `ReadResult` validates the complete stored binding, dimensions and retained
  ordered aliases, preserving original uint64 values and observation/window
  times. Pending or corrupt history is unavailable; unknown never becomes
  noncommit. Exact full windows and microsecond-representable snapshots are
  required; no freshness is rounded forward. These methods do not authenticate
  external results or authorize effects. External-result reconciliation, fenced
  replay and Valkey execution remain pending.

- `NewVelocityRecovery(VelocityRecoveryConfig{Journal: journal,
  MaximumWindow: time.Hour, LeaseDuration: leaseBound})` owns scoped primary
  recovery leases. `Acquire` accepts the trusted projection's nonzero random
  128-bit boot epoch, not request data. Independent processes have one live owner
  per tenant/namespace. Database time is sampled after locking; authoritative
  expiry alone allows monotonic takeover. New boots retire prior epochs, which
  cannot resurrect. `Renew` returns a superseding opaque receipt; old receipts
  and old generations fail `CheckLease`. Checks prove point-in-time ownership,
  not effect permission. Missing/ambiguous acknowledgements return no receipt.
  The supported maximum window is one hour; explicit leases are positive,
  microsecond-representable and at most one minute. Initialization records zero
  replay progress and never publishes healthy state. Journal scan completeness,
  external-effect reconciliation, Valkey fencing and health publication remain
  unfinished; ownership acquisition alone cannot enable authentication.
  Writer transactions take a shared tenant/namespace lock before allocating
  insertion time/sequence or locking a result row. Acquisition takes that same
  lock exclusively and cannot cross an unresolved writer commit. Lock waits
  remain inside the journal timeout and cancellation budget. Historical reads
  remain independent; later pending/unknown or terminal declarations are not
  discarded. They remain replay-owner work, so acquisition alone is not cursor
  completeness, replay closure or effect admission.
  All participating writers must run the shared-lock implementation before
  relying on this drain guarantee. Earlier experimental journal binaries did not
  take that lock; stop or upgrade them first. Mixed-version writer operation is
  not certified by this development checkpoint.

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

- Install `VelocityIntegrityMigrationSource{Base: intentHistory,
  Version: laterAllocation}` before running current journal writers. Each native
  insertion and declaration atomically seals the complete persisted record with
  domain-separated HMAC-SHA-256 under the retained journal key. The seal covers
  scoped identity, sequence, fingerprint, original preparation/recording times,
  outcome, every ordered target/alias, and full snapshots. Readback and terminal
  replay reject missing or altered authentication without re-sealing history.
  PostgreSQL timezone and text formatting cannot renew or change sealed times.
  The forward migration preserves earlier experimental records unchanged and
  unsealed; they are retained for investigation, not accepted as authenticated
  readback/replay. Do not replace the journal key or run old writers alongside
  the current profile. Attributable legacy recovery remains unfinished; there
  is no automatic backfill, pruning or fail-open migration fallback.
  Record integrity is not external-result truth, rollback-resistant storage,
  replay completeness, Valkey effect authority or healthy publication.

- Install `VelocityReplayMigrationSource{Base: integrityHistory,
  Version: laterAllocation}` before current writers. Native insertion and first
  terminal declaration atomically assign an indexed, separately authenticated
  change position. Terminal idempotent replay creates no new position. All
  original signed facts remain unchanged; valid pre-position history receives
  bounded native bookkeeping only after its original seal verifies. Migration
  does not sign old records; unverifiable legacy history remains unavailable.
  `recovery.ReadPage(ctx, lease, cursor, batch)` accepts batches 1..1000
  (reference 100), starts at zero cursor, and returns copied immutable records
  plus `page.Next()`. Pages drain overlapping writers and validate exact live
  custody before and after the bounded read in the same primary transaction.
  Renewal accepts the continuation with the new lease; superseded leases and
  foreign/takeover cursors deny. Reads include all retained history, not a
  storage-time cutoff, and preserve expired snapshots without renewing windows.
  Use the returned cursor to observe insertions or declarations after an empty
  page. Original tenant, namespace digest, attempt digest and fingerprint are
  copied from authenticated retained facts. Attempt identity uses the core
  `VelocityReplayIdentity` profile, preserving existing journal bytes; the
  sequence-derived record ID remains separate. No raw attempt is stored, and
  projection does not mint a new command. Both native adapters must select the
  same stable namespace/key independently of rotating dimension aliases.
  Records are redacted/nonserializable owned-adapter projections, never
  `CounterCommand`, dispatch, effect application, or positive validity proof.
  Initialization can persist traversal bookkeeping but does not rewrite original
  history or epoch progress. Failures and ambiguous acknowledgements return no
  page/cursor. Current pagination is not applied replay closure, external-result
  reconciliation, Valkey fencing or healthy publication; those remain unfinished.

- Owned replay additionally requires paired `JournalIssuer` and
  `NativeVerifier` from `risk.NewVelocityRecoveryAuthorities`. Trusted
  composition retains journal issuance only in this adapter and native issuance
  only in the concrete projection; application-facing stores expose neither.
  Crossed or partial ownership is rejected at construction. Omitting both
  preserves lease/page operations but disables owned replay.
  `OwnedLease` checks exact current primary custody. `OwnedHistory` rereads the
  authenticated original record under a bounded writer-fenced transaction,
  preserving original identity, aliases, counts and timestamps, then closes SQL
  before native IO. Pending/unknown remain unresolved, not retry permission.
  Install `VelocityAppliedMigrationSource{Base: replaySource, Version:
  laterAllocation}` for `RecordApplied`. Only the configured native owner's
  acknowledgement of the exact lease and original terminal history advances
  scoped change-order progress. Duplicates are idempotent; gaps, foreign graphs,
  stale leases and corrupt sealed checkpoints deny. The forward migration starts
  populated epochs with no applied authority. Progress never publishes health;
  native restore and stable writer-fenced healthy activation remain unfinished.
  `ResumeApplied(ctx, lease)` returns a bounded primary-authenticated cursor
  for `ReadPage`, skipping only durable acknowledged effects rather than scanned
  pages. Same-owner renewal preserves progress; takeover or a new epoch replays
  retained history from zero. Current-generation seal and original terminal
  anchor must authenticate; corruption, stale ownership or ambiguous commit
  returns no cursor. Unresolved suffix history remains visible. This cursor is
  traversal custody, not proof of complete replay or permission to publish health.
  `PrepareClosure(ctx, lease)` establishes a stable primary journal cut after
  every retained change is applied. Pending, unknown, unpositioned or unapplied
  history denies. The existing epoch's `replay_through > replay_from` fences
  new same-scope journal writes until renewal or expiry; unchanged terminal
  replay remains idempotent. Locks end before the method returns. Matching
  retry recovers the same cut after a lost commit acknowledgement.
  `CheckClosure` verifies exact retained custody under primary time. Neither
  method proves historical temporal coverage, performs native IO or publishes
  health. Native publication, primary confirmation and admission must still
  agree before a concrete store can enable traffic. Do not treat a captured
  interval, empty page or successful closure as healthy readiness.

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

### Forward lockout transition storage

`LockoutStateMigrationSource` appends one atomic migration after
`LockoutMigrationSource`, preserving every installed checksum and every populated
restriction's version, original interval and keyed root. Allocate its version
permanently and separately from any selected velocity history. New nullable
custody fields deliberately remain empty for legacy rows; the upgrade does not
invent administrative permission, a command, an event or an ended restriction.

The storage represents an explicit end without deleting CAS history or
shortening the original expiry. Complete native linkage needs a canonical opaque
record ID, binding digest and existing same-tenant command with the exact
start/end operation; inconsistent or partial linkage is rejected. These fields
are latest domain-state linkage, not a second command/replay journal.

Existing interval-only admission deliberately remains unchanged and must not
be treated as honoring an administrative end. Direct SQL in the populated
upgrade test is a schema fixture, not a production mutation API.

### Selected native lockout transitions

`Config.LockoutMutations` adds the native start/end operations to the same
registered risk contributor. Install `LockoutTransitionMigrationSource` after
the state migration and the existing authorization owner's authority schema
before selecting it. Unselected profiles acquire no new schema dependency.

`PrepareLockoutCommand` checks the configured current authorization revision
outside Work and seals the full trusted request at its original primary UTC
microsecond read instant. Its administrative operation is distinct from the
credential-change operation being restricted. It does not restrict password
signin, password recovery or factor-recovery routes. Preparation and a
provisional feature receipt are not commitment; effects run only through the
sole identity coordinator. Applications must not implement this orchestration
themselves; use the owned `LockoutExecutor` below.

Native apply locks the existing authorization owner's actor epoch through
commit, resolves the retained keyed subject root without charging an attempt,
checks primary-time expiry after lock acquisition, then performs exact-version
CAS. Starting an active restriction is a conflict, not implicit extension.
Ending preserves the original interval and aggregate version history. Canonical
protected audit and lifecycle effects share that transaction; failure rolls
back the domain transition. Closed command fields and original decision
freshness cannot be changed on replay.

The selected admission profile honors an explicit end only when current state
matches its exact immutable same-command domain version. Missing selected
history or malformed custody fails closed. Historical domain versions retain
original effects for the existing coordinator's recovery participant even
after subsequent transitions. They own no command leases, retry state or
second replay journal; no pruning is exposed. This native contributor is not
the complete canonical risk service or release-gate completion.

`NewLockoutExecutor` composes the caller-owned primary pool, selected repository,
real audit/lifecycle adapters and the current authenticated actor/tenant/user
scope. Choose a separate immutable executor scope for each selected start/end
operation. Admission and historical disclosure policies are separately required;
neither successful history nor an actor epoch is mutation permission.

Pass an unchanged `LockoutExecutionRequest` to `Execute`. The executor reads the
existing authorization owner's current actor epoch, samples original primary
time, checks mutation policy outside Work, prepares the canonical effects and
executes exactly once through the existing coordinator. Applications provide
configuration and verified scope, not SQL, epoch lookup or transaction glue.

Only a successful authorized primary resolution exposes `Snapshot`, the exact
original committed post-state. `Recover` checks the current disclosure policy
and reads the original immutable domain version, even after later starts/ends.
Retain original intent and all referenced signing keys. Changed intent denies;
retained-key rotation neither changes original state nor renews its validity.
Unknown results expose no snapshot and require same-request recovery, not an
unproved replacement command. Existing issuance workflows remain separate.

## Production effect composition

Use `audit/postgres.NewIdentityContributor` and
`transactional-outbox/v2/postgres/identity.NewContributor` for `ExecutorConfig`
Audit and Lifecycle. Install their owned migrations (including command/effect
bindings) before use; audit fresh-install preflight must precede audit migrations.
They write through the same coordinator Work, without owning another transaction.
Do not replace these phases with application SQL stores or treat a successful
phase callback as commitment.

The real PostgreSQL public CAPTCHA integration composes both adapters across
pre-auth subject/anonymous, authenticated and administrator flow variants.
Lost commit acknowledgement reveals no candidate and recovers the exact original
without another provider verification. Effect failures after actual writes roll
back evidence and success effects. Recorded audit/outbox payloads exclude the
provider token and opaque evidence bearer. Remote provider interoperability and
complete protected login journeys remain separate, unfinished acceptance work.
