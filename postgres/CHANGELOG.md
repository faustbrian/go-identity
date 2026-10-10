# Changelog

## Unreleased

- Add an optional exact-owner native feature check at the final SQL commit
  boundary, after audit/outbox and journal writes. Original admission expiry
  or failure rolls back provisional effects without renewing facts; callback
  scope cannot regain Apply-only command authority. Existing contributors and
  commit APIs remain compatible.

- Add kernel-owned credential eligibility for an original selected email/phone
  recipient, retaining anonymous command scope and locking current identifier,
  user and credential authority until transaction closure. Expose original
  command identity only to the exact protected Apply participant for native
  transactional correlation. Existing exact-user credential admission is
  unchanged; these checks do not authenticate or issue a session by themselves.

- Bind original password-signin password and pre-auth cookie to separate
  retained-key intent domains, preserving user/anonymous scope through native
  preparation and final-plan attachment. Changed secrets conflict without
  rewriting the journal; busy/destroyed owners and plain signin metadata deny.
  Existing CAPTCHA-protected signin schemas retain their mapping. Raw custody
  is not persisted. Native password comparison and atomic login
  policy/session composition remain required; this does not enable login alone.

- Preserve the explicitly admitted password-custody command variant when
  attaching prepared output to its final transaction. Generated hash-only and
  authenticated password changes retain their scope and original replay result;
  legacy accessors stay closed and native proof policy remains required.

- Support explicit protected counters in native prepared feature execution.
  Commit the original charge before generation, conserve it across restart and
  retained-key rotation, and keep final current-authority checks. Denied attempts
  retain their audit/result without generating output. Install the additive
  CounterPreparationMigrationSource after admission preparation history before
  enabling this profile; old readers fail closed and existing history is unchanged.

- Bind authenticated password-change hash, source bearer and complete upstream
  proof to separate retained-key command intent. Preserve original nanoseconds
  and full versions without journaling raw custody. Existing hash-only intent
  stays unchanged; native policy validation and atomic proof consumption remain
  required before an authenticated password-change workflow can execute.

- Bind opaque password-hash change intent with the retained command key, without
  retaining verifier bytes in journal metadata. Require the exact native
  replacement participant; changed material cannot replay an original result.
  Existing hash-free command encodings remain unchanged.

- Add a typed kernel-owned existing-password change effect through the original
  coordinator. Lock exact primary predecessors and commit independent user,
  credential-authority and reference successors with native material, audit,
  outbox and retained recovery evidence. Install the additive replacement
  migration and select the native replacement/outbox traits. Existing history
  and denial-only compromise APIs stay unchanged; complete password workflows
  and their proof/session policy composition remain under development.

- Allow one feature owner to compose user and anonymous-flow variants of the
  same schema/version. Preserve exact descriptor selection and reject duplicate
  or conflicting policies within each subject namespace. Existing command and
  stored-plan encodings remain unchanged.

- Add code-free consuming OTP feature recovery that matches the full original
  attempt before disclosure and again under recovery locks. Preserve committed
  and classified aborted outcomes without comparing codes or charging again;
  unavailable reconciliation remains unknown. Existing recovery APIs retain
  their profiles. Public OTP sign-in composition remains under development.

- Expose checked OTP consumption scope only inside the exact protected feature
  invocation, so composed session effects can bind to the original reservation
  without a separate authentication commit. The projection contains no code or
  bearer and never authorizes credential delivery before commit.

- Let the exact native preparation owner select committed encrypted input and
  output by the original server command ID under current query authorization.
  Preserve original policy/key versions and output generation; never allocate,
  regenerate or take over work during lookup. Missing or incompatible custody
  fails closed. Existing metadata-only command queries remain unchanged.

- Add opt-in external preparation admission through the existing command
  journal, outside SQL and before acknowledged generation. Recheck original
  local facts after waits and before final commit; matching replay conserves
  output without provider work. Install AdmissionPreparationMigrationSource
  after preparation history before selecting this profile. Its immutable
  profile prevents legacy admission bypass; existing profile-1 history and
  APIs are unchanged. Concrete public OTP Send remains under development.

- Retain code-free native preparation input atomically with request-key
  correlation. Matching restart recovers original encrypted input; races cannot
  overwrite it and legacy mappings are not enrolled. Install the optional
  forward request-key preparation migration. Existing APIs remain unchanged.

- Add exact tenant-scoped email/phone recipient lookup and native transaction
  fencing of the original identifier, verification and user security epochs.
  Ineligible recipients are uniformly suppressed; infrastructure failures are
  not absence. Install existing identifier/status/credential migrations first.
  This does not authenticate callers or provide a public OTP Send workflow.

- Let the exact registered prepared-feature owner read its original retained
  ciphertext and output generation during final execution. Owned copies retain
  restart/takeover provenance without shared per-request state or new command
  encodings. Ordinary, admission, foreign and expired invocations deny access.

- Add opt-in native generated-feature execution through the original command
  journal. Current primary admission precedes acknowledged generation start;
  matching retries conserve retained output and its original generation.
  Final execution binds generated custody separately without replacing caller
  intent, commits effects atomically, and returns original terminal replay.
  Install the existing preparation extension before enabling this profile.
  One-use/protected-counter preparation profiles remain closed; public OTP
  Send composition remains under development.

- Add optional immutable preparation custody to the existing command journal.
  Native preparation can fence generation before entropy and retain the original
  encrypted output across lease takeover. A missing output after a committed
  generation marker remains uncertain and cannot authorize a replacement.
  Historical command and migration profiles remain unchanged. Public OTP Send
  composition and authenticated output recovery are still under development.

- Add opt-in, current-policy-authorized retry-key correlation before generated
  command preparation. Matching scoped retries retain one random command ID
  across fingerprint-key rotation and ambiguous commits; changed intent denies.
  Immutable forward-only storage never expires or reassigns unknown work.
  This is correlation only, not reservation, execution or an OTP Send service.
  Compose through a separate opt-in constructor, preserving the existing
  coordinator configuration and default-disabled behavior.
  Construct request configuration with opaque lookup-key custody to prevent
  disclosure through nested diagnostics as well as direct formatting.

- Native feature participants can admit a passwordless user's active primary
  status and original security epochs through the live transaction, without
  inventing a credential reference. Returned or foreign invocations cannot
  borrow admission; credential-specific checks remain unchanged.

- Bind code-free pre-auth-cookie and session-token feature custody into the
  existing private command fingerprint domains without storing bearer bytes.
  Code-free custody cannot enter OTP comparison or reservation phases;
  current original-flow admission remains the native workflow's obligation.

- Add explicit native metered OTP check execution and authorized historical
  recovery through the existing command journal. Correct checks commit only
  metering and a redacted receipt, not authentication or domain/session effects;
  wrong checks retain denial classification. Exact retry does not compare or
  charge again. Existing denial and consuming participant interfaces are
  unchanged; implementations opt in through the additive check interface.

- Bind submitted session tokens into a distinct private OTP command fingerprint
  domain, preserving retained-key replay and existing code/pre-auth encodings.
  Protected OTP checks/finalization lend only the original session token to
  the exact live owner; returned, foreign and pre-auth handles deny. Tokens and
  codes remain absent from scalar, receipt and recovery projections.

- Admit passwordless OTP users without fabricated credential references by
  locking primary status and comparing all three original security epochs.
  Keep credential-specific admission unchanged. Protected OTP apply/finalize
  now lend the separately submitted pre-auth cookie to the exact live owner
  without exposing the code; returned handles lose access. Native workflow
  composition remains under development.

- Bind separately submitted pre-auth cookies into versioned private command
  fingerprints without persisting bearer bytes or changing existing command
  encodings. Different cookies cannot borrow a code-only command's replay.

- Expose existing primary directory, credential and user-authorization checks
  to sealed OTP denial, reservation, protected-use and finalization handles.
  Bind checks to the exact live owner and original command; ignored failures
  poison the transaction. Proven noncommit release remains possible after
  revocation. Native session/pre-auth orchestration remains unfinished.

- Add OTP current checks, same-transaction terminal finalization and proof-bound
  release for the exact native reservation owner. Keep submitted codes out of
  domain/recovery handles, recheck before commit without another attempt charge,
  and retain reserved custody when noncommit cannot be proven. Production OTP
  storage and authenticated final-login composition remain unfinished.

- Add native consuming OTP reservation and exact predecessor rebind in the
  existing command transaction. Preserve live replay without another comparison
  and roll back failed participant prefixes. Domain execution and release stay
  disabled until current-check/finalize/recovery phases exist.

- Add frozen OTP attempt plans and coordinator-owned counted-denial transactions.
  Wrong-attempt charges, denial audits and aborted commands commit atomically;
  retries preserve exact attempt identity without another comparison. Code-free
  recovery requires current policy and the complete original attempt. Consuming
  OTP phases and the production OTP adapter remain unavailable.

- Bind opaque one-time submissions into retained-key canonical command intent
  without storing code bytes or changing ordinary command encodings. Reject
  generic admission until native counted OTP reservation/finalization exists.

- Add native CAPTCHA consuming current-check/finalize and proof-bound release
  phases in the shared coordinator. Protected effects and evidence finalize
  atomically; denial rolls back effects and releases only after proven rollback.
  Unknown outcomes retain reservations until unanimous primary noncommit proof.
  Reservation-only owners remain closed to domain execution and recovery.

- Add invocation-bound CAPTCHA evidence reservation and exact predecessor
  rebind in the shared command transaction. Native scope validation precedes
  SQL; failed participant prefixes roll back together. Domain consumption and
  pending release/recovery remain unavailable until their typed phases exist.

- Add typed CAPTCHA consuming-plan custody with exact signed linkage, original
  validity and risk-policy version, separate from issuance replay reservation.
  Historical encoding binds every declared role and shares one risk owner with
  phone evidence or counters. Existing plan bytes are unchanged when absent;
  executable admission remains closed until native consuming phases are wired.

- Expose sealed current CAPTCHA replay fingerprint/generation linkage only to
  the active declared native feature or recovery participant. Foreign, returned
  and undeclared handles fail closed; linkage does not grant replay ownership,
  current authorization, commitment or predecessor-transfer authority.
  Primary recovery separately exposes the exact previous participant generation
  being reconciled; a new recovery owner cannot falsely require an old replay
  winner to have already transferred ownership.

- Add explicitly declared native CAPTCHA replay reservation and exact-generation
  rebind through the sole coordinator before domain work. Preserve historical
  plan bytes when unselected and keep user/anonymous-flow namespaces distinct.
  This typed phase supports durable alias custody across domain rollback;
  production CAPTCHA storage and protected consumption remain pending.

- Persist and recover explicit anonymous-flow feature scope through the existing
  coordinator, with current-policy authorization against its own resource
  namespace and exact actor/scope matching. Preserve legacy user command and
  plan encodings; record-free audits and lifecycle events retain the flow target.

- Add current-policy authorized historical feature-command recovery with exact
  retained transition versions and audit metadata. Reuse the sole primary
  reconciliation owner without reserving missing commands, exposing kernel
  payloads or granting fresh credential authority; generic lookup is unchanged.

- Add current-policy authorized original-input final-authentication receipt
  query and recovery. Match exact retained-key command/proof intent and frozen
  plan without renewing expired proof authority, reserving missing commands
  or disclosing credentials. Preserve generic metadata-only command lookup.

- Add proof-bound final-authentication command preparation and reservation with
  an explicitly configured trusted authenticator. Ordinary reservations reject
  authenticated session issuance. Preserve original credential/proof metadata
  across retained-key replay, check current native eligibility before effects
  and terminalization, and consume proof atomically with protected effects.
  Native session issuance remains pending; this does not expose a login service.

- Add forward-only final-authentication proof-use tombstones and private
  same-Work staging. Conserve original versions and nanosecond expiry; deny
  proof reuse across commands, tenants and versions, including expiry during
  uniqueness-lock waits. Provisional use rolls back with protected effects.
  Public session issuance remains disabled pending complete native admission,
  session effects and recovery.

- Reject privacy command receipts that differ from the retained original request
  during journal persistence and request-bearing replay. Preserve scope-only
  observation for separate retained-key integrity verification; replay does not
  renew expired proof authority or alter recorded snapshots.

- Bind privacy command claims to the complete original intent and opaque proof
  envelope through retained-key fingerprints. Exact replay survives key rotation;
  changed scope, session, versions, projection choices or proof cannot acquire
  the original command ID. Encoding consumes no proof and renews no authority;
  public privacy execution stays closed pending protected composition.

- Add transaction-bound native privacy session-admission invocations with exact
  registered-owner custody, copied original intent and ordered initial/final
  checks. Denied, retained, substituted or repeated phases cannot leave usable
  Work or renew session/proof freshness. Public export execution remains closed
  pending complete native session/proof/cut/effect and recovery composition.

- Add bounded native privacy job/snapshot persistence tied to the same Work's
  allocation and frozen intent. Preserve sealed bytes, retained key version and
  full-width cuts; reject stale eligibility, duplicate staging and command-ID
  rebinding. Epoch and metadata roll back together. Public admission, workers
  and downloads remain disabled pending the complete protected composition.

- Add forward-only privacy epoch and pending-destructive-state fences, with
  private same-Work export allocation under the exact user lock. Preserve
  aggregate/security versions, imported IDs and full-width counters; rollback
  discards the provisional epoch. Public privacy execution remains disabled
  pending native session/proof checks, complete cuts and queued admission.

- Adopt the committed identity privacy request/recovery and integrity contracts
  without downgrading the PostgreSQL adapter's capability dependency.

- Atomically terminal-release reserved capability custody with the failure
  audit and aborted receipt after proven domain rollback and a live-owner
  recheck. Preserve that owner's generation, including takeover, without
  widening reservation authority. Failed release leaves pending/unknown
  custody; protected identifier workflow activation remains unfinished.
  Audit persistence panics now return redacted failure rather than escaping
  the coordinator; provisional audit writes roll back with terminal release.

- Reject protected identifier reservation plans whose proof fingerprint differs
  from the exact verified capability envelope, including another signature of
  the same payload. Historical command fingerprints and frozen plan decoding
  retain their original representation.

- Bracket provisional identifier persistence with initial and final session
  admission, denying duplicate or out-of-order checks. Final comparison exposes
  only the exact transaction-owned identifier epoch successor; denial prevents
  proof finalization and commit without renewing session freshness. Public
  execution remains disabled pending complete native workflow composition.

- Publish stable owner-derived global, tenant, user, identifier and aggregate
  credential scope keys for exact session-vector comparison. Framed keys avoid
  delimiter aliases; historical custom scope keys are not silently replaced.

- Bind an optional read-only session admission role into protected identifier
  plans without treating it as a durable recovery participant. Invocation-only
  checks borrow existing kernel authority queries; ignored denials prevent
  commit. Historical role-free plans retain their bytes. Public identifier
  execution remains disabled pending complete native workflow composition.

- Couple provisional identifier writes to the enlisted capability consumption
  phase and exact owned receipt; finalize consumption before terminal receipt
  persistence in the sole transaction. Public identifier execution remains
  disabled pending complete session/current-authority and recovery composition.

- Enlist optional subject-bound capability issuance under the original command,
  with frozen metadata, exact-owner staging and invocation-only persistence and
  recovery custody. Issuance, domain mutation, audit, lifecycle and command result
  share one commit; missing grants, phase failures and late expiry roll back.
  Historical no-issuance plan bytes and consuming-token phases remain unchanged.
  Native capability persistence and end-user issuance workflows remain separate.

- Preserve required authorization APIs under Go minimal version selection and
  consume the committed identity kernel contracts used by the current adapter.
  Dependency archives use canonical Go module checksums.

- Add an explicitly allocated forward identifier-retirement migration and
  native provisional persistence for attach, verify, primary switch, replace
  and remove. Record and verification fences, keyed reuse cooldowns and
  permanent retired-ID history share the protected transaction. Public
  identifier execution remains disabled pending complete current-authority,
  proof consumption, audit and recovery composition.

- Add distinct invocation-only capability apply and finalize custody for the
  exact registered participant and current coordinator generation. Retained,
  foreign and wrong-phase handles fail; callback failures poison domain work.
  Capability-bearing domain execution remains disabled until its native
  identifier mutation and complete transactional owner are implemented.

- Add effective-user authorization epoch admission under the original native
  participant and coordinator transaction. Missing/stale authority and ignored
  invalid input prevent commit; actor or workload identity cannot substitute
  for the command user. The additive authorization owner remains responsible
  for storage and locks. This does not activate session issuance.

- Add opt-in explicit deployment/tenant authority bootstrap and bounded primary
  reads. Native participants can compare exact epochs under coordinator-owned
  row locks; missing, disabled or stale tenant authority denies without default
  creation. Existing migration bytes and ordinary user writers are unchanged.
  This prerequisite does not enable sessions or provide lifecycle mutation APIs.

- Add active-participant credential admission under the existing coordinator.
  Exact credential and independent user, identifier and credential epochs are
  checked under primary row locks, with expiry sampled after lock acquisition.
  Denial invalidates the work; this prerequisite neither issues sessions nor
  replaces proof consumption or other owners' current-authority checks.

- Add owner-checked delivery staging under the frozen original participant.
  Identically configured unenlisted contributors cannot stage their custody;
  existing trusted low-level staging remains compatible.

- Enlist optional encrypted delivery effects under the original mutation and
  command receipt. Frozen logical intent and exact participant identity survive
  replay and recovery; missing custody, failed persistence or expired effects
  roll back the mutation. Historical no-delivery plan bytes remain unchanged.
  The production queue, sender processing and envelope verification belong to
  the separate delivery adapter and remain in development.

- Add opt-in one-use risk current checks and terminal finalization in the same
  domain transaction as protected feature, audit, lifecycle and command receipt.
  Late denial rolls back every provisional effect before proved-noncommit
  release; committed replay never consumes again. Reservation/release-only
  owners remain unsupported for domain execution until native checks exist.

- Add opt-in native current counter checks before protected feature mutation and
  final domain commit. Late denial rolls back domain, audit and lifecycle effects
  while preserving the independently committed charged attempt. Missing native
  admission support keeps counter-bearing execution closed; phase custody and
  original evidence cannot be retained or renewed.

- Add protected-command counter reservation phases with invocation-only native
  authority. Allowed charges commit with pending command ownership; denied
  charges commit with the matching failure audit and aborted receipt, and exact
  replay/takeover does not charge again. Native durable counter algorithms and
  current domain admission remain pending; counter-bearing Begin stays disabled.

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
