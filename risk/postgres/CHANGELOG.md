# Changelog

## Unreleased

- Activate an exact covered, primary-confirmed and native-confirmed velocity
  snapshot under the existing primary writer fence. Retain original cut and
  expiry; record actual activation time separately. Current eligibility checks
  do not widen replay custody, and matching retries preserve all timestamps.
  Invalidation is terminal for that activation and reconciles ambiguous commits
  without clearing counters or lockouts. Install the forward activation
  migration: legacy healthy rows without activation provenance become
  unavailable while their retained facts and windows remain intact. Native
  continuity and owned public-store execution are still required for traffic.

- Restart a live velocity recovery traversal after projection loss with new
  generation-bound custody and zero applied progress. Preserve the original
  expiry, history origin and journal lifetime; stale closure and publication
  cannot survive. Matching retries reconcile successful commit ambiguity
  without erasing successor progress. The applied and publication migrations
  are required. Restart does not activate traffic or authorize native effects.

- Export recorded velocity publication confirmation into exact configured core
  custody without writing or refreshing the primary record. Every use rechecks
  original lease, covered cut and recorded confirmation; stale custody denies.
  Retained lease and coverage checks preserve caller cancellation after primary
  IO. Export remains distinct from native continuity and healthy admission.

- Record the configured native owner's exact covered-cut publication in the
  primary epoch without reopening traffic or extending the original lease.
  Matching retries reconcile commit ambiguity without refreshing confirmation;
  renewal and takeover clear superseded records. Install the additive
  publication migration for confirmation; existing lease/page APIs remain
  usable without it. Confirmation is not proof of present native continuity.

- Export primary-authenticated covered velocity closure through the configured
  recovery graph without renewing its lease or cut. Stable keyed identity binds
  original scope, applied progress and continuous coverage; stale or uncovered
  custody cannot reach the native consumer. Export is not healthy admission.

- Add primary full-window coverage checks to recovery closure. The forward
  coverage migration records journal lifetime in the existing epoch owner;
  unknown historical provenance requires a full-window warmup, while renewal,
  takeover and a new projection boot preserve established continuity. Stable
  cuts alone remain insufficient for native health. Legacy lease/page APIs do
  not require the optional coverage migration.

- Prepare an opaque durable recovery closure in the existing epoch owner after
  all retained changes are applied. Its writer fence rejects new same-scope
  evidence while preserving unchanged terminal replay; renewal or expiry
  invalidates the closure and reopens evidence admission. Matching retries
  recover the original cut after commit ambiguity. Closure grants neither
  historical-coverage proof nor native publication or healthy admission.

- Resume velocity replay from authenticated durable applied progress, preserving
  same-owner renewal while replaying from zero after takeover or a new epoch.
  Corrupt anchors, stale leases and ambiguous commits disclose no cursor;
  unresolved suffix history remains discoverable. Resumption grants no health
  or native-effect authority and requires the applied-progress migration.

- Authenticate original recovery records into issuer-bound public cross-adapter
  custody with privately retained, separately paired issuance capabilities, and
  checkpoint attributable terminal effects in scoped journal order. The opt-in
  forward applied-progress migration preserves populated history and starts
  with no applied authority. Duplicate acknowledgements are idempotent; missing,
  unresolved, corrupt, foreign issuance and stale ownership fails closed.
  Legacy lease/page construction remains supported without owned replay.
  Healthy publication and
  complete native recovery composition remain unfinished.

- Preserve original authenticated velocity attempt identities and fingerprints
  in restricted recovery projections. Use the core's stable replay profile for
  journal insertion and terminal lookup without changing retained digest bytes,
  seals, outcomes or window times. Corrupt history returns no partial page;
  projection grants no counter mutation or healthy-epoch permission.

- Document and exercise public CAPTCHA issuance/recovery with the real audit
  and lifecycle PostgreSQL contributors, including anonymous/admin scopes,
  ambiguous acknowledgement, original response conservation and atomic
  rollback after effect writes. No application-owned effect stores are needed.

- Execute native CAPTCHA current-use checks and atomic terminal finalization in
  the protected coordinator transaction. Reject expired, altered or foreign
  evidence before mutation and commitment. Release only after rollback or
  unanimous primary noncommit proof, including after verifier removal or
  expiry; unresolved and divergent ownership remains retained, never reusable.

- Add native CAPTCHA consuming reservation and exact-generation takeover in the
  existing coordinator transaction. Require committed original issuance and
  complete signed evidence/consumer linkage; conserve expiry and reservation
  time, denying stale lock-wait prechecks and terminal/foreign ownership without
  partially advancing command authority. Domain consumption remains unfinished.

- Preserve signed CAPTCHA consuming custody alongside protected feature
  target/version fields through `MapCaptchaUse`. Authenticate exact native
  plans under selected current verifier configuration without invoking callbacks
  or conflating risk and authorization policies. This construction/admission
  boundary grants no durable consumption or protected-mutation authority.

- Add an opt-in forward CAPTCHA consuming-custody migration preserving issued
  evidence and encrypted responses. Reserved and terminal consuming states
  require complete journal-bound ownership and original-expiry constraints;
  unresolved legacy consuming history fails the upgrade instead of being reset.
  Runtime protected consumption remains under development.

- Add owned public CAPTCHA execution and independently current-authorized
  original-response recovery through the shared coordinator. Bind immutable
  trusted pre-auth, authenticated or administrator flow to the verified caller;
  conserve encrypted original responses across restart and lost acknowledgement,
  without provider reevaluation, new bearers or renewed historical expiry.
  Protected consumption and complete lifecycle/release profiles remain pending.

- Add an independently allocated forward CAPTCHA scope-custody upgrade. Preserve
  populated aliases and serialize new reservations against retained key versions,
  denying omitted keys and disjoint-key races without scanning token history.
  Referenced versions cannot be deleted while retained aliases depend on them.
  Pin version-to-secret commitments and require original reviewed retained
  custody for populated upgrades; omission or same-version secret substitution
  fails closed. Conserve original pending ownership across retained-key additions.

- Add selected immutable CAPTCHA profile authentication, durable all-alias
  reservation and exact-generation rebind, same-Work encrypted issuance and
  primary participant recovery. Preserve replay ownership across domain rollback
  and original database-bound validity. The public issuance executor, complete
  rotation/retirement policy and protected-use workflow remain unfinished.

- Add a separately selected forward CAPTCHA custody migration. Preserve
  committed replay winners, all retained fingerprint aliases/key versions and
  distinct user/anonymous evidence storage independently of payload erasure.
  Installation requires the existing kernel/risk namespace and does not enable
  runtime issuance or protected consumption; native executor work remains open.

- Add token-free native CAPTCHA issuance command mapping for user and anonymous
  flows, strict signed-custody restoration, and separate encrypted original
  response custody. Preserve original aliases, metadata and validity; altered
  command scope or metadata cannot decrypt historical responses. These are
  preparation contracts, not a completed durable CAPTCHA issuance executor.

- Add explicitly selected native administrative lockout start/end contributors
  with current policy and actor-epoch checks, original primary-time freshness,
  exact-version CAS and same-transaction canonical effects. End preserves the
  original interval; selected admission requires attributable domain history.
  Install the new forward domain-version migration and authorization authority
  schema before enabling mutation. Existing profiles remain unchanged; the
  owned workflow executor reads actor epochs and resolves the original committed
  snapshot without caller-written transactions, refreshed retry permits or
  substituting latest state. Canonical risk-service composition remains pending.
  This selected profile requires the authorization authority contract at the
  same revision already consumed by the kernel and core risk module.

- Add forward-only lockout transition storage preserving populated restriction
  versions, original intervals and keyed roots. Native linkage requires a
  canonical opaque record ID and an exact same-tenant start/end command;
  partial custody and inconsistent end state fail. Installation grants no
  transition authority. Native start/end execution and ended-state admission
  remain unfinished; existing interval-only admission stays unchanged.

- Add opt-in current durable lockout enforcement under protected-command locks.
  Active restrictions survive retained-key rotation and counter-window reset;
  unavailable state denies and expiry uses original exclusive primary time.
  Install the forward lockout migration before selecting `EnforceLockouts`.
  Existing counter-only development setup is unchanged. Authorized mutation,
  overrides, recovery routes and complete risk-service composition remain pending.

- Add bounded authenticated velocity change pages under exact live recovery
  custody. Late lower-sequence declarations and post-empty insertions remain
  discoverable without renewing original history or claiming effects/health.
  Install the forward replay migration before upgrading all writers; original
  authenticated history receives bounded native position initialization while
  unsealed legacy history remains unavailable. Renewal preserves continuation
  with its new lease; stale, foreign and takeover custody deny.

- Authenticate complete native velocity intent and terminal history atomically,
  retaining original windows and values and rejecting altered or missing seals
  before readback or replay. Install the new forward integrity migration before
  upgrading all writers. Earlier experimental rows remain unchanged/unsealed
  and fail closed; no automatic backfill blesses unverifiable history. Native
  replay traversal, external-result recovery and health publication remain pending.

- Synchronize velocity intent/result transactions with recovery ownership using
  one scoped database lock held through commit or rollback. Acquisition drains
  overlapping insertions and declarations without losing later evidence or
  renewing history. Cancellation while waiting grants no receipt. Replay scan
  completeness and external effects remain separate unfinished work.
  Upgrade or stop earlier experimental journal writers before relying on drain;
  mixed-version writers do not share this guarantee.

- Add primary database-time velocity recovery leases with one scoped owner,
  monotonic generation takeover, retired-boot denial and exact superseding
  renewal receipts. Initialization records no replay progress or healthy state;
  ambiguous commits grant no custody. Native replay completeness and Valkey
  effect/health publication remain unfinished.

- Atomically retain complete original velocity results and reconstruct historical
  terminal outcomes through `RecordResult` and `ReadResult`. Exact receipt custody,
  persisted scope and every retained alias are rechecked. Conflicting terminal
  declarations, incomplete history and unrepresentable snapshots fail closed;
  matching replay never refreshes observations. Unknown cannot become noncommit
  or authorize redispatch. External-result reconciliation and Valkey replay/health
  publication remain separate unfinished work.

- Persist authenticated ephemeral attempt intent and all retained target aliases
  atomically through `VelocityJournal`. Pending replay cannot redispatch, changed
  intent cannot overwrite its journal, and unknown commits expose no receipt.
  Install the additive `VelocityIntentMigrationSource` and use the updated risk
  dependency. It preserves populated velocity/evidence history without inventing
  snapshots. This does not enable terminal completion, recovery or healthy Valkey.

- Add forward-only `VelocityMigrationSource` recovery storage for keyed ephemeral
  attempts, original snapshots, retained aliases and unavailable-by-default boot
  epochs. Existing evidence and protected-counter migration history is unchanged.
  This is storage support only: native journaling, fenced replay and atomic Valkey
  health publication remain required before enabling the ephemeral adapter.

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
