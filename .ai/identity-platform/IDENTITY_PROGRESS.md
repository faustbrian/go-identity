# Identity Platform Progress

Implementation activated by the user on 2026-10-14. B1, B2 and B3 are closed;
M04 email lifecycle is active.

- Replacement-primary profile closed (2026-10-15 14:47 UTC): reference
  `4a10c0f` is on origin/main with Required `38754176873` green. Public consumers
  can nominate the exact verified replacement and atomically remove/promote it
  through native/opt-in HTTPS, without renewing verification or advancing
  authority twice. Fourteen public-dependency PostgreSQL/race journeys pass
  (38.739s), including the five new native/HTTP/rollback/contention/unknown
  variants and nine earlier removal scenarios. Reference/command race, tagged
  vet, bounded HTTP fuzz, selected secrets/structure/docs and complete independent
  review pass; public published-runner initialization passes. All prerequisite
  source commits (`2d1115c`, `03bac9a`, `85ed1e5`) are on main with CI green.
  No Tools changes, tags or deployment. Admin/stronger-factor, OTP/auto-signin,
  privacy/lifecycle completeness and full-unit qualification remain; M04 is
  still open and full delivered milestones remain 3/39.

- Replacement-primary profile (2026-10-15 14:37 UTC): five genuine PostgreSQL/
  race journeys now remove a primary and promote the exact versioned verified
  replacement through native/HTTPS composition, preserving verification age,
  remaining signin/reset, required session effects and original replay/recovery.
  Late rollback restores both records; competing requests have one winner;
  uncertain commit recovers the original result. All 14 old/new removal profiles
  pass (36.221s), affected module race/vet and bounded parser fuzz pass, and
  complete independent source review approves the 26-path candidate. Root API
  `2d1115c` is pushed to main; nested public pins/composition and final main CI
  delivery remain. This new profile is not closed yet; full M04 stays open and
  full milestones remain 3/39. Prior safe-removal delivery below remains valid.

- Safe-removal profile closed (2026-10-15 14:18 UTC): reference `1ae0790`
  is on origin/main with Required `38749879283` green. Selected password/
  known-empty-MFA consumers can remove a verified or pending address through
  public native/opt-in HTTPS composition, retain actual remaining-address
  signin/reset and observe required old-session denial and pending cascade
  admission. All nine public-dependency PostgreSQL/race removal scenarios pass
  (25.749s), including independent migrations, rollback, contention, populated
  upgrade and uncertain-commit recovery. B1/B2/B3 journeys/upgrades pass
  (61.830s), reference/command unit race and tagged vet pass, and independent
  complete review approves unchanged 68-path source `28b57921`. Published-module
  runner initialization passes without sibling replacements. Full M04 stays
  open: explicit replacement-primary, administrator/stronger-factor profiles,
  OTP/auto-signin and privacy/lifecycle completeness and final unit qualification
  remain. Pending cascade admission is not completed asynchronous cleanup.
  Two legacy Valkey-backed MFA/reset attempts lacked fixtures and are not
  passing evidence. Full delivered milestones remain 3/39; no new unit is verified.

- Integration checkpoint (2026-10-15 14:07 UTC): native removal `038260b` and
  opt-in HTTP `d81001e` are reviewed, on main and CI green; capability `ab21810`
  and outbox `9663e96` are also delivered/green. Public-source reference removal
  journeys pass. Final integration review found missing independently selected
  rate migration and incorrect shutdown failure shape; both are fixed with
  focused red/green proof, including actual operator/rate/HTTPS use. Baseline
  regressions, final affected reference checks/re-review and reference delivery
  remain. Full M04/unit qualification is not claimed; still 3/39 full milestones.

- Public prerequisite checkpoint (2026-10-15 13:41 UTC): reviewed PostgreSQL
  removal `65ce0f3` is delivered to main with green Required. Outbox `5c13952`
  and capability `ab21810` have independent approval and public-source native
  PostgreSQL/race proof, but await protected-main CI/delivery. Their initial
  temporary-ref runs failed before runtime selection because the CI diff base
  was zero; seeded refs now carry the exact sources without lowering checks.
  Final native password/HTTP/reference public binding, complete profile review
  and delivery remain; safe removal is local only, M04 open and delivered 3/39.

- Removal checkpoint (2026-10-15 13:33 UTC): all eight real PostgreSQL/HTTP
  profiles pass with race, including rollback, competing removals, ambiguous
  commit recovery, populated upgrade and actual remaining-address signin/reset.
  Public request contracts `5e4052e` are on main with green Required; independently
  approved kernel `65ce0f3` is on main with Required pending. Removal event cascade
  correlation had been dropped downstream; the minimal adapter fix now passes
  real reference and public-source native SQL/race tests and is under review.
  Capability/password/HTTP/reference public dependency integration, final review
  and delivery remain. M04 is not closed; still 3/39 milestones delivered.

- Native safe-removal checkpoint (2026-10-15 12:55 UTC): real PostgreSQL/race
  reference journeys now remove either a verified or a pending address,
  reject old sessions/removed-address signin, retain original retry/recovery and
  pending cascade identity, retire the pending target link, then actually sign in
  and reset through the remaining verified address. Local source workspace, not
  public delivery yet. HTTP and remaining failure/concurrency proof, public pins,
  complete review and main delivery remain. Still 3/39 milestones closed.

- Delivered-link profile closed (2026-10-15 11:56 UTC): reference `31b51a9`
  is on origin/main with Required run `38730702735` green. Consumers can list/get,
  add/resend/verify and change their primary email through opt-in public HTTP
  backed by native PostgreSQL, including old-address notice and session effects.
  Independent complete review approved the exact committed patch. Public-source
  HTTPS/upgrade and B1/B2/B3 regression journeys, final race/vet and fresh-cache
  documented runner initialization pass. No sibling source replacements needed.
  Safe removal is now active; M04 stays open, still 3/39 complete milestones.

- Public consumer checkpoint (2026-10-15 11:51 UTC): native email add/resend/
  confirmation/primary-change workflows are reviewed and on main (`456332d`),
  Required green. Normal public dependencies now pass the selected HTTPS email
  and B1/B2/B3 plus populated-upgrade journeys; no local supplier replacement
  is needed. Final reference review/delivery and fresh-cache documented runner
  remain before closing the delivered-link profile. Safe removal follows; full
  M04 and whole-unit qualification remain open. Still 3/39 milestones delivered.

- Public custody checkpoint (2026-10-15 11:09 UTC): secure envelope v2 lower
  owners and workflow/HTTP/native MFA are pushed to main (`f168811`, `ed660e7`),
  Required green. Native session public-source and real PostgreSQL race/vet,
  secrets and independent review pass; delivery is next. Capability/migrations
  candidates await protected-main delivery. Password/magic-link/OTP and final
  email reference public composition remain; safe removal follows link-profile
  closure. Still 3/39 delivered, not another closed consumer outcome.

- Native dependency checkpoint (2026-10-15 10:22 UTC): MFA `c2503b8`, session
  `40f3c12` and OTP `4cfde77` are on main with green hosted checks, real native
  PostgreSQL/race proof and independent final reviews. Magic-link native SQL,
  unit race/vet and bounded fuzz pass; its source delivery review is pending.
  Password unit race passes, but real integration cannot compile against its
  old migration pin. Current upstream main lacks the existing retained
  namespaced/discovery/atomic/resumable bootstrap APIs too. A bounded owning
  migration port preserves the current engine and APIs; no test bypass or new
  verification machinery. Password/native integration and final public-source
  email reference composition remain next, then safe removal. Still 3/39.

- Public transport checkpoint (2026-10-15 09:46 UTC): `5d5bf82` is pushed to
  main with green Required CI. Consumers have opt-in email address reads,
  keyed verification/change HTTP requests and distinct confirmation handlers,
  with native/reference composition still pending. Six child HTTP modules,
  HIBP and both risk adapters pass public-source race/vet; real PostgreSQL risk
  integration and selected fuzz pass. Independent review exposed two buffered
  disclosure failures (early guard cleanup and the operation-owned deadline);
  both have red/green regressions, full email race/vet and complete approval.
  MFA's native adapter now builds/tests against public dependencies; real SQL
  proof is next, followed by the remaining native adapter chain/reference.
  M04 and safe removal remain open; delivered stays 3/39. Authentication fixture
  scanning and whole-platform/unit qualification are not claimed resolved.

- Public-owner checkpoint (2026-10-15 09:25 UTC): email/risk/i18n foundation
  `f43df04` and rate-limit atomic/saturation admission `0ebce39` are delivered
  to main with green hosted checks and complete independent source review.
  Workflow/HTTP binding `af758fe` is now pushed to identity main; its hosted
  Required check is running. Standalone public-source password, magic-link,
  MFA, OTP and HTTP race/vet pass, as do selected parser fuzz runs. Those are
  real consumer module checks, not yet the final composed native M04 journey.
  Next: child HTTP/HIBP/risk public bindings, native adapters and the frozen
  PostgreSQL/HTTPS link journey, then safe removal. HIBP's old HTTP-client pin
  is unavailable; the supported released v2.1.0 transport is under affected
  compatibility checks. Authentication's synthetic-fixture scan and full-unit
  qualification remain open. Consumer milestones remain 3/39.

- Latest prerequisite checkpoint (2026-10-15 08:39 UTC): capability `2bb797e`
  and identifier `9892f17` are now on origin/main after exact-source hosted CI
  passed. Their complete native local checks and independent final reviews pass;
  the identifier's offline generation remains byte-reproducible. Email, risk and
  localization now pass standalone public-dependency race checks (risk/i18n also
  vet); these consumer binding changes remain local. Current public rate-limit
  v2 lacks the atomic batch API and PostgreSQL migration directly consumed by
  HTTP/reference. The bounded additive port, not a replacement engine, passes
  root/all-package unit race and vet, real PostgreSQL original-command/rollback/
  lost-ack/burst-refill scenarios and 10,000 receipt fuzz executions. Its native
  static/API/docs check, independent review and source delivery remain pending.
  No new consumer outcome closes: delivered remains 3/39. The final public M04
  HTTPS composition, then safe removal and full unit qualification remain open;
  authentication's central synthetic-fixture scan is still unresolved.

- Latest prerequisite checkpoint (2026-10-15 08:06 UTC): native delivery/
  PostgreSQL `9684f45` and native outbox `2f1e128` are on origin/main, hosted
  CI green. Both use authenticated public dependencies; real PostgreSQL/race,
  API checks and complete independent reviews pass. Capability's native v2
  participant `f06ff01` plus public GoDoc correction `c539674` is committed on
  its source CI ref, not main. Hosted checks exposed integer-range findings
  and a required workspace; corrections pass real integration/race and pinned
  security analysis. Final local check is rerunning after cold-run timeout
  reallocation within the unchanged total test budget. Identifier's additive
  fixed-Unicode port is reviewed/committed as `54d59e6`, publicly downloadable
  as `v2.0.3-0.20261015075448-54d59e67717e`, not on main yet. Review caught and
  fixed codepoint-versus-byte IDNA hyphen validation; public red/green, official
  corpora, race/fuzz, reproducible upstream data, API/docs checks pass. Hosted
  CI then flagged five integer conversions; explicit bounds preserve public
  behavior, and their final native check/review remain pending.
  Then rebind/prove the final M04 public composition and finish safe removal.
  Authentication central fixture scanning remains unresolved. Delivered is
  still 3/39; these prerequisites do not close a consumer milestone or unit.

- Latest prerequisite checkpoint (2026-10-15 06:47 UTC): identity PostgreSQL
  `bdc73de`/documentation `3bfdb5b`, delivery/session `1f0b46a`/documentation
  `608e4cd`, audit PostgreSQL `d62df28`, and outbox preparation `37ea154`
  are on their mains with eligible source CI green. The optional outbox
  lifecycle adapter passes standalone public-dependency integration/race
  (8.009s) and complete independent review after rejecting remote DSN fallbacks;
  its commit, public self-download and hosted delivery remain pending.
  Corrected new independent adapter paths omit the root engine's `/v2` before
  their physical directory. Next: publish the native outbox source, repin
  delivery/PostgreSQL and capability adapters, then prove the final M04
  composition and safe removal. Authentication fixture scanning remains open.
  Delivered remains 3/39; no new whole-unit/platform qualification is claimed.

- Latest prerequisite checkpoint (2026-10-15 06:02 UTC): identity root `5afeba0`
  and authorization `a9fe820` delivered to their mains, applicable CI green.
  Standalone public-dependency PostgreSQL race/vet and real SQL integration
  now pass, including reset and prepared MFA after test-fixture corrections;
  production migration SQL is unchanged. Complete PostgreSQL review precedes
  its delivery. Authentication central scanning of synthetic JWT fixtures
  remains unresolved, and full-unit documentation qualification remains open.
  No new consumer milestone closes: 3/39; M04 safe removal, composed final
  review/delivery and remaining platform capabilities are still outstanding.

## Live ownership and update rule

This is the live progress record for implementation in go-identity on main.
Keep it current at material consumer delivery/verification changes and every
six hours of active implementation. No idle-session timer or new reporting
framework is required. Keep the current milestone in [EXECUTION_LEDGER.md](EXECUTION_LEDGER.md).
Historical planning ledgers and evidence stay at their original locations.

## Current state

- Compatibility checkpoint (2026-10-15 05:41 UTC): identity root now passes
  race using actual public dependency downloads without the supplier workspace;
  matching PostgreSQL code passes local race. Caller major-version changes are
  local, not delivered. Password's Secret/parameter extension is on main with
  CI green. Authentication/authorization extensions are reviewed committed
  candidates; authorization CI retries a confirmed action-download failure.
  Authentication main delivery needs a centrally reviewed exception for six
  exact public synthetic JWT fixtures; repository scanner exceptions are not
  authoritative, and the required Tools release needs separate authorization.
  Audit's restored transaction contributor, forward migrations and writer grants
  pass unit race and real PostgreSQL replay/rollback/retention/composition. No
  Tools implementation has started; consumer integration continues. M04 link
  delivery/removal and full unit qualification remain open: still 3/39 delivered.

- Source delivery checkpoint (2026-10-15 05:04 UTC): kernel PostgreSQL managed
  email transitions are reviewed and on identity main as `1abac9f`, after root
  `8c06f54`. Module race (12.848s), native identifier/rollback/contention checks
  (3.909s), current decoder fuzz (6.332s) and vet pass. The inherited test-fixture
  atomic copy was corrected without runtime changes. Both identity Required
  source checks pass. Capability root `5d37bc9` and OpenAPI `77bfaaf` are now
  also on their respective mains after eligible push CI; their CI-only refs are
  removed. A concrete public-source gap remains: retained authorization,
  authentication, password and audit-PostgreSQL extensions are absent from
  current public mains and their old revisions no longer resolve. Repinning
  alone cannot supply the consumed contracts. Port only those contracts to
  current majors before public-download/adapter delivery. The password v2
  secret/parameter port now passes standalone full race/vet, bounded fuzz and
  native boundaries, and is in independent review. No hashing/entropy engine
  API or historical evidence machinery was restored. M04 remains open, 3/39
  delivered; these prerequisite source deliveries are not whole-unit release
  qualification. The disposable PostgreSQL server/data/password are removed;
  task-owned supplier archives/caches remain live for this compatibility run.

- Source delivery checkpoint (2026-10-15 04:49 UTC): kernel pending-email
  restart and atomic verify-primary transitions plus capability v2 contracts
  are reviewed and pushed to identity main as `8c06f54`. Root race (1.804s),
  vet and changed-content secret checks pass; its actual Required CI passes
  (38683294730), which is planning/secrets proof, not hosted runtime proof.
  Downstream PostgreSQL/adapter pins are being advanced in dependency order.
  Capability's bounded digest conversion passes full local gosec and focused
  race; its exact-source push CI and OpenAPI's push CI remain live. Dispatch
  checks cannot satisfy protection, so the existing workflows now also select
  scoped identity CI-only push refs; no checks or rules were weakened. The
  standalone root download check exposes inherited unavailable supplier pins;
  committed-supplier runtime proof remains valid, public-download qualification
  remains open. M04 consumer profile/removal are not delivered: still 3/39.

- Latest M04 consumer outcome (2026-10-15 04:32 UTC): the running reference
  HTTPS backend now supports keyed add/resend/verification and primary-email
  change/confirmation through actual selected native owners. The two real
  PostgreSQL/HTTPS journeys pass under race (37.242s), including original
  retries, cooldown/supersession, old notices, saved-session denial and new
  signin. Portable request ports, closed cookie/Origin/CSRF HTTP selection,
  graph lifetime protection, affected unit race and bounded handler fuzz pass.
  These journeys now also pass against the capability v2 port (37.478s), as do
  native adapter composition/rollback/recovery/supersession (7.235s), affected
  unit race and baseline plus combined reset/change command journeys (20.695s).
  The upstream OpenAPI extension bug is fixed and independently approved;
  full HTTP unit race now passes (13.372s). Approved capability root `189b41d`
  and OpenAPI `8de9186` commits await protected-main CI via exact-source CI-only
  refs; neither is on main yet. Adapter/source pins and full M04 final review
  and main delivery remain; identity M04 itself is still uncommitted.
  Safe removal remains subsequent, not silently closed by this profile.
  Delivered stays 3/39, with whole-unit qualification still open. No Tools or
  historical evidence work was added. Current disposable fixture remains live
  while the bounded checks and compatibility investigation finish.

- Latest M04 consumer outcome (2026-10-15 03:31 UTC): optional keyed native/
  reference add/resend/change now preserves the original result after proof
  consumption and process reconstruction. Real registration/signin/cookie
  journeys prove retry, cooldown, rollback, supersession, new-address confirmation,
  old-address notice, saved-session denial and new-address signin (race,40.276s).
  Concurrent keyed add creates one address/grant/message; changed intent and
  ineligible signer deny. Read-only rate metadata authenticates original custody
  before mutable session lookup, without allocating a mapping or consulting an
  unavailable provider on replay. Native integration, affected unit race/vet and
  bounded parser fuzz pass. All work remains local/uncommitted and retained-v1.
  Delivered remains 3/39; full-unit qualification is open. Next is the portable
  request port plus actual request HTTP/reference wiring, then change-confirm
  reference transport, review, capability v2 compatibility and main delivery.
  Task-owned PostgreSQL, wrapper/workspace, Go caches and scratch are removed.

- Latest M04 consumer outcome (2026-10-15 03:02 UTC): genuine registration,
  verification and signin now reach address list/get over actual reference
  HTTPS with native data/version/disclosure policy. Shared-safe-rate, standalone
  and get-only selections pass, including target/credential/query denial and
  absent-address non-disclosure (race, 9.041s). The same running backend now
  passes address reads plus both signup/managed-link confirmation (33.830s).
  Redaction and final-write expiry/cancellation/status/body guards pass; known
  primary account blocking denies the self profile. HTTP/reference unit race,
  vet and bounded query fuzz pass. No new tooling/evidence engine was introduced.
  Keyed add/resend/change HTTP and selected change reference transport remain,
  followed by final review, capability v2 compatibility and main delivery.
  All M04 work remains local/uncommitted; delivered is still 3/39, with full unit
  qualification open. The next keyed-request mapping investigation is complete;
  its native report and concrete reuse boundary are retained in the live ledger.

- Latest M04 consumer outcome (2026-10-15 02:40 UTC): one explicitly selected
  reference HTTPS route now verifies both signup and managed-address links after
  authenticating their signed original profiles. The actual signup/signin/add/
  resend/successor-confirmation journey passes with wrong origin/callback,
  signature tampering, exact replay and second-command denial (race, 33.789s).
  No failed-source fallback, automatic signin or new crypto authority is used.
  A real denial-classification defect is fixed: receipt-free native Forbidden
  stays a refusal with unknown outcome, not an outage or fabricated rollback.
  Affected HTTP/password/reference unit race and vet pass. Keyed add/change,
  address-read HTTP and selected change transport still need wiring; final review,
  capability v2 compatibility and main delivery remain. All M04 work is local/
  uncommitted; delivered remains 3/39 and full unit qualification is still open.
  Its isolated PostgreSQL, supplier workspace/archives, Go caches and exact task
  scratch are stopped/removed (02:42 UTC).

- Latest M04 consumer outcome (2026-10-15 02:23 UTC): opt-in reference native
  composition now constructs the actual email/proof/risk/delivery owners and
  migrations. Genuine registration/signin reaches graph-owned address list/get,
  add/delivery/resend/verification and primary change/old notice/session denial.
  Query-only selection needs no password-verification selection. Populated B1
  upgrade/retry preserves identity/session versions and the exact original
  operator record, then completes change. The combined five real PostgreSQL
  consumer selectors pass under race (42.310s); reference unit race (8.374s),
  reference vet and diff check pass. No fake domain stores or manual selected
  migration SQL supply this graph proof. Full keyed management/read HTTP and
  authentic shared signup/managed verification routing are next, followed by
  final review, capability v2 compatibility and main delivery. All M04 work is
  local/uncommitted; delivered remains 3/39, with no new whole-unit qualification.
  The isolated PostgreSQL server, temporary supplier workspace/archives, Go
  caches and exact task scratch are stopped/removed (02:24 UTC).

- Latest M04 consumer outcome (2026-10-15 01:55 UTC): primary-email change now
  passes over actual HTTPS/native PostgreSQL after genuine signup/signin,
  including wrong origin/callback, replay/original recovery, old notice, saved
  session denial and new-address signin (both first-primary and replacement).
  HTTP grouping preserves one email feature and distinct native actions;
  unknown outcomes and malformed/nonprimary disclosure remain withheld.
  HTTP/email and password adapter race/vet pass; native plus HTTPS change
  integration passes (7.072s). This is a public feature mounted on the genuine
  native owner, not full FeatureSet email composition. Native reference config,
  keyed request/read transport and shared signup/managed verification routing,
  final review, v2 compatibility and delivery remain. Still local/uncommitted,
  3/39 delivered; no whole-unit qualification or new percentage is claimed.
  Owned PostgreSQL, temporary workspace and Go caches are stopped/removed.

- Closure correction (2026-10-15 01:39 UTC): no profile has been delivered during
  M04's first two six-hour active windows. Stop adding removal prerequisites and
  close the working link-based list/get/add/resend/verify/change profile through
  opt-in HTTP/reference, independent review, v2 compatibility and main delivery.
  Then finish removal. This changes sequencing, not feature scope or denominator;
  M04 stays open and delivered remains 3/39. The new removal storage prerequisite
  passes real PostgreSQL target retention/rollback, exact unused-grant retirement,
  historical fail-closed classification and reservation-recovery conservation.
  Full supplier consumption integration and selected public signup cases pass
  under race (5.521s), unit race/vet pass. These local retained-v1 results do not
  supply the missing native removal API or qualify current capability v2 main.
  Its isolated database, temporary supplier workspace and Go caches are stopped
  and removed (01:40 UTC); no shared/user resources were touched.

- Latest M04 outcome (2026-10-15 01:08 UTC): genuine signup/signin reaches native
  new-address change and a second true-primary replacement. Each captures the
  original old recipient, verifies/promotes once, invalidates saved current
  sessions, sends the old notice and permits new-address signin. Exact replay and
  proof-free recovery do not duplicate effects or disclose a fresh address.
  Success, rollback and one-winner contention pass on real PostgreSQL under race.
  Rollback keeps current sessions and both address states unchanged and conserves
  the failed command's audit/cause. This is local native consumer behavior, not
  complete HTTP selection or main delivery. M04 is uncommitted; delivered stays
  3/39. Safe removal/remaining failure cases, full reference transport composition,
  independent final review, capability v2 migration and main/Required CI remain.
  Removal's pure policy now denies losing the last verified email; its native
  transaction/token lifecycle is still unimplemented. The bounded change run's
  database, supplier workspace and Go caches are stopped/removed (01:20 UTC).

- Latest M04 outcome (2026-10-14 17:57 UTC): actual signup/verification/signin
  now reaches native add -> captured link -> fresh login/password proof -> durable
  resend cooldown -> replacement delivery -> predecessor denial -> successful
  successor confirmation. Late rollback preserves the original link/proof;
  proof-free request recovery returns acknowledged metadata and denies foreign
  scope. The original verified signin address is unchanged. Real PostgreSQL
  consumer race test passes (32.20s) with an actual 30s selected cooldown, not
  aged authority. This is native public composition after HTTPS baseline, not
  complete management HTTP/reference selection. Primary change/removal,
  contention/remaining denial partitions, final review, capability v2 migration
  and main delivery remain. Delivered milestones stay 3/39; M04 is uncommitted.

- Resend prerequisites (2026-10-14 17:22 UTC) pass locally: signed stable managed
  mailbox family, capability-owned predecessor invalidation and populated upgrade,
  plus exact pending verification-generation restart through the shared kernel
  writer. Native SQL proves replacement rollback preserves predecessors and commit
  invalidates only older selected unused grants without erasing recovery. Existing
  signup/unselected behavior stays separate. These are prerequisites, not a public
  resend outcome: fresh-primary orchestration, cooldown, common pre-domain fence,
  replacement delivery and successor confirmation still require wiring and proof.
  Delivered milestones remain 3/39; no additional unit qualification is claimed.

- Latest M04 checkpoint (2026-10-14 16:44 UTC): the native managed add journey now
  reaches explicit atomic verification after captured delivery and scanner-safe
  inspection. Proof use/address effects commit together; exact replay is metadata
  only, second-command use denies and proof-free recovery preserves the original
  result. Late SQL failure rolls back address/use and reconciles noncommit.
  Credential/authorization changes deny inspection and confirmation. Final success
  and rollback race selectors pass; affected kernel/password/MFA/capability race
  checks, adapter vet and bounded feature-plan fuzz pass. The selected managed
  confirmation endpoint also passes over real TLS with native PostgreSQL IP,
  subject/challenge counters, proof use and address effects. Exact HTTP retry keeps
  original audit correlation; changed protected intent still conflicts. Existing
  signup transport tests and the original B1 native baseline remain green.
  Resend, primary change, removal, real signup-to-management and full reference
  signup/management route composition remain; no new milestone is
  closed. User authorized finishing M04 against the retained v1 adapter locally,
  then migrating the adapter and affected consumers to capability v2 before main
  delivery. All M04 code is still local/uncommitted; no complete review, main push
  or Required CI is claimed for it.

- M04 implementation has started locally. Email-owned authorized list/get now
  preserve primary address and verification versions, apply explicit owner/admin
  and disclosure policy, filter non-email rows, and bind bounded pagination to
  exact scope and unchanged primary versions. Email unit race and bounded cursor
  fuzz pass. The public native query API also passes after genuine registration,
  delivered verification and signin with original session admission against real
  PostgreSQL (TestReferencePostgresEmailQueries, 5.924s). These changes are local
  and uncommitted; independent review and delivery are pending. Add/resend/change/
  remove, atomic proof/session/lifecycle effects and opt-in query HTTP remain.
  No additional consumer milestone or whole unit is closed.
  The native password-owned email proof bridge is also local: genuine signed
  action/session/actor checks pass; protected coordinator proof use rolls back
  with failure, commits once with effect/audit, and denies a second command.
  An opt-in migration extends the existing one-use constraint without rewriting
  installed history. This is prerequisite contract proof, not a completed email
  mutation, recovery or HTTP journey. All M04 changes remain uncommitted.
  The native integration now commits a real pending address with original
  password-proof consumption and required audit, preserving the verified primary.
  Late failure rolls back address/proof/version effects; stale versions and
  canonical collisions deny unchanged. Existing kernel persistence regression
  also passes. Managed-link policy tests with real signing reject original-intent
  substitutions and signup/management confusion; email race/vet and bounded fuzz
  pass. Kernel race passes; explicit kernel vet has an unchanged MFA-fixture
  copy-lock diagnostic. Native issued-state/encrypted delivery, confirmation,
  change/removal, HTTP and complete review/delivery remain disconnected. No
  additional consumer milestone is closed.
  Native EmailManagementService now passes request-to-captured-link integration:
  original password verification -> atomic pending address/issued grant/encrypted
  delivery -> owned worker -> captured address-bound management link with real
  signature verification. Repeated worker processing and stale/used proof send
  nothing again. Runtime fixture account/factor state is explicit; real-signup
  consumer and opt-in HTTP composition remain owed. Kernel/password/MFA adapter
  race checks pass. Inspection/confirmation, resend, primary change/removal,
  recovery and complete-profile review/delivery are next; M04 is not closed.
  Scanner-safe managed-link inspection now passes the same real native path:
  committed request -> owned worker capture -> repeated original-intent reads
  by actual current confirmation authority -> boolean current-state validation.
  Wrong tenant/action/user/revision/callback and configuration deny; current
  blocking, changed MFA and revoked issuance deny; provider outage fails closed;
  cancellation is preserved. Reads neither consume the link nor send again.
  The original journal rejects ciphertext substitution, and generic preparation
  query regression remains green. Latest native race run passes (2.247s), kernel
  unit race passes (3.132s). Atomic confirmation, resend, primary change/removal,
  actual signup-to-management and HTTP remain owed. Changes stay uncommitted;
  no additional milestone/unit or full qualification is claimed.

- B3 is closed. Its native PostgreSQL/HTTPS journey passes:
  wrong-current-password
  and CSRF denial, fresh verification without session extension, keyed change,
  both original sessions denied, old-password rejection, new-password signin
  and stale-proof denial. Additive keys preserve original baseline custody.
  A scoped request-admission policy defect and duplicate-key JSON acceptance
  were reproduced and corrected. Affected native unit race tests pass;
  native HIBP audit attribution and populated migration checks also pass.
  Repeated race runs exposed a concrete shared HTTP defect: successful tenant
  admission forwarded its two-second callback context into the entire workflow,
  truncating the configured router deadline. The focused regression failed
  before correction and now passes; original request deadlines/cancellation
  are preserved and the callback timer is retired before dispatch. The complete
  selected Baseline race suite now passes, including B1/B2, fresh B3 and its
  populated upgrade. PostgreSQL-only native rollback/scoped recovery and the
  isolated legacy keyed-change compatibility cases pass. Independent review
  found a combined consumer
  walkthrough using the pre-reset credential. Its added regression failed,
  then passed after carrying the successful reset's password/version into
  change; standalone reset/change journeys also pass. Complete final review
  approved tree dbd3b480. Source 24b1b08 is on origin/main; a reviewed one-file
  scanner-preparation fix 47a3ee0 preserves the fatal scan deadline and private
  verifier/runtime cache separation. Required CI passed in run 38559659144.
  **3/39 consumer milestones delivered**; full unit/release qualification is
  not claimed. Next is M04 email lifecycle. Whole-goal completion remains a
  rough low-confidence 5-10% estimate, not measured effort or a qualification
  score. Most capability families and final package qualification remain.

- B2 now passes the local public HTTPS reset journey: two saved original
  sessions, captured request delivery, repeated non-consuming inspection,
  committed completion/exact replay, changed replay and consumed-proof denial,
  both original sessions denied, old-password denial and new-password signin.
  Populated B1-to-reset upgrade preserves the account and original operator
  request; separate reset migration retry passes. Native selected reset checks
  cover expired/unissued/foreign proofs, current factors, rollback/recovery and
  no repeated password work. Independent complete review approved the corrected
  full source tree 94e5b34a after original-audit-custody and at-capacity restart
  findings were reproduced and resolved. Final reference unit/race and all
  Baseline PostgreSQL/race integration cases pass, including original audit
  reconciliation after actual COMMIT acknowledgement loss. Delivered to
  origin/main as fd439aa; Required CI passed in run 38547848026. B2 is closed:
  the second consumer milestone delivered. Earlier transient signin failures
  remain unattributed; the current full pass does not prove an environmental
  cause. Broader HTTP, legacy-fixture, public-download and full-release
  qualification are not claimed.
  Overall remains a rough low-confidence 5-10% estimate, not measured effort.

- Delivered: B1 authentication, B2 reset and B3 fresh password verification/change
  on the runnable PostgreSQL backend. Next is M04 email lifecycle. The complete
  fresh
  PostgreSQL-only B1 HTTP journey now passes locally with captured delivery and
  existing rollback/replay/CSRF/isolation checks. It does not backdate history.
  The runnable HTTPS consumer also passes locally using the command's public
  graph, real PostgreSQL, private captured delivery and a synthetic HIBP IO
  seam. It proves wrong/unverified-password denial, CSRF, saved-cookie revocation
  and clean shutdown. Reproducible source wiring and walkthrough now exist;
  the frozen source-runner integration passed. Independent review found two
  filesystem-durability defects; their new failure/recovery regressions failed
  before correction and now pass with the affected command under race.
  Complete final review approved the corrected slice, delivered on origin/main
  as `90d4f2c`; Required CI passed in run `38527264686`. B1 is closed:
  B1 was the first delivered milestone. No new whole-unit verification is
  claimed. Native runtime proof is local, not hosted runtime/deployment proof.
- Existing runtime source checkpoint: identity main `ef377dd`. Adopt it;
  documentation commits do not restart its implementation or invalidate
  unchanged runtime proof. Verify live Git state on activation.
- Proven selected workflow at the prior reviewed checkpoint: native email-OTP
  enrollment, encrypted delivery/confirmation, password-origin challenge,
  selected HTTP send/verify, session/CSRF issuance, public session read,
  credential-free replay and factor-version invalidation with real PostgreSQL.
  This does not substitute for B1 or full MFA/unit qualification.
- Historical recorded unit counts: 5/67 integrated and 2/67 verified, with
  0/61 fully qualified product units. These are prior records, not a new
  qualification audit or an overall effort percentage. Reconcile only affected
  units from their native evidence as implementation proceeds.
- Hosted check scope: documentation-only run 38513309150 passed Required on
  `833df6f`. Historical run 38501126112 failed on imported-history secrets.
  The later pass is not runtime/full-history qualification and does not repair
  that old result. Assess B1's actual affected checks; isolate a reproduced
  delivery failure, not a dashboard cleanup or new planning/tooling programme.
  B1 changed-content secrets and local repository/config/cohesion/docs/offline
  specification checks passed. Whole-history secrets still fail on unchanged
  committed history; full-release qualification remains pending.
- Closed Tools PR #338 stays closed. No historical evidence import, Tools-main
  planning publication or completion of the retired repair goal is required.
- Full target remains 67 units, 19 journey categories and 10 shared-issuer cases.
  The complete prompt is IMPLEMENTATION_GOAL.md in the preserved planning
  snapshot supplied by the user. No specification/history migration is needed.

## Consumer outcomes (39, unweighted)

The rows below record actual milestone closure, not helpers or release counts.
An unassessed row is not a claim that its existing code is missing. Do not
restart old slices merely to fill this table; adopt applicable prior proof.

| ID | Consumer outcome / owning units | Current disposition |
| --- | --- | --- |
| B1 | Runnable registration/verification/signin/session/logout baseline: identity, identity/postgres, identity/password, identity/password/postgres, identity/session, identity/session/postgres, identity/delivery, identity/delivery/postgres, identity/http, identity/reference; required primitive contracts | Closed: reviewed native PostgreSQL/HTTPS journey, reproducible consumer walkthrough, main 90d4f2c and Required CI 38527264686. Public-dependency journeys and published runner initialization subsequently pass at 1ae0790; full-unit qualification pending. |
| B2 | Reset and required session invalidation using the baseline owners plus identity/risk/hibp | Closed: reviewed native PostgreSQL/HTTPS reset, two-session revocation, original audit recovery and populated upgrade; main fd439aa and Required CI 38547848026; full-unit/release qualification pending |
| B3 | Password change and fresh reauthentication through baseline owners | Closed: reviewed PostgreSQL/HTTPS verification/change, two-session revocation, populated upgrade, original auditing, rollback/recovery and combined reset/change; main 24b1b08 plus CI-only 47a3ee0, Required CI 38559659144; full-unit/release qualification pending |
| M04 | Email add/change/verify/list/get/remove with session/lifecycle policy: identity/email | Delivered profiles: public PostgreSQL/HTTPS list/get, keyed add/resend/verification/primary change (`31b51a9`), safe password/known-empty-MFA removal (`1ae0790`) and explicit atomic replacement-primary removal (`4a10c0f`), independently reviewed with main CI green. Administrator/stronger-factor, OTP/auto-signin, privacy/lifecycle completeness and final qualification remain; full row not closed. |
| M05 | Username availability/signin/rename: identity/username, stable identifier contracts | Closure not reassessed |
| M06 | Delivered magic-link signin and session: identity/magiclink | Closure not reassessed |
| M07 | Purpose-bound email OTP request/delivery/completion: identity/otp, identity/otp/postgres | Closure not reassessed |
| M08 | Verified phone enrollment/change, OTP/password signin and reset: identity/phone, OTP/password owners | Closure not reassessed |
| M09 | Anonymous session, self-deletion and collision-safe permanent upgrade: identity/anonymous, identity/anonymous/postgres | Closure not reassessed |
| M10 | Confirmed TOTP enrollment and TOTP signin: identity/mfa, identity/mfa/postgres | Closure not reassessed |
| M11 | Confirmed secondary-OTP enrollment, delivered-code signin and session: MFA/OTP/password/session owners | Selected email profile proven; full milestone not closed |
| M12 | Factor listing/update/removal/disable/replacement with fresh proof: MFA owners | Closure not reassessed |
| M13 | Recovery-code reveal/use/regeneration and independently approved administrative recovery: MFA owners | Closure not reassessed |
| M14 | Trusted-device issuance/use/revocation and step-up: MFA/session owners | Closure not reassessed |
| M15 | WebAuthn register/assert ceremony and durable credential validation: webauthn, webauthn/postgres | Closure not reassessed |
| M16 | Passkey-first registration, discoverable signin and credential management: passkey, passkey/postgres | Closure not reassessed |
| M17 | Social OAuth authorization-code/S256 callback to session: identity/oauth, identity/oauth/postgres, identity/oauth/providers | Closure not reassessed |
| M18 | Social account linking/unlinking and stored provider-token refresh: OAuth owners | Closure not reassessed |
| M19 | Verified One Tap to identity/session: identity/oauth/onetap | Closure not reassessed |
| M20 | Bounded OAuth proxy callback to the intended application: identity/oauth/proxy | Closure not reassessed |
| M21 | User/organization API-key issue/import/verify/rotate/revoke: identity/apikey, identity/apikey/postgres, identity/apikey/valkey | Closure not reassessed |
| M22 | Organization create/manage/join/invite/remove and authority lifecycle: organization, organization/postgres | Closure not reassessed |
| M23 | Teams and dynamic roles/permissions enforcement: organization, authorization contracts | Closure not reassessed |
| M24 | Bans/session administration and bounded audited impersonation: identity, session, identity/impersonation, identity/impersonation/postgres | Closure not reassessed |
| M25 | Verified domain/provider registration and federation policy: sso, sso/domain-verification, sso/postgres | Closure not reassessed |
| M26 | Enterprise OIDC/OAuth federation, mapping/JIT/linking and session: sso/oidc, sso/oauth2 | Closure not reassessed |
| M27 | SAML federation including replay/lifecycle policy: sso/saml | Closure not reassessed |
| M28 | Authorized SCIM discovery/User CRUD/filter/PATCH/pagination: scim, scim/postgres | Closure not reassessed |
| M29 | SCIM Groups, organization reconciliation and deprovisioning effects: scim/organization and organization owners | Closure not reassessed |
| M30 | OAuth client/consent, authorization-code/S256 grants and refresh rotation: oauth-server, oauth-server/postgres | Closure not reassessed |
| M31 | OIDC discovery/JWKS/ID-token/userinfo consumers: oauth-server/oidc | Closure not reassessed |
| M32 | Workload client-credentials issuance, introspection and revocation: OAuth server owners | Closure not reassessed |
| M33 | Restricted token exchange with lineage/non-expanding authority and bounded cache validity: OAuth server, authentication, API-key and organization owners; SI-01 through SI-10 | Closure not reassessed |
| M34 | Device authorization to issuance/expiry/denial: oauth-server/device, optional native PostgreSQL composition | Closure not reassessed |
| M35 | Action-bound risk/velocity/admission and every selected CAPTCHA provider: identity/risk, identity/risk/postgres, identity/risk/valkey, identity/risk/captcha, identity/risk/captcha/recaptcha, identity/risk/captcha/turnstile, identity/risk/captcha/hcaptcha, identity/risk/captcha/captchafox; HIBP remains required when setting passwords | Closure not reassessed |
| M36 | Locale selection and localized public messages/delivery templates: identity/i18n | Closure not reassessed |
| M37 | Privacy export/deletion/anonymization/legal retention and audit investigation: identity and applicable lifecycle owners | Closure not reassessed |
| M38 | Session refresh/rotation, account switching/transfer/enrichment, devices and consistent remember-me, including selected cache projection: identity/session, identity/session/postgres, identity/session/valkey | Closure not reassessed |
| M39 | Complete opt-in reference composition, OpenAPI/readiness, typed extensions/operations and reusable consumer contract suites: identity/reference, identity/http, identity/identitytest; all remaining cross-cutting acceptance | Closure not reassessed |

## Retained package scope (67 units)

The unit list comes from the existing GOAL_MANIFEST.json; dependencies and exact
product contracts remain in the preserved planning snapshot. Update affected
rows only from actual integration/qualification evidence. Consumer delivery and
whole-unit qualification are separate; never mark a unit verified from a
constructor, compile result, milestone fragment or paperwork count.

| Unit | Qualification disposition at preparation |
| --- | --- |
| `primitive/authentication-identity-contracts` | Historically integrated; retain applicable native proof |
| `primitive/authorization-identity-contracts` | Historically integrated; retain applicable native proof |
| `primitive/capability-identity-contracts` | Historically verified; retain applicable native proof |
| `primitive/capability-postgres-identity-contracts` | Historically partial; develop consumed contracts as needed |
| `primitive/identifier-identity-contracts` | Historically integrated; retain applicable native proof |
| `primitive/password-secret-contracts` | Historically verified; retain applicable native proof |
| `identity` | Not requalified by this documentation change |
| `identity/postgres` | Not requalified by this documentation change |
| `identity/session` | Not requalified by this documentation change |
| `identity/session/postgres` | Not requalified by this documentation change |
| `identity/session/valkey` | Not requalified by this documentation change |
| `identity/delivery` | Not requalified by this documentation change |
| `identity/delivery/postgres` | Not requalified by this documentation change |
| `identity/risk` | Not requalified by this documentation change |
| `identity/risk/postgres` | Not requalified by this documentation change |
| `identity/risk/valkey` | Not requalified by this documentation change |
| `identity/risk/captcha` | Not requalified by this documentation change |
| `identity/risk/captcha/recaptcha` | Not requalified by this documentation change |
| `identity/risk/captcha/turnstile` | Not requalified by this documentation change |
| `identity/risk/captcha/hcaptcha` | Not requalified by this documentation change |
| `identity/risk/captcha/captchafox` | Not requalified by this documentation change |
| `identity/risk/hibp` | Not requalified by this documentation change |
| `identity/password` | Not requalified by this documentation change |
| `identity/password/postgres` | Not requalified by this documentation change |
| `identity/username` | Not requalified by this documentation change |
| `identity/email` | Not requalified by this documentation change |
| `identity/magiclink` | Not requalified by this documentation change |
| `identity/otp` | Not requalified by this documentation change |
| `identity/otp/postgres` | Not requalified by this documentation change |
| `identity/phone` | Not requalified by this documentation change |
| `identity/anonymous` | Not requalified by this documentation change |
| `identity/anonymous/postgres` | Not requalified by this documentation change |
| `identity/mfa` | Not requalified by this documentation change |
| `identity/mfa/postgres` | Not requalified by this documentation change |
| `webauthn` | Not requalified by this documentation change |
| `webauthn/postgres` | Not requalified by this documentation change |
| `passkey` | Not requalified by this documentation change |
| `passkey/postgres` | Not requalified by this documentation change |
| `identity/oauth` | Not requalified by this documentation change |
| `identity/oauth/postgres` | Not requalified by this documentation change |
| `identity/oauth/providers` | Not requalified by this documentation change |
| `identity/oauth/onetap` | Not requalified by this documentation change |
| `identity/oauth/proxy` | Not requalified by this documentation change |
| `identity/apikey` | Not requalified by this documentation change |
| `identity/apikey/postgres` | Not requalified by this documentation change |
| `identity/apikey/valkey` | Not requalified by this documentation change |
| `identity/impersonation` | Not requalified by this documentation change |
| `identity/impersonation/postgres` | Not requalified by this documentation change |
| `organization` | Not requalified by this documentation change |
| `organization/postgres` | Not requalified by this documentation change |
| `sso` | Not requalified by this documentation change |
| `sso/domain-verification` | Not requalified by this documentation change |
| `sso/oidc` | Not requalified by this documentation change |
| `sso/oauth2` | Not requalified by this documentation change |
| `sso/saml` | Not requalified by this documentation change |
| `sso/postgres` | Not requalified by this documentation change |
| `scim` | Not requalified by this documentation change |
| `scim/postgres` | Not requalified by this documentation change |
| `scim/organization` | Not requalified by this documentation change |
| `oauth-server` | Not requalified by this documentation change |
| `oauth-server/oidc` | Not requalified by this documentation change |
| `oauth-server/device` | Not requalified by this documentation change |
| `oauth-server/postgres` | Not requalified by this documentation change |
| `identity/i18n` | Not requalified by this documentation change |
| `identity/http` | Not requalified by this documentation change |
| `identity/reference` | Not requalified by this documentation change |
| `identity/identitytest` | Not requalified by this documentation change |
