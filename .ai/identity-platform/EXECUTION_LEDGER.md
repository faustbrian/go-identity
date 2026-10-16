# Identity Implementation — Current Milestone

Activated on 2026-10-14. B1, B2 and B3 are closed; M04 email lifecycle is active.

## Active: M04 email lifecycle; administrative-removal profile delivered

- Administrative-removal profile closed (2026-10-16 00:43 UTC): foundation
  `9785b1c`, native password/HTTP `9ee4c44` and reference `ffc3b47` are on
  origin/main; exact-head Required runs `38829897110`, `38830322339` and
  `38830970598` pass. Actual authorized A removes B's versioned email with A's
  fresh one-use proof/session preserved separately from B's atomic mutation,
  audit/cascade, token retirement and session invalidation. B's remaining
  configured signin/reset works; A's session/authority stays unchanged.
  Current exact target grants are checked for original/restored unfinished
  preparation outside SQL locks; terminal historical replay stays unchanged.
  GOWORK-off public-dependency PostgreSQL/HTTPS tests pass all eight selected
  journeys in 30.019s using the disposable PostgreSQL fixture and this command:

  ```sh
  go test -race -tags integration -count=1 -timeout=180s \
    -run '^TestReferencePostgres(AdministrativeEmailRemoval|EmailRemovalKeepsVerifiedSigninReset|AdministrativeEmailQueriesHTTPS)$' .
  ```

  Affected owner/reference/command race and tagged vet, bounded removal fuzz,
  changed-content secrets and planning checks pass. Independent complete review
  `/root/m04_admin_removal_final_review` APPROVE covers original base `d877f24`,
  corrected source46 `c34b719f77d333975a2dccce6d6569168aaf1d66254a37bdf88b5861278ff84d`
  and final public52 `d35c1c5367fd99b2e5f7d6b70a6f4f24a017f75b869ea343c319d3462f426314`;
  the final tree matched that reviewed snapshot before publication. Published
  runner `v0.0.0-20261016004146-ffc3b47efb33` initializes from an empty consumer
  directory with GOWORK off, no database/listener or local source overrides.
  Full M04 stays open: stronger-factor, OTP/auto-signin, privacy/lifecycle
  completeness and final unit qualification remain. Full milestones3/39;
  no new qualified unit, Tools change, tag or deployment. Reuse unchanged proof.

- Local administrative-removal checkpoint (2026-10-16 00:28 UTC): eight selected
  real PostgreSQL/HTTPS/race journeys pass30.408s (six administrative modes plus
  self removal/admin reads). Independent review of snapshot `5d7c8eba` requested
  changes for missing exact target permission on retained work. Original-input
  withdrawal and genuinely retained-output withdrawal both reproduced commit
  before the correction; current checks run only in out-of-transaction
  preparation/restoration, not locked callbacks or terminal historical replay.
  All affected module race/tagged vet, bounded removal fuzz and local docs/
  structure passed before that correction; affected reruns/final review and
  public pin/main delivery remain. Root/email/kernel/MFA public GOWORK-off race
  checks pass; no Tools change or new evidence machinery. Full M04 stays open.

- Frozen administrative-removal profile (2026-10-15 15:34 UTC): explicitly
  selected native/HTTPS administrator A removes B's exact versioned email using
  A's original fresh action-bound password proof/session/CSRF, with authoritative
  known-empty MFA for A and B. Current exact tenant/actor/action/target policy is
  mandatory. Preserve B's actual remaining configured password signin/reset,
  target session invalidation, token retirement, atomic audit/cascade and keyed
  replay/unknown recovery; A's sessions and credentials remain unchanged.
  Preserve legacy self requests/custody bytes and closed disabled HTTP selection.
  Add narrow actor credential/authorization admission using existing kernel
  checks, deterministic cross-subject row locking before either subject's locks,
  and actor proof consumption in the existing password record/transaction.
  No new proof/store/replay engine. Stronger MFA/OTP/admin impersonation are not
  selected; enrolled/unknown factors deny, never weaken to password-only.
  Reuse bounded `/root/m04_admin_boundary` map at main `d877f24`; suppliers root
  `2d1115c`, kernel `03bac9a`, password/PG `85ed1e5`, MFA/PG `ed660e7`, email
  `6f013f9`, HTTP/email `15b4764`. Owners: kernel/email/MFA/password/HTTP/reference.
  Prove two genuine accounts, target retained signin/reset and revoked target
  sessions, actor preservation, missing grant, wrong/stale actor proof, active
  factors, foreign target, changed-key input, rollback/one-use, contention and
  original ambiguous recovery. TDD focused native/API tests; disposable real
  PostgreSQL/HTTPS race; affected module race/tagged vet, changed-input fuzz,
  public pins/consumer proof, selected secrets/docs/structure, one complete
  independent review, ordinary main/Required delivery. M04 stays open.

- Administrative-read profile closed (2026-10-15 15:27 UTC): native `6f013f9`
  and HTTP `15b4764` are on main, Required `38759536861`/`38759823377` green.
  Reference `91397a7` is on origin/main with Required `38760195512` green.
  Published runner `v0.0.0-20261015152518-91397a78110d` initialization succeeds
  with GOWORK off and no database/listener opened. Six public SQL/HTTPS/race query
  profiles PASS13.355s; reference/command race8.557s/6.775s and tagged vet pass.
  Distinct genuinely registered actors/targets prove exact permission, durable
  safe audit, acknowledgement failure, self preservation and unchanged primary
  identity/verification/command/one-use state. Native public race1.293s,
  HTTP public race13.017s and vet pass; query fuzz18771exec/6.395s passes.
  Selected secrets/structure/docs pass. Independent native reviewer
  `/root/m04_admin_reads_final_review` APPROVE binds original base `08ab596`,
  source22 `4bdf04391e7620f504a4893915b2e70187b8971378a28aa4153ac5fafa6e1bd2`,
  final reference11 `fca2d6ba485934a52daef551c0ae47587b4aa7eb59ef5846313351491cf41b0f`
  and committed public26 `05b52fd5d9c1bbe9abdfc747313bd923af1a8a1b3ac1fd9330b19ce975fed013`.
  The final committed source matches the approved public26 digest exactly.
  This frozen profile is closed; reuse its unchanged runtime evidence.
  Admin removal still needs genuine independent actor-scoped proof admission;
  stronger-factor, OTP/auto-signin and privacy/lifecycle completeness remain.
  Full M04 stays open, delivered full milestones3/39; no new unit qualification.

- Frozen M04 administrative-read profile (2026-10-15 14:59 UTC): authenticated
  human A can explicitly target B for native and opt-in HTTPS email list/get,
  only under current tenant/action/target authorization and safe redaction.
  Existing native query/repository already separates actor/target; HTTP is self
  only. Add required fail-closed administrative access audit at the shared query
  owner, backed by existing audit/PG in reference; no new journal or domain store.
  Audit errors/unknown ack, current permission/session failure, stale policy,
  foreign/absent targets, cross-scope cursors, cancellation/shutdown deny output.
  Preserve self routes, no credentials/refresh/mutation, disabled target override
  rejection and current shared safe-rate ownership. No risk-profile override or
  unselected risk-evaluator bypass is introduced. Admin removal remains separate:
  native original session/credential/proof admission is still actor=self and
  cannot be relabelled into actor-scoped proof inside target-scoped Work.
  Bounded map `/root/m04_admin_boundary` is retained; do not restart it.
  Owners: email query/audit contract, HTTP email decode/projection/OpenAPI and
  reference native/HTTP/audit composition; existing session, authorization,
  audit/PG and primary repository. Baseline main `08ab596`, runtime `4a10c0f`,
  root `2d1115c`, email/PG `03bac9a`, HTTP `85ed1e5`, audit/PG `d62df28`.
  Tests: focused audit-required red/green, native/HTTP contract+schema/race,
  changed query fuzz, real public reference PostgreSQL/HTTPS with distinct real
  actor/target, durable safe audit and negative/cleanup cases; affected vet,
  public pins/consumer, secrets/structure/docs, one independent complete review,
  ordinary main/Required delivery. No broader qualification or other profile.

- Replacement-primary profile closed (2026-10-15 14:47 UTC): reference
  `4a10c0f722593b4e6d7a333364dca13523bbf5cf` is on origin/main; Required
  `38754176873` passes. Parent verified exact committed 36-path source digest
  `2e97b8acddfa5e84dc2f17f33594dacaf742f791f85c7fb1d0c3b1651df7e2c4`
  unchanged from independent `/root/m04_replacement_final_review` APPROVE;
  final reference7 digest `49a7bcce65b3d77752e82323661811794ee4e6a994390267d2a63460b3089f68`.
  Root `2d1115c`, email/kernel `03bac9a` and native password/HTTP `85ed1e5`
  public pins are independently revalidated and main/CI green. GOWORK-off real
  SQL/race14profiles PASS38.739s; reference/cmd race9.896s/9.103s, taggedvet,
  selected secrets, local planning/docs/diff checks pass. Public
  `go run github.com/faustbrian/go-identity/reference/cmd/identity-baseline@v0.0.0-20261015144451-4a10c0f72259 init`
  with local capture/private directory succeeds without a database or listener.
  This closes the frozen profile; do not add neighboring variants to its diff
  or repeat unchanged verification. Full M04/units remain open, count3/39.
  Next bounded mapping: current administrative email authority and independent
  actor/target proof/transaction contracts, then freeze one supported next path.

- Replacement publication checkpoint (2026-10-15 14:37 UTC): complete source
  review `/root/m04_replacement_final_review` APPROVE binds base `8be20a7` and
  26-path digest `00e350175f10133188af4aee068d2a973511948175262d922f6fcbf1ede60929`.
  Root4 subset digest `9267aa9ef5746b32994fbbbd25cf38be0f86d029f658fa792f4e985285f7563b`
  is committed/pushed as `2d1115c` (`20261015143552`), root public source/race/vet
  pass; Required `38752841914` is running. Email/kernel pins are advancing to
  that public root, then native password/HTTP, then reference. No local source
  replacement will remain in public delivery. All 14 removal SQL/race profiles
  pass36.221s; full six affected modules' race/vet, schema/input regressions,
  legacy custody byte compatibility, non-inferred selection and bounded decoder
  fuzz (2030executions/8.473s) pass; selected secrets/structure/docs pass. Public
  nested composition and reviewed final pin closure remain; do not close yet.

- Frozen next profile (2026-10-15 14:25 UTC): explicit versioned replacement
  primary in password/known-empty-MFA self-removal, through the existing native
  `AddressRemove` and opt-in reference HTTPS endpoint. Consumer nominates one
  different already-verified email belonging to the same partition; removal
  and promotion commit together, aggregate/authority advance once, verification
  age is never renewed, and existing token/session/audit/cascade/replay custody
  remains atomic. Reject absent/unverified/self/foreign/stale/overflow targets,
  extraneous replacement fields in old dispositions and changed keyed replay.
  Prove real registration/add/verify/primary -> removal/promotion -> retained
  signin/reset, rollback, contention and unknown recovery; no new migrations,
  private stores or replacement engine. Admin, stronger MFA, OTP/auto-signin,
  async closure and full-unit qualification stay outside this finite profile.
  Owners: root pure transition, email request, kernel locked preparation/writer,
  native password original intent, HTTP decoder/OpenAPI and reference journey.
  Adopt source baseline `8be20a7` / runtime `1ae0790`, native `038260b`, kernel
  `65ce0f3`, public email `5e4052e`, capability `ab21810`, outbox `5c13952`.
  Focus: root/email/kernel/native/HTTP unit race and tagged vet; real reference
  `TestReferencePostgresEmailRemoval*` SQL/race via disposable loopback PG;
  bounded changed decoder fuzz; public dependency/consumer proof, changed-content
  secrets, local structure/docs, one complete independent review, main/CI delivery.

- Safe-removal profile closed (2026-10-15 14:18 UTC): reference `1ae0790`
  is delivered on origin/main, Required `38749879283` green. Independent native
  `/root/m04_removal_native_final_review` APPROVE binds base `31b51a9`, precursor
  head `d81001e` and exact 68-path source digest
  `28b579212985f41cfa87d42093ea3dc362f3836278e0d2000dd0af0d7f379fe4`;
  committed bytes are unchanged. Nine actual PostgreSQL removal/race profiles
  pass (25.749s); reference unit race 13.837s, command 8.931s, tagged vet,
  changed-content secrets and all local planning/doc checks pass. Five B1/B2/B3
  public CLI/runtime journeys and populated upgrades pass (61.830s). Public
  `go run github.com/faustbrian/go-identity/reference/cmd/identity-baseline@v0.0.0-20261015141547-1ae0790cd201 init`
  with explicit local capture/private directory resolves authenticated public
  dependencies and initializes, without local replacements or sibling source.
  Selected native/HTTP self-removal preserves remaining actual signin/reset,
  required session effects, original replay/recovery and pending cascade identity.
  This closes the frozen profile now; do not reopen it for neighboring variants.
  Full M04 remains open for explicit primary replacement, admin/stronger-factor,
  OTP/auto-signin, privacy/lifecycle completeness and whole-unit qualification.
  Asynchronous consumer completion is not claimed; legacy Valkey/MFA attempts
  without their TLS fixture remain unverified. Full delivered count stays 3/39.

- Prior replacement-profile intent (now delivered above): explicitly nominate a verified replacement primary during
  safe self-removal and apply that exact versioned promotion in the same native
  transaction. Current delivered requests deliberately support only preserving
  an existing primary or leaving it unassigned; do not weaken those semantics
  or infer a replacement by ordering. Map the existing identifier mutation/
  version/persistence owner once, then freeze the finite profile before coding.

- Integration checkpoint (2026-10-15 14:07 UTC): native password removal/base
  HTTP `038260b` and opt-in email HTTP `d81001e` are independently approved,
  on origin/main and Required green. Capability `ab21810` and outbox `9663e96`
  are also on origin/main with exact-source and main Required green. Final
  reference normal public-dependency removal SQL/race passes (24.426s); unit/
  command race and tagged vet pass. Integrated review requested two concrete
  reference fixes: independently selected keyed email must install atomic rate
  history, and removal lifetime rejection must emit its own closed response.
  Both have red/green regressions; independent operator/rate/HTTPS removal now
  passes (5.437s). B1/B2/B3 public CLI regressions are running, followed by final
  affected reference verification and one complete final-diff re-review. Earlier
  email HTTPS regressions passed; extra legacy Valkey-backed MFA/reset attempts
  lacked their TLS fixture and are not passing evidence. No M04/profile closure
  or whole-unit qualification yet; delivered full milestones remain 3/39.

- Public prerequisite checkpoint (2026-10-15 13:41 UTC): kernel `65ce0f3`
  is on main with Required `38743441315` green. Outbox projection `5c13952`
  and capability target-retirement `ab21810` are independently approved local
  main commits, not yet delivered to origin/main. Public-source unit/race/vet
  and full native SQL/race pass (outbox 4.729s; capability 7.726s). A first
  temporary-ref creation failed CI's zero-before classifier, not runtime tests.
  Capability now qualifies through the existing seeded `chore/identity-custody-ci`
  (`38744543417`). Outbox's separately seeded `chore/identity-outbox-removal-ci`
  is allowed by reviewed one-line CI commit `9663e96`; all checks/permissions
  remain unchanged. Wait for eligible green source checks, push these exact main
  commits, then bind native password/HTTP/reference public dependencies and close
  the complete-profile review. Do not restart unchanged tests or tooling work.

- Removal checkpoint (2026-10-15 13:33 UTC): all eight real PostgreSQL/HTTP
  removal profiles pass with race (23.366s), including primary disposition,
  denial/rollback, exact replay, competing attempts, lost commit acknowledgement,
  populated upgrade and actual remaining-address signin/reset. Independent
  review approves public root/email `5e4052e` (main/Required green) and kernel
  `65ce0f3` (main, Required pending). A real regression reproduced downstream
  outbox loss of cascade correlation; the minimal optional-field projection
  preserves old event bytes and now passes the removal journeys, public-source
  adapter race/vet and full native SQL/race (4.729s). Adapter prerequisite review
  is active. Native capability, password, HTTP/reference public pins and final
  complete-profile review/delivery remain; M04 stays open, delivered 3/39.

- Native removal checkpoint (2026-10-15 12:55 UTC): both actual PostgreSQL/
  reference journeys pass with race: verified-address and pending removal retain
  real remaining-address signin/reset, reject removed-address signin and old
  sessions, preserve original retry/recovery/cascade admission, and retire the
  target pending link. Combined risk revisions and optional factor-storage test
  composition are corrected without bypasses. Local source workspace only;
  HTTP, remaining failure/concurrency cases, public pins, review and delivery
  remain. No milestone or whole-unit qualification closes.

- Delivered-link profile closed (2026-10-15 11:56 UTC): reference `31b51a9`
  is on origin/main, Required `38730702735` green; independent complete review
  approves exact committed patch `6abae994`. Public-source email HTTPS/upgrade,
  B1/B2/B3 regressions, final race/vet and fresh-cache documented runner init pass.
  This closes the frozen link profile, not M04 or whole-unit qualification.
- Safe-removal profile: authenticated human with known-empty MFA, fresh original
  password proof, exact expected address/version, reason and explicit primary/
  recovery disposition. Supported native removal and opt-in HTTP/reference must
  keep an actual verified password signin/reset path; revoke only target-bound
  unused grants and apply required identifier/session, audit and lifecycle effects
  in the existing Work/partition lock. Preserve original retry/recovery custody.
  Existing bounded mapping/QA/token-boundary reports remain inputs; no new plan
  chain. Exclude administrator/stronger-MFA variants, never silently downgrade.
  Prove success then remaining-address signin/reset; last-path/wrong/stale/cross-
  scope denial; exact-target grant retirement; rollback/replay/unknown/contention.
  Use focused native PostgreSQL/race, API/HTTP/reference integration and changed
  parser fuzz, then one independent complete-diff review and main/Required delivery.

- Public consumer checkpoint (2026-10-15 11:51 UTC): native delivered-link
  workflows `456332d` are on main with green Required. The normal public module
  graph (`GOWORK=off`, no replacements) passes selected email HTTPS request,
  change, shared signup/managed confirmation, read and populated-upgrade journeys
  (86.257s), plus five B1/B2/B3 and populated upgrade journeys (50.967s). Final
  reference unit race (8.951s), command unit race (8.025s), tagged vet, selected
  secrets and planning checks pass. Complete reference review and fresh-cache
  documented runner initialization remain before delivery/profile closure.
  Capability `401a89a` and migrations `8b5ef1e` are on main, eligible push CI and
  main CI green. The required-check obstacle was dispatch-event eligibility,
  solved using bounded push carriers without bypassing checks or protection.
  Native email fixture isolation/required previous-address intent were corrected
  without weakening production guards; combined real SQL passes (14.407s).
  Safe removal remains next; M04 stays open and delivered remains 3/39.

- Public custody checkpoint (2026-10-15 11:09 UTC): lower session/delivery/risk
  owners `f168811` and workflow/HTTP/native MFA `ed660e7` are on main with green
  Required. Independent review found the previously selected envelope v1.0.0
  lacked retained provider-cause containment; supported envelope v2.0.1 restores
  it. Cross-version ciphertext/AAD and error-containment probes pass. Native
  session v2 composition passes public-source unit race (1.822s), real SQL race
  (29.755s), vet, selected secrets and review; its delivery is next. Native
  capability `401a89a` and migrations `ca105f2` are reviewed public candidates,
  awaiting their own protected-main qualification/delivery. Reuse unchanged
  runtime evidence; do not change Tools or protection. Password/magic-link/OTP
  and final reference public composition remain in progress. No profile closes;
  safe removal follows delivered-link closure, and delivered remains 3/39.

- Native dependency checkpoint (2026-10-15 10:22 UTC): MFA `c2503b8`, session
  `40f3c12` and OTP `4cfde77` are pushed to main with green hosted Required.
  Complete public-source race/vet, real PostgreSQL suites and independent
  final-diff reviews pass; OTP issuance fixtures now supply the required
  structural command metadata without changing admission or production SQL.
  Magic-link public-source unit race (1.370s), real SQL race (7.612s), vet and
  original-output fuzz (10,000x) pass; its 25-path source batch is under review.
  Password unit race passes (2.312s), but integration compilation proves the
  pinned migration version lacks `ForNamespace`. Current upstream main also
  lacks the retained namespaced/discovery/atomic/resumable APIs consumed by the
  actual reference bootstrap. Port that existing additive owner implementation
  onto current migration main, preserving its engine/APIs/dependencies; do not
  bypass the native runner or replace it in tests. Then prove password/native
  and final public reference composition. Selected magic-link source snapshot
  scanning is clean; the unscoped historical scan still fails and is not a
  delivered-history qualification. No M04 profile closes: delivered stays 3/39.

- Public transport checkpoint (2026-10-15 09:46 UTC): `5d5bf82` is on main;
  hosted Required `38715052759` passes. It delivers selected email reads,
  keyed verification/change request transport and distinct link confirmations,
  plus child HTTP/HIBP/risk public bindings. All nine affected module race/vet
  checks pass; real risk PostgreSQL race passes (26.780s), selected parser fuzz
  passes. Complete independent review found premature disclosure-guard cleanup
  and missing operation-owned deadline custody during buffered middleware unwind.
  Both regressions failed before their fixes; buffering race x20 (2.342s), full
  email race (14.515s), vet and new complete independent review now pass. Exact
  committed patch is the approved `61ef1ab3` digest. The old HTTP prose scanner
  false positive was clarified in `6275648`; its hosted check also passes.
  Native MFA adapter now passes standalone public-source race/vet (1.464s);
  real SQL proof precedes its review/delivery, then session/OTP/password adapters
  and reference. No new consumer milestone closes: delivered remains 3/39.

- Public-owner checkpoint (2026-10-15 09:25 UTC): workflow/HTTP bindings are
  reviewed and pushed as `af758fe`; hosted Required is running. Password,
  magic-link, MFA, OTP and HTTP pass standalone public-source race/vet; six
  selected parser fuzz runs pass. Email/risk/i18n foundation `f43df04` and
  rate-limit atomic admission plus saturation `0ebce39` are on main with green
  hosted checks and independent source reviews. Real PostgreSQL atomic replay,
  rollback, raw-byte intent and refill regressions pass. Next dependency wave
  binds child HTTP, HIBP and risk adapters before native workflow composition.
  HIBP's unavailable historical HTTP-client revision is replaced with released
  v2.1.0; borrowed transport/redirect/privacy behavior needs affected proof.
  Delivered remains 3/39. Final public M04 HTTPS proof, subsequent safe removal,
  authentication fixture scanning and whole-unit qualification remain open.

- Prerequisite checkpoint (2026-10-15 08:39 UTC): capability `2bb797e` and
  identifier `9892f17` are on origin/main; exact-source hosted CI, complete native
  local checks and complete independent reviews pass. Email public-download
  unit race passes (1.550s); risk/i18n standalone race/vet passes (1.487s/1.305s).
  HTTP's actual public rate-limit main `ba14272` lacks the consumed optional
  atomic batch service and PostgreSQL migration. One bounded map identifies only
  the additive API/native implementation, retained replay tests and shared token
  refill-horizon correction; existing engines/dependencies/docs remain intact.
  Port tests first fail on the missing public methods/types, then full native
  unit race/vet passes. Real isolated PostgreSQL atomic/replay/intent/conflict/
  lost-ack/rollback/overlap/burst tests pass (1.184s); receipt fuzz passes 10,000x.
  The disposable PostgreSQL cluster is stopped/removed. Native API/static/docs
  qualification, complete independent review and main delivery are next, followed
  by the frozen M04 public HTTP/reference binding/proof. No removal expansion
  before closing that delivered-link profile. Delivered still 3/39; authentication
  central fixture scanning and whole-unit qualification remain unresolved.

- Prerequisite checkpoint (2026-10-15 08:06 UTC): native delivery/PostgreSQL
  `9684f45` and native outbox `2f1e128` are on origin/main, applicable hosted
  CI green. Public dependency downloads, real PostgreSQL/race and complete
  independent reviews pass. Capability participant `f06ff01` plus GoDoc
  `c539674` is committed/publicly resolvable on its CI ref, not main. Its final
  post-verification context fence destroys prepared custody on cancellation;
  four cancellation/deadline one/two-grant regressions failed before the fix,
  then full integration/race 14.030s, fuzz, API/source-docs and review passed.
  Native CI required minimal Go1.27.2 workspace and locally visible integer
  framing bounds; corrected source passes integration/race 21.852s and pinned
  gosec. Native check then timed out in cold local-test at 1m; rebalanced the
  existing 3m total to root 1m/native 2m without removing any selected check.
  Current full native rerun remains pending. Identifier current v2 main
  `429f747` lacked normalization, unlike retained unavailable old sources.
  Its additive port is committed `54d59e6`, independently approved and normally
  downloadable as `v2.0.3-0.20261015075448-54d59e67717e`, not on main yet.
  Full module race, API/docs/workflow, official corpora and exact offline
  generation pass. Review found inherited byte-index IDNA hyphen validation;
  nine public cases failed before fixing rune positions, then race/corpora
  passed (4.535s), and final fuzz with regression seeds passed (11.311s).
  Hosted CI flagged five range conversions; corrected through the existing
  generator/provenance with upstream inputs untouched. New race/corpora 2.023s,
  source-docs/secrets/reproduction pass; final native check/review pending.
  Released identifier families/dependencies remain unchanged. This is the M04
  prerequisite, not a new milestone or historical evidence migration. Final
  public HTTPS composition and safe removal remain; delivered still 3/39.

- Prerequisite checkpoint (2026-10-15 06:47 UTC): identity PostgreSQL `bdc73de`
  plus documentation `3bfdb5b`, delivery/session `1f0b46a` plus `608e4cd`, audit
  PostgreSQL `d62df28` and outbox preparation `37ea154` are on origin/main,
  eligible source CI green. Native outbox candidate `b9956143` (complete patch
  digest prefix, not a commit) passes standalone real PostgreSQL/race 8.009s,
  vet and independent complete review. Review reproduced a remote-fallback DSN
  guard bypass; both test entries now use shared primary/fallback validation,
  with red/green regression. No runtime contributor change was needed.
  New independent child modules use repository-relative paths, not the root
  engine's `/v2` before their directory. Native outbox publication and consumer
  repins precede the final M04 HTTP/reference proof and safe removal. Still
  3/39; authentication central fixture scanning/full-unit qualification open.

- Public PostgreSQL checkpoint (2026-10-15 06:02 UTC): root `5afeba0` and
  authorization `a9fe820` are on their mains with applicable CI green.
  PostgreSQL consumes authenticated public current-major dependencies with
  `GOWORK=off`: unit race 4.742s, vet (including integration-tagged code),
  identifier-mutation SQL race 1.890s and broad native SQL race 29.539s pass.
  Test-only repairs preserve production migration bytes: stop downgrading
  preparation constraints, isolate recovery tenants/fingerprints, use real
  migration history, and replace an inherited denial-only MFA success fixture
  with a live SQL/code precheck. Complete adapter review is active before
  commit. Authentication's synthetic-JWT central scan failure remains open;
  no Tools edit/release/bypass occurred. An unscoped docs check found inherited
  exported-field comment gaps; full-unit docs are not qualified. M04 stays
  open, delivered 3/39. All completed disposable PostgreSQL clusters are removed.

- Public-source compatibility checkpoint (2026-10-15 05:41 UTC): identity root
  now passes standalone public-download race (1.600s), without GOWORK supplier
  substitutions, on the reviewed authentication v2/authorization v3/password v2
  contracts. Native PostgreSQL race passes on the matching local imports
  (5.856s). These caller changes remain uncommitted. Password `4eb0fef` is on
  main with CI green. Authentication `d9f5132` and authorization `a9fe820` are
  reviewed committed candidates on CI-only refs, not main. Authorization's
  latest failure was setup-go archive download; failed-job-only retry is live.
  Authentication's central history scan flags six pinned synthetic JWT vectors;
  repository exceptions cannot change that policy. The exact central fixture
  exception requires a Tools release; scoped publication authority is requested,
  not assumed. Continue integration meanwhile. Audit contributor/migrations and
  least-privilege grants pass native race plus real PostgreSQL replay/rollback/
  retention/coordinator checks (1.979s); its source and major-version caller
  updates remain local. A fixture now names its audit-only operation rather
  than impersonating protected session issuance. Full M04 remains open, 3/39;
  no full-unit or composed shared-issuer qualification is claimed. Both owned
  PostgreSQL runs have stopped and removed their isolated clusters.

- Dependency delivery correction (2026-10-15 05:04 UTC): PostgreSQL source
  `1abac9f` follows root `8c06f54` on identity main; native race/vet, focused
  real PostgreSQL/fuzz and independent source review pass. Both hosted Required
  planning/secrets runs pass. Capability root `5d37bc9` and OpenAPI `77bfaaf`
  are on their mains with eligible exact-source push CI. The consumer profile
  is not closed: public download exposed unavailable old primitive revisions,
  and current authentication v2/authorization v3/password v2/audit-PostgreSQL
  lack consumed retained extensions. Preserve current engines and port only
  needed typed contracts with their existing coverage; this is a prerequisite
  of the same frozen outcome, not a historical-record or Tools programme.
  Password Secret/Parameters currently pass standalone full race/vet, two
  bounded fuzz targets and source/conformance guards on v2; final review is
  active before delivery. Audit root v1.0.0 remains public and unchanged.
  Adapter registration also exposed copied historical benchmark flags without
  a native typed operation; do not call that inventory or unit qualification
  passing. Resolve the actual new-module contract before adapter delivery,
  without silently bypassing or inventing a passing benchmark. Keep removal
  after the delivered link profile. Disposable PostgreSQL is stopped/removed.

- Prerequisite delivery (2026-10-15 04:49 UTC): root kernel source `8c06f54`
  is on origin/main with native root race/vet and independent full-root review
  approved; hosted Required 38683294730 passes its planning/secrets contract.
  It does not certify runtime or public-download qualification. Root public
  dependency resolution still encounters inherited unavailable supplier pins.
  The PostgreSQL prerequisite now selects that actual root source and the
  authenticated capability v2 source `caab644`; its focused verification and
  independent complete-module review are active before the adapter/back-
  dependant pins advance. Capability/OpenAPI eligible push CI remains live;
  manually dispatched green checks were correctly rejected by protection.
  No rule/check bypass, PR or Tools change. M04 remains open, delivered 3/39.

- Request HTTP/reference checkpoint (2026-10-15 04:32 UTC): storage-neutral
  email request ports now forward to the actual keyed native owner. Opt-in
  `HTTPEmailRequests` composes add/resend/change-request and change-confirm in
  the canonical email feature, sharing strict rate ownership and guarding whole
  request lifetime before proof reads. Closed cookie/Origin/CSRF/key inputs and
  original-outcome responses expose no mailbox, credentials or recovery route.
  Both real reference PostgreSQL/HTTPS consumer selectors
  `TestReferencePostgresEmail{Requests,ChangeRequests}HTTPS` pass together under
  race (37.242s): real signup/signin/proof, add/resend/cooldown/supersession,
  successor verification, two primary changes, old notices, replay and saved
  session denial/new-address signin. Initial missing-config compile failure and
  native-clock wiring failure were corrected; keyed address IDs are asserted
  from the actual original request result, not a caller-selected fixture ID.
  Email, HTTP/email and reference unit race pass (1.324s/10.065s/8.598s); exact
  HTTP stored-CSRF policy test passes (1.366s); bounded real handler body fuzz
  passes (6.386s). Capability v2 root custody APIs and native adapter are now
  ported; identity source imports and trusted issuer gates use v2. Both actual
  M04 HTTPS journeys pass on v2 (37.478s), native adapter composition/consumption
  including supersession/rollback/retirement passes (7.235s), and baseline plus
  combined reset/password-change command journeys pass (20.695s). Affected
  direct-consumer unit race passes; current full HTTP race passes (13.372s).
  The OpenAPI failure was upstream extension misclassification. Its narrow fix
  and named-map regressions pass native race/vet/fuzz and independent review.
  Root v2 custody and the OpenAPI fix are separately independently approved and
  committed as capability `189b41d` and OpenAPI `8de9186`. Direct main pushes
  were rejected because Required must run first; exact-source CI-only refs
  carry those commits without PRs or protection changes (runs 38681971480 and
  38681972006). Main delivery remains pending. Adapter/module source pins and
  complete M04 final review/delivery still remain; identity M04 is uncommitted.
  No new milestone closes, and no public-download or whole-unit qualification
  is claimed. Removal remains subsequent. Current task-owned loopback
  PostgreSQL/workspace/caches remain live for this bounded verification session.

- Keyed native/reference checkpoint (2026-10-15 03:31 UTC): implemented
  `KeyedEmailManagementService` over the existing immutable request mapping and
  sole email preparation/transaction. Add/change select winning server command/
  address; resend retains its exact target. Encrypted original session/proof,
  CSRF, domain/previous-address versions, factor generation and counter instants
  restore before live primary reads. Exact retries return original metadata;
  changed intent conflicts without another grant or message. A focused regression
  exposed original-signer replacement being accepted by name alone; retained
  record signature verification now denies it. Concurrent same-key add converges
  on one address/grant/delivery. Existing immutable mapping rejects replacement.
  `RequestRateSource`/graph `RequestRateSourceKeyed` reads original custody before
  live session lookup, including spent-proof/provider-outage retries; absent
  history permits only source reads, no durable mapping or issuance. It grants
  no current authority and returns no metadata on conflict/error.
  Native race selector `TestPrimaryPasswordCredentialIntegration/native-email-management-keyed`
  passes (1.979s). Real signup/signin/cookie graph selectors
  `TestReferencePostgresEmail{ChangeGraph,KeyedChangeGraph,KeyedResendGraph}` pass
  together under race (40.276s): add/resend cooldown/rollback/supersession,
  original replay, two primary changes, old notice/session invalidation and
  new-address signin. Native password/reference unit race pass (2.112s/8.675s),
  both vets/diff check pass; bounded `FuzzKeyedEmailOriginalInput` passes (6.312s).
  No tooling, second journal or crypto authority was added. These results use
  the retained-v1 supplier and local/uncommitted identity tree; no final profile
  review, main delivery or whole-unit qualification. Delivered remains 3/39.
  Next: portable email-owned request port and opt-in HTTP/reference request
  handlers. Authenticate retained proof/possession and rate metadata before
  mutable session lookup, not the reverse; use canonical verification-send
  (add/resend) and change-request IDs. Select change-confirm reference transport,
  then final review, approved capability v2 migration/compatibility and delivery.
  Keep removal after this profile's delivery. Native fixture selectors need
  separate disposable database state; their cluster-global audit roles must be
  cleaned before switching to reference graph fixtures, not fixed in Tools.
  The owned PostgreSQL, workspace wrapper/supplier archives, all three Go
  caches and exact scratch are stopped/removed; all run handles are terminal.

- Address-read HTTP checkpoint (2026-10-15 03:02 UTC): actual reference HTTPS
  list/get now uses native session/query owners, current human-self scope and one
  shared safe limiter. Standalone safe-rate selection enables no HTTP session
  route; get-only exposes no list route. Real PostgreSQL selectors
  `TestReferencePostgresEmail{QueriesHTTPS,QueriesStandaloneHTTPS,GetOnlyHTTPS,QueriesGraph}`
  pass under race (9.041s), covering native versions, credential/target/query
  denials and no identity mutation. The shared signup/managed-confirmation test
  now also selects/runs address reads in that same server; race passes (33.830s).
  HTTP/email unit race (6.898s), reference unit race (8.432s), both vets/diff check
  pass. New query fuzz passes (6.267s) with bounded native decoding. Redaction,
  expiry/cancellation, changed-status/body and streaming response guards pass;
  a blocked-self projection regression failed before its transport correction.
  Native512-byte values and100-row JSON-escaped pages remain bounded without
  truncation. Co-selected reads initially exposed duplicate OpenAPI scheme names;
  operation-owned names now pass real construction. No core validator was changed.
  Still local/uncommitted, 3/39 delivered, no whole-unit qualification. Next:
  keyed add/resend/change requests and selected change reference transport, then
  final review, capability v2 compatibility and main delivery.
- Keyed-request handoff: bounded mapper `/root/m04_email_http_map` confirms the
  existing `ResolvePreparedRequestKey`/`RequestKeyPreparationContributor` mapping
  must restore winning command/address, original session/signed-proof/CSRF,
  domain versions/previous address, link instants, factor/counter input and exact
  request intent before today's primary lookup. Current email `request` still
  does live `Prepare` first; reconstruct local authenticated original input, then
  reuse the existing email phase/sole journal. Mapping may read/encrypt but cannot
  sign links, assess providers, charge counters or mutate. No new journal/cache/
  crypto authority is needed. Retain the native report; do not restart mapping.

- Shared HTTP checkpoint (2026-10-15 02:40 UTC): the real reference server now
  explicitly selects one signup/managed-add verification route. The native router
  authenticates persisted issuance plus signed profile/confirm-action before
  dispatch; selected-owner errors never try another source. Signup verification
  and genuine add/resend successor verification pass on that same HTTPS server,
  with wrong origin/callback, signature tampering, exact replay and consumed-link
  second-command denial. `TestReferencePostgresEmailManagementSharedHTTPS` passes
  under race (33.789s); HTTP/email and password/postgres unit race pass (6.777s,
  2.012s); reference unit race passes (8.886s); all three affected vets and diff
  check pass. New native/router configuration APIs supplied red before support.
  Real testing exposed receipt-free native Forbidden being converted to an outage;
  its focused regression failed, then passed while retaining unknown/no recovery
  and continuing to reject malformed claimed commits. Reference CORS's documented
  plain-text origin denial remains unchanged. Reused bounded mapping from
  `/root/m04_email_http_map`; no new crypto/receipt/cache or tooling owner.
  Still local/uncommitted and retained-v1; keyed request/read HTTP, selected change
  reference transport, final review, v2 compatibility and main delivery remain.
  M04 remains open, delivered 3/39; no new unit or release qualification.
  The isolated PostgreSQL, private supplier workspace/archives, Go caches and
  exact task scratch are stopped/removed (02:42 UTC); all run handles are terminal.

- Native reference checkpoint (2026-10-15 02:23 UTC): `StoreConfiguration.Email`
  selects graph-owned verification/change/address handles, actual native forward
  histories, original proof, risk and encrypted delivery. Unselected/missing,
  inactive/foreign/closed authority denies. Real consumer race selectors
  `TestReferencePostgresEmail{ManagementGraph,ChangeGraph,ChangeGraphUpgrade,Queries,QueriesGraph}`
  pass (42.310s), including actual resend cooldown, new-address confirmation,
  old notice/session effects, query-only selection and populated upgrade/retry
  without rewriting original operator custody. Reference unit race passes
  (8.374s), reference vet/diff check pass. Earlier missing-reference API tests
  supplied red; graph failures exposed inconsistent fixture risk revisions,
  corrected without relaxing native validation. Complete source/catalog changes
  use a new operator command, not rewritten historical requests. HTTP/native
  profile remains incomplete/uncommitted: close keyed management/read transport
  and authentic common verification dispatch, then final review, v2 compatibility
  and main delivery. No milestone/unit closure or new percentage is claimed.
  Its isolated PostgreSQL, temporary supplier workspace/archives, disposable Go
  caches and exact task scratch are stopped/removed (02:24 UTC).

- HTTP checkpoint (2026-10-15 01:55 UTC): public change-confirm now runs the
  shared bounded protected pipeline with its distinct native action, result and
  original recovery; no verification recovery is constructed for a change.
  `FeatureConfig` groups verification and change under one email feature identity
  and rejects ambiguous verification owners. Managed wire metadata no longer
  describes signup. Native `ChangeConfirmationRateSource` supplies exact original
  change challenge metadata without borrowing verification-only admission.
  New API/grouping/source regressions failed before support. HTTP/email unit race
  passes (6.870s); password/postgres unit race passes (1.976s); both vets and diff
  check pass. Actual PostgreSQL signup/signin -> primary change over real TLS
  passes origin/callback denial, fresh/replay, native original recovery, old notice,
  saved-session denial and fresh new-address signin for both sole-verified and
  existing-primary cases. Reference selectors `TestReferencePostgresEmailManagementChange`
  and `TestReferencePostgresEmailChangeHTTPS` pass under race (7.072s). The latter
  mounts the public feature with the actual native owner, not a fake domain store;
  FeatureSet-owned management configuration is still absent, not silently proved.
  Next: reference native owners/selected migrations/lifetime handles; then close
  keyed add/change/read HTTP and one authentic signup/managed verification route.
  Native typed recovery suffices unless recovery HTTP is explicitly selected;
  do not invent missing canonical inspect/recovery operation IDs. Existing native
  M04/B1-B3 evidence remains applicable only to unchanged inputs. No final review,
  profile/milestone delivery, v2 compatibility, commit or push is claimed.
  All bounded-run test handles are terminal; isolated PostgreSQL, supplier
  workspace/archives, Go caches and exact task scratch are removed (01:56 UTC).

- Closure correction (2026-10-15 01:39 UTC): M04 has passed two six-hour active
  windows since B3 without a delivered profile. The concrete drag is combining
  already working add/resend/change with new removal storage/orchestration before
  transport/delivery closure. Split successive complete consumer profiles without
  dropping any M04 obligation or changing 3/39: first finish selected opt-in
  HTTP/reference list/get, add/resend/verify and password-authorized primary
  change/old notice, review and deliver it; then finish safe removal against that
  working backend. Retain all removal code and original acceptance. Do not expand
  removal further before closing the first profile. Capability v2 compatibility
  remains mandatory before owning-main delivery; no retained-v1 overlay on v2 main.
- Removal prerequisite (2026-10-15 01:38 UTC): opt-in issuer retention now stores
  the authenticated signed verification Resource in forward migration 005.
  Default issuance SQL remains unchanged. Real public signup issuance proves
  original target retention, default-null compatibility and late rollback. Native
  SQL proves exact tenant/user/identifier unused issued/reserved retirement,
  exclusion of other targets/subjects/tenants/purposes/used grants, populated
  upgrade, rollback, and fail-closed active unclassified/originless history.
  Revocation conserves original reservation/origin; exact revoked-unused evidence
  is negative for recovery and unanimous terminal reconciliation preserves
  revocation. No new journal/fence/transaction or public removal service exists.
  Bounded mapper `/root/m04_removal_contract_map` and QA `/root/m04_removal_qa`
  found no requirement contradiction; their native reports remain in this thread.
  Focused red failed on missing APIs, then supplier unit race passed (1.320s).
  Full `TestNativeConsumptionIntegration` plus public registration
  `success|target-retention|target-retention-rollback` passed under race (5.521s);
  supplier vet and diff check passed. These are retained-v1 local prerequisites,
  not public removal acceptance, v2 compatibility, final review or delivery.
  The owned PostgreSQL, runner, supplier workspace and Go caches are terminal
  and removed; exact path absence was verified (01:40 UTC). Shared resources
  were untouched. Next is first-profile HTTP/reference closure, not more removal.

- Current checkpoint (2026-10-15 01:08 UTC): actual PostgreSQL signup/signin now
  reaches native ChangeRequest -> captured link -> scanner reads -> ChangeConfirm
  -> old-address notice -> new-address signin. Explicit sole-verified policy
  establishes the first primary without promoting the old signup address;
  a second genuine change replaces an existing primary. Original old-address
  versions/policy are signed and encrypted. Candidate verification/primary and
  directory authority advance once; old verification/time is preserved. Saved
  post-request sessions deny after success; replay/recovery disclose metadata only.
  Real race acceptance passes: success (2.54s), late rollback (2.12s), concurrent
  confirmation (2.17s), via `go -C reference test -race -tags=integration -run
  '^TestReferencePostgresEmail(ChangeRollback|ChangeConcurrentConfirmation|ManagementChange)$' -count=1 -v .`.
  Rollback preserves original/pending addresses and the current session, emits no
  success effects/notice, retains the failure audit/cause and terminally releases
  the aborted grant. Two competing confirmations have one winner. Root/kernel/
  password/MFA/risk adapters pass affected unit race; email's latest unit race
  passes (1.267s). Email/password/MFA/risk adapter vet passes. Known pre-existing
  kernel test-fixture copy-lock vet gap remains. Fixed-depth change-plan decoding
  retains signup/verification bytes; its selected fuzz run passes (11.283s).
  Bounded mapping/QA `/root/m04_change_boundaries` and `/root/m04_change_qa` supplied
  original-address/security cases; no planning restart or evidence tooling was
  added. Source remains local/uncommitted, retained-v1 wired, no full final review
  or new milestone/unit closure. The interrupted earlier race handle/fixtures
  were absent; no result was assumed. Removal, remaining denial/unknown partitions,
  full management HTTP/reference composition, v2 migration and main delivery remain.
- Removal boundary: `/root/m04_removal_token_boundary` confirms verified nonprimary
  email already supports native password signin and reset. The existing complete
  user/identifier partition lock serializes native issuance/confirmation/removal;
  no new target fence is justified. Capability rows currently lack signed Resource,
  so exact-target retirement needs capability-owned retained target metadata and a
  closed same-Work seam. Do not retire all subject grants, omit unclassified legacy
  rows, erase reservation/origin evidence or introduce a replacement store.
- Bounded run closed (2026-10-15 01:20 UTC): pure `RemovalProfile` now rejects
  losing the last verified email and permits retaining an eligible nonprimary
  alternative without inventing a primary. Its regression failed before support;
  selected policy/change-contract race tests pass (1.231s). This is not a native
  removal service or accepted removal journey. Native credential/factor checks,
  exact-target token retirement and coordinated mutation remain next. All tests
  are terminal; isolated PostgreSQL is stopped and the database, supplier
  archives/workspace, owned Go caches and task fixture are removed. No shared or
  pre-existing resources were removed. The goal remains active.

- Current checkpoint (2026-10-14 17:57 UTC): public native add/resend now passes
  after actual HTTPS signup, captured signup verification and genuine signin.
  Fresh login/password proof after the identifier epoch change does not bypass
  the configured 30s test cooldown. Actual time advances; no authority or signed
  timestamps are promoted. Late replacement failure preserves the predecessor
  and original primary proof; a new command succeeds using that unspent proof.
  Captured successor delivery, predecessor inspection/explicit-confirm denial,
  repeated non-consuming successor reads, atomic successor2/2 -> verified3/3,
  proof-free committed-request recovery and foreign recovery denial all pass.
  The original verified signin address retains its exact versions/flags. Native
  fixture SQL confirms exactly two selected grants, one use, and no rolled-back
  successor. `go -C reference test -race -tags=integration -run
  '^TestReferencePostgresEmailManagementResend$' -count=1 -v .` passes (32.20s).
  Public API and successor-field regressions failed before support. Bounded
  read-only medium mapping/QA reports `/root/m04_resend_mapping` and
  `/root/m04_resend_qa` found no requirement contradiction. Their remaining
  contention/authority/replay partitions are implementation work, not acceptance.
  Selected protected preparation uses existing forward histories, not a new
  migration engine. Capability cooldown reads database creation time, not old
  password-proof time, under the common pre-domain family fence.
  Request recovery is historical metadata; it does not resurrect a source
  session. Primary change/removal, contention, final review and full reference
  signup/management HTTP dispatch remain. Local retained-v1 supplier wiring is
  not committed/public-download qualification; v2 migration precedes main delivery.
  No new milestone or unit is closed; all M04 source remains uncommitted.
  Final focused password-adapter race passes (2.166s), kernel unit race passes
  (3.019s; known earlier kernel test-fixture copy-lock diagnostic means explicit
  vet remains pending), MFA adapter race passes (1.311s), retained capability
  adapter race passes (1.392s); password adapter explicit vet passes. No aggregate
  unit qualification or independent final-diff review is claimed.
  The isolated PostgreSQL cluster is stopped and the hold-open runner is terminal;
  its database, synthetic credentials, supplier archives/workspace and all owned
  Go caches are removed. No pre-existing/shared resources were removed.

- Current checkpoint (2026-10-14 16:28 UTC): native managed request -> captured
  delivery -> non-consuming inspection -> explicit atomic verification passes
  locally under race. Exact-command replay returns metadata only; a second command
  cannot reuse the proof. Public recovery observes the original committed result
  without the proof. Late SQL failure rolls back provisional proof/address writes
  and recovery reports noncommit; the aborted grant is terminally released, not
  resurrected. Credential and authorization changes deny inspection and execution.
  The credential-inspection regression failed before its admission correction.
  Final native selector
  `go -C reference test -race -tags=integration -run '^TestPrimaryPasswordCredentialIntegration$/^native-email-management$' -count=1 -v ./integration/password`
  passes (2.151s); the separate `native-email-management-rollback` selector passes
  (1.942s). Credential/authorization denial selectors pass (2.061s/1.981s).
  Kernel unit race passes (3.182s), password-adapter race (1.884s) and vet pass,
  MFA-adapter race passes (1.253s). Existing feature decoder fuzz now includes
  distinct signup/management seeds and passes a bounded two-worker 10s run
  (11.346s); deterministic cross-profile/trailing/truncated denial passes. Unchanged
  kernel explicit-vet fixture copy-lock diagnostic remains pending qualification,
  not a blocker to this development boundary.
  Capability adapter race (1.290s) and vet pass against local supplier source.
  Resend, primary swap/removal, real-signup and HTTP composition remain.
  No additional milestone, independent final review or commit/push is claimed.
- User-approved delivery sequence: finish M04 locally using retained v1 capability
  adapter in the existing feature/identity-platform worktree at c13f373. Capability
  remote main 3d8677d is v2 and lacks that adapter. Before main delivery, port the
  adapter and affected consumers to v2 with direct compatibility proof; do not
  overlay v1 history on v2 main or touch the unrelated dirty capability checkout.
  Local runs consume the uncommitted adapter changes through disposable workspace
  composition; these are not committed-pin or public-download qualification.
- Managed-confirmation HTTP checkpoint (2026-10-14 16:44 UTC): native managed
  rate-source API preserves original grant ID/lifetime before and after use,
  rejects callback substitution/cancellation and performs no debit. Its native
  regression failed before the API existed. Explicit managed HTTP constructors
  select that provenance owner; shared transport retains origin, typed middleware,
  bounded JSON/rate ordering and no-session response custody. Their focused test
  failed before the constructors existed. Real TLS + native PostgreSQL rate,
  capability and directory owners now pass (`native-email-management-http`,
  2.436s), including origin/callback denial, verified projection, exact replay and
  protected-intent conflict. The HTTP retry regression exposed fresh correlation
  changing the command fingerprint; restoring only the original acknowledged
  correlation fixes it without bypassing proof/callback/counter comparison.
  Separate final rollback/credential/authorization selectors pass
  (1.963s/1.983s/1.987s). Password/postgres unit race passes (2.206s); HTTP/email
  unit race and compiled examples pass (4.847s); both explicit vets pass.
  The original PostgreSQL B1 baseline passes (3.680s) after the shared plan/codec
  changes. This is the selected native confirmation endpoint, not full reference
  dispatch of signup and management links or real-signup-to-management proof.
  Resend, primary swap/removal and complete graph composition remain next.
  No independent review, commit/main delivery or M04 closure is claimed.
  The bounded run's isolated PostgreSQL is stopped; its database/credential,
  immutable supplier archives, temporary workspace and Go caches are removed.
  The owned hold-open runner is terminal; no shared/user resources were removed.
- Base: main c02025c. The bounded /root/m04_entrypoint_map investigation is
  complete. Adopt native identifiers, original password reauthentication,
  capability issuance/consumption, delivery and the sole PostgreSQL coordinator.
  External suppliers retain reference/LOCAL_SOURCES.json committed pins.
- Resend prerequisite checkpoint (2026-10-14 17:22 UTC): bounded supplier map
  `/root/m04_resend_supplier_map` established that the existing capability family
  columns/participant can be reused. No replacement store or journal was added.
  New managed-family and selected-consumption tests failed before their APIs/fence
  existed. Explicit signed mailbox scope is stable across new commands/session/
  key/time metadata, while original intent and signup separation remain enforced.
  Legacy four-caveat management payloads remain unchanged; explicit selection adds
  exactly one checked `email.supersession` caveat. Capability migration 004 extends
  the populated existing shape/index without altering 003. Native selected test
  `go test -race -tags=integration -run '^TestNativeConsumptionIntegration$/^magic-link_supersession_preserves_recovery_and_rolls_back$' -count=1 -v github.com/faustbrian/go-capability/postgres/identity`
  passes (1.548s): old schema rejects the managed scope before upgrade; rollback
  preserves predecessors; commit invalidates older issued/reserved unused grants;
  consumed, unselected and other families remain unchanged; old consumption denies
  without erasing reserved recovery evidence. This is native adapter SQL evidence,
  not complete public resend/issuance/delivery or current-authority composition.
  Root IdentifierRestartVerification now advances only pending non-primary
  identifier/verification versions, preserving value and unrelated primary;
  generic identifier operations remain closed. The distinct resend native schema
  reuses EmailAttachmentContributor/shared private writer with exact mailbox and
  target predecessors. Both new domain/field regressions failed before support.
  Root/email/kernel unit race pass (1.577s/1.285s/2.907s), supplier unit race passes
  (1.395s); root/email/supplier vets pass. Existing email intent fuzz now covers
  selected and legacy grants and passes a bounded two-worker 10s run (11.285s).
  Public VerificationResend and 60s reference cooldown are NOT implemented yet.
  Next: acquire the common family fence before domain locks; wire fresh-primary
  resend, protected cooldown and atomic replacement delivery; reconstruct successor
  versions and permit managed confirmation beyond initial1/1 while keeping signup
  unchanged. Then prove the full public predecessor-denial/successor-consumption
  journey. No independent review, commit/push or milestone closure is claimed.
  The bounded run's isolated PostgreSQL is stopped; task-owned database, temporary
  workspace, supplier archives and Go caches are removed, with absence verified.
- Consumer outcome: authenticated add/resend -> captured new-address link ->
  repeated non-consuming inspection -> explicit verification; safe self/admin
  list/get; fresh-password-authorized change -> captured new-address link ->
  atomic verified primary swap -> old-address notification; fresh authorized
  removal preserving a permitted verified signin and recovery path. Prove the
  public native APIs and opt-in reference HTTP composition with real PostgreSQL.
- Selected profile: current password-authenticated humans with known-empty MFA;
  no auto-signin, no OTP participant, no administrative mutation. Old-address
  confirmation is explicitly not required in this profile; original fresh
  password proof and new-address possession are required, old notification is
  selected. OTP, stronger factors, auto-signin and other policies remain owed
  within M04; this first profile is not full row or unit qualification.
- Owners: email storage-neutral orchestration/projections/policy; kernel
  PostgreSQL identifiers, uniqueness, retirement and lifecycle admission;
  password/postgres original action-bound proof issuance/one-use; session native
  current admission and required effects; existing capability and delivery
  participants; reference only composition and HTTP only typed transport.
- Finite acceptance: actual add/verify/change/list/get/remove journey, explicit
  self/admin policy and indistinguishable forbidden/absent/cross-tenant reads,
  bounded versioned pagination, signed action/subject/session/version/freshness
  denial, scanner-safe validation, resend supersession/cooldown, collision/CAS
  winner, last-signin/recovery denial, required session/token invalidation,
  original audit/privacy history, rollback and native exact-command unknown
  recovery. An event alone is not a completed lifecycle cascade.
- Affected checks: email native unit/race tests; root identifier/access tests;
  native PostgreSQL identifier and password-proof integration; selected
  reference email journey and B1/B2/B3 consumer compatibility, changed hostile
  input fuzzing, affected migrations/docs/current secrets. One complete
  independent final-diff review after the coherent profile passes, affected
  changelogs, then ordinary main delivery and Required CI. No Tools migration
  or global requalification is a prerequisite.
- Catalog correction: read-only AddressGet/List cannot claim a committed
  mutation. Their required Outcome is NotCommitted; successful authoritative
  observation and safe projection are reported separately. Requests also need
  trusted caller and exact target-user context, absent from the old minimal
  catalog, without deriving authority from browser-controlled IDs.
- First implementation checkpoint: the new email-owned AddressQueryService
  implements authorized self/explicit-admin list/get over the existing primary
  IdentifierRepository. Focused behavior failed before implementation, then
  passed; complete email unit race passed (1.263s) with the committed supplier
  composition. Real PostgreSQL registration -> delivery -> verification ->
  signin -> original session admission -> public email list/get -> logout passes
  in TestReferencePostgresEmailQueries (5.924s). This is native API proof, not
  email query HTTP or mutation delivery. Bounded cursor fuzz passed (10.318s).
  No new milestone/unit is closed, no independent final review or commit/push
  yet. Add/change/remove and their coordinated proof/lifecycle effects are next.
- Final bounded read checkpoint: exact-disclosure denial cases and fuzz seeds
  added; email unit race passes (1.247s), vet passes, final native PostgreSQL
  query journey passes (3.603s), bounded two-worker cursor fuzz passes (10.287s).
  git diff --check passes. The isolated PostgreSQL cluster is stopped and its
  owned cache/supplier/database scratch is removed. No shared resources touched.
  Native commands: email `go test -race -count=1 ./...`, `go vet ./...`,
  `go test -run '^$' -fuzz '^FuzzAddressQueryCursorAdmission$' -fuzztime=10s -parallel=2 .`;
  reference `go test -race -tags=integration -run '^TestReferencePostgresEmailQueries$' -count=1 -v .`.
- Native proof checkpoint: EmailPrimarySource authenticates the existing signed
  password proof for exact allowlisted email actions; its opaque admission
  preserves original session/credential/action/expiry and binds command intent.
  Prepare failed before implementation (1.447s), then passed. Protected
  consumption exposed the installed proof-table CHECK permitting only password
  change/MFA enable. New opt-in EmailReauthenticationMigrationSource appends
  version 9 without changing default history 1-8, FK custody or one-use index.
  The real runner upgrades populated proof history and retries; the native
  coordinator test passes (2.368s): atomic rollback, committed proof/effect/audit
  and denial of a second command. Its tiny SQL effect is an adapter contract
  seam, not email domain delivery or recovery. Password/postgres unit race
  passes (2.032s); vet passes. Final focused native email test passes after
  diagnostic removal (1.878s); the affected existing native password-change
  regression passes separately on unchanged default history (4.116s), including
  proof-lock expiry, ambiguity, cookie fences and keyed replay/conflict cases.
  Cookie/domain/factor/risk/reference composition remains
  required; no new milestone, independent review, commit or push is claimed.
- Native proof commands: password/postgres `go test -race -count=1 ./...` and
  `go vet ./...`; reference
  `go test -race -tags=integration -run '^TestPrimaryPasswordCredentialIntegration$/^native-email-primary$' -count=1 -v ./integration/password`
  and the same command selecting `^native-password-change$`. Each integration
  run used its fresh owned database/roles, not existing services. The final
  database is stopped and owned cache/supplier/credential scratch is removed.
  No shared/user resources were accessed or deleted. Work remains local and
  uncommitted on main; continue with actual email domain/delivery integration.

- Pending-address checkpoint: typed EmailAttachmentContributor now maps the
  frozen managed intent to the exact enlisted EmailAttachmentDomain. The sole
  coordinator applies the shared private identifier writer; generic Begin stays
  closed. The native password integration now uses a real pending email, not
  the old test-only SQL effect. It passes under race (1.964s): stale user/identifier
  epochs and canonical collision deny without consumption; failure after all
  provisional writes rolls back proof/address/epochs; success preserves the old
  verified primary, advances exact directory versions and commits required audit;
  the original stale/used proof cannot create another effect. Existing private
  identifier persistence integration also passes (1.788s), covering retirement,
  cooldown, complete partitions, tenant exclusion and contention. Kernel unit
  race passes (3.048s). Explicit kernel vet fails on unchanged
  mfa_send_counter_scope_test.go:79 copying reservationState's atomic.Bool;
  no pass or final qualification is claimed for that check.
- Managed-link checkpoint: ManagedVerificationPolicy reuses the bounded real
  parser/configuration and existing capability signer, with a separate keyed
  management-v1 intent frame. Tests reject request/session/address/version/action
  substitutions and cross-use of signup links, retain original key/expiry custody,
  and keep validation non-consuming. Email unit race passes (1.266s), email vet
  passes, and bounded two-worker intent fuzz passes (11.286s). Command selectors:
  reference native-email-primary as above; kernel
  `go test -race -tags=integration -run '^TestIdentifierMutationIntegration$' -count=1 -v .`;
  email `go test -run '^$' -fuzz '^FuzzManagedVerificationOriginalIntent$' -fuzztime=10s -parallel=2 .`.
  These are local prerequisites, not a completed email journey. Next: native
  original-command issuance and encrypted delivery alongside attachment, followed
  by inspection/confirmation/change/removal and opt-in HTTP. All local M04 work
  remains uncommitted; full-profile review, delivery and qualification are pending.
  The owned PostgreSQL cluster is stopped; all supplier/cache/credential/database
  scratch from this bounded run is removed and absence verified.

- Request-to-captured-link checkpoint: EmailManagementService now composes the
  original password proof, current known-empty MFA, native protected counters,
  retained provider-only risk, kernel pending attachment, capability issuer and
  encrypted delivery through ExecutePreparedFeature. The kernel's final-declaration
  regression failed before the narrow managed-email issuance extension, then
  passed; unrelated features and recipient overrides still deny. Native runtime
  passes under race (1.941s): real password comparison -> pending address plus
  issued grant/encrypted intent -> owned PostgreSQL worker -> captured new-address
  link -> real signature/scope validation. Repeated processing and used/stale
  proof create no second message. This adapter test has explicit pre-existing
  account/MFA fixture state; it is not the real-signup consumer/HTTP journey or
  live-provider delivery. Kernel unit race passes (3.025s), password-adapter
  race passes (2.085s) and vet passes, MFA-adapter race passes (1.341s). The old
  kernel vet copy-lock diagnostic remains. All work is still uncommitted; no
  new milestone or unit qualification is closed. Next: non-consuming managed-link
  inspection and explicit atomic confirmation, then the retained change/removal,
  resend, consumer/HTTP and recovery cases. Native selector: reference
  `go test -race -tags=integration -run '^TestPrimaryPasswordCredentialIntegration$/^native-email-management$' -count=1 -v ./integration/password`.
  The owned PostgreSQL cluster is stopped and all bounded-run supplier/cache/
  credential/database scratch is removed. No shared services were accessed.

## Closed: B3 fresh password reauthentication and change

- Base: main 0675bfd; adopt delivered B1/B2 and the existing native
  verification/keyed-change/cookie/session-effect owners. Supplier pins remain
  those in reference/LOCAL_SOURCES.json. One bounded B3 investigation is done.
- Outcome: opt-in browser-cookie verification of the current password, then
  explicit keyed change, old-password rejection, new-password signin and denial
  of both saved original sessions. Revoke all sessions; no automatic signin,
  preserved-session, bearer, administrative or stronger-factor variant.
- Preserve populated baseline keys and original migration requests; new
  reauthentication/change key custody is an additive private local file.
  Change and reset remain independent explicit HTTP selections.
- Finite acceptance: wrong-current-password/CSRF/foreign-origin denial, fresh
  proof leaves session unchanged, original signed purpose/action/session/
  credential/version/expiry fences, reuse/breach/HIBP outage denial, atomic
  rollback and original scoped native recovery, replay cannot authenticate a
  revoked cookie, two-session revocation, populated migration/restart custody.
- Adopt the supported existing public ChangeRequest and separate verification
  contracts. The stale typed catalog's caller-selected subject, current password
  and revocation fields are not the public change body: current password is
  proved through verification; subject/session comes from native authority;
  revocation is frozen trusted policy. Record this correction with the B3
  consumer documentation, not a Tools catalog migration.
- Focused checks: new baseline opt-in/journey/upgrade regressions red/green;
  reference unit race and TestBaseline integration; existing
  TestReferenceServerPasswordProtection and TestPrimaryPasswordCredentialIntegration
  native recovery/freshness/breach/rollback cases. Run actual PostgreSQL and
  source-consumer wiring, then one complete independent final-diff review,
  affected changelogs/current secrets and ordinary main delivery/Required CI.
- Runtime diagnosis: sanitized journal observations located intermittent race
  failures both before retained output and after the final plan. A native
  comparison deadline expired after only 875ms of that comparison; shared
  tenant admission was forwarding its narrower two-second context into the
  whole workflow. TestReferenceServerTenantAdmissionDoesNotReplaceWorkflowDeadline
  failed before correction, then passed. Admission stays bounded; dispatch
  retains the original router/caller deadline. No primitive, proof age, audit
  acknowledgement or configured workflow timeout changed. Final runtime
  regression/review/delivery remain pending.
- Final selected local checks: reference unit race passes (11.648s and command
  11.345s); complete TestBaseline plus tenant-admission race integration passes
  (command 146.945s, reference 5.134s). The PostgreSQL-only native protection
  journey passes (4.478s), including real rollback, revoked-cookie denial and
  independently authorized scoped recovery. Isolated legacy native password
  change passes (4.523s); earlier broader overlapping-fixture failures remain
  outside that claim. Current tooling v2.5.1 planning-check and changed-content
  secrets pass. A concurrent remote CI-only update ca43e21 was fast-forwarded
  and verified on origin/main without changing identity runtime source.
  Complete independent review and B3 main delivery are pending.
- /root/b3_complete_review reviewed immutable tree 90851a21 against ca43e21
  and requested changes for one concrete consumer defect: the accepted generic
  exercise with both flags reset the password but then used its predecessor
  password/version for change. The new combined real PostgreSQL/HTTPS race
  regression failed at second-session signin (403, 15.01s). The consumer now
  carries the successfully reset credential/version into change. The corrected
  combined journey and standalone reset/change race cases pass (39.395s total);
  complete review of the corrected full diff remains pending.
- Closure: /root/b3_complete_review (GPT-6.1 Sol medium) approved complete
  tree dbd3b48006664109723059a7c79eea603a7684d1 against ca43e21. Corrected
  command unit race passes (9.411s); command vet and local docs pass. Source
  24b1b0842f32e831fc16933749899ef2310aba1a is on origin/main. Its initial CI
  run 38558305428 timed out during cold secret-scanner compilation, not an
  identity runtime test. The independently reviewed one-file CI repair
  47a3ee0eb50104556fb9c6f636c3e3616cd20a06 prepares the exact pinned scanner
  in isolated verifier-only caches, preserving the fatal forty-second scan
  and cleanup. Cold local rehearsal passed; Required CI succeeded on 47a3ee0
  in run 38559659144. That repair's reviewed tree is aef50df4, same reviewer.
  B3 is closed: 3/39 consumer milestones delivered. No Tools source changed;
  no whole-unit, public-download, release or production qualification is
  claimed. Disposable PostgreSQL is stopped. Next: M04 email lifecycle.

## Closed: B2 emailed-capability password reset

- Base: identity main `04118b2`, adopting B1 and existing native reset workflows.
  Same committed supplier source pins as `reference/LOCAL_SOURCES.json`.
- Outcome: explicit reset selection on the runnable PostgreSQL backend;
  request → private captured delivery → repeated read-only inspection → explicit
  completion → old-password denial → new-password signin → all original sessions
  denied. No automatic signin and no scanner-triggered consumption.
- Owners: password and password/postgres native issuer/current-account/factor
  admission and coordinated mutation; session/postgres atomic all-session effect;
  existing capability ValidateIssuedProof and one-use owner; delivery, risk/HIBP,
  HTTP typed transport and reference composition. No replacement domain store.
- Selection: email capability recovery only, with current known-empty MFA
  authority and unchanged signed generation. Reset is opt-in; B1 default routes
  and credential custody remain compatible. OTP/admin recovery and B3 are excluded.
- Named gaps from one bounded source pass: CLI reset composition/authorization,
  reset-attributed HIBP collector, consumer walkthrough and public read-only
  reset inspection. Inspection returns only valid/invalid state, never a subject,
  reservation or future permission; completion repeats authoritative checks.
- Finite acceptance: full public HTTPS journey and captured mail; indistinguishable
  unknown/ineligible request results; repeated inspection does not consume; used,
  stale-factor, foreign-purpose/tenant, expired and invalid proofs deny; origin and
  input bounds; wrong/old password denial; exact replay and conflicting-input
  rejection; required session revocation; HIBP breach/outage denial before hashing;
  atomic rollback, native original-command recovery and affected shutdown checks.
- Focused checks: new command B2 and inspector regressions red/green; affected
  password/native/HTTP/reference tests under race with real task-owned PostgreSQL;
  selected existing reset factor/replay/rollback/disconnect tests and B1 direct-
  consumer regression. Reuse unchanged counter/kernel proof and supplier pins.
- Close after one independent complete-final-diff review, affected current
  checks, changelogs and ordinary main delivery with Required CI. No tooling,
  historical qualification, unrelated recovery variants or new approval machinery.
- Current local proof: the full HTTPS reset journey now passes, including two
  saved sessions and changed/consumed-token attempts. The HIBP composition now
  supplies the security profile's actual canonical policy and system actor;
  screening/audit remain fail closed. Native early denial before a receipt
  remains denial, not a fabricated rollback or an erased recovery ambiguity.
  Populated upgrade and exact operator reset retry pass. New inspection wire
  denial assertions failed before matching shared-router error shapes and now
  pass. Selected native reset/factor/recovery tests pass; an attempted entire
  legacy signin fixture fails from overlapping fixture histories/expectations
  and is not claimed green. No unrelated fixture/tooling repair is included.
  Later final correction checks and delivery are recorded below.
- Final affected local checks pass: password and password-HTTP race suites;
  reference unit race suite and all Baseline command integration cases;
  native reset migrations and selected native reset/factor/recovery/screening
  cases; shared secret-rate regressions; bounded JSON fuzzing; published
  configuration/repository/cohesion/docs/offline specification checks.
  The broader HTTP suite's response-extension case also fails on unchanged
  B1 source with the same pinned suppliers, so it is a retained broader
  qualification gap, not a green whole-suite claim or a reset implementation
  repair. Final reviewed source and delivery are recorded below.
- Complete review of tree `392e9c47` requested changes for one concrete B2
  defect: a lost primary HIBP audit acknowledgement denied screening but the
  collector's safe error projection discarded original event recovery custody.
  The local command now durably retains exact native redacted records before
  append and offers bounded explicit native reconciliation after restart.
  Primary acknowledgement is still required for usable screening; no command,
  event-ID or authorization engine is added. Restart reconciliation failed
  before the native privacy policy was reapplied, then passed unchanged-byte
  recovery against the real PostgreSQL command. Final correction checks and
  new complete review remain pending; prior review is not approval.
- The next complete review found a concrete at-capacity publication-crash
  defect: a complete batch and its staging alias could exceed the directory
  entry limit and prevent reconciliation. The 256-batch crash regression
  failed before correction, then passed under race. Recovery now removes
  only exact private staging names under the local filesystem gate and counts
  complete batches; native append IO remains outside that gate. Original
  lost-acknowledgement, privacy/cancellation, directory-sync denial/retry and
  reference unit race tests pass. No timeout or primary-acknowledgement policy
  was relaxed. Complete final review of the resulting full diff remains.
- Closure on 2026-10-14: /root/b2_complete_review (GPT-6.1 Sol medium)
  approved the complete base 04118b2 to source tree
  94e5b34a3f1a28ec22718e7b30315e2cd421bd6d. Both audit findings are resolved.
  Reference go test -race ./... passed; command
  go test -race -tags=integration -run '^TestBaseline' -count=1 -v
  ./cmd/identity-baseline passed (74.088s), including B1/B2, populated upgrade,
  actual PostgreSQL post-COMMIT acknowledgement loss and native audit replay.
  Command vet, planning-check, local docs and final changed-content secrets
  passed. Earlier transient signin failures remain unattributed; no policy or
  timeout was weakened. Complete source commit fd439aa71aa0e12259785cf2b094daf996ab3eb7
  is on origin/main; Required CI succeeded in run 38547848026. This closes B2,
  not whole-unit, public-download, full-history or release qualification.
  The owned PostgreSQL cluster is stopped. Next: B3 fresh reauthentication,
  password change and required session effects, with wrong/stale-proof denial.

## Closed: B1 runnable authentication baseline

- Workspace: go-identity on main, adopting the existing runtime checkpoint.
- Outcome: real PostgreSQL bootstrap → registration → captured verification
  delivery → verification → password signin → authenticated session read →
  logout, with a reproducible run command and supported consumer walkthrough.
- Security: account/tenant isolation, current authority, enumeration resistance,
  credential custody/redaction, origin/CSRF/cookie policy, atomic one-use and
  protected effects, revocation, relevant denial/replay/rollback/contention and
  ambiguous-outcome recovery remain mandatory before acceptance.
- Exclusions for B1: reset/change (B2/B3), other login methods, organization,
  social/enterprise federation and broader feature profiles. Required security
  prerequisites still belong inside B1; no fake store or weaker fallback.
- Selected public graph: ComposeStores → ComposeProviders → ComposeWorkers →
  ComposeFeatures → NewServer. Keep existing account/password/session owners.
  Select only password signup, registration verification, password signin,
  original-flow initiation and cookie session read/signout HTTP.
- Concrete startup gap: the existing signup journey privately backdates
  Valkey recovery history. That is conditional history proof, not fresh startup.
  B1 will select durable PostgreSQL admission counters with explicit ownership,
  rather than forge coverage, disable risk, or weaken the existing Valkey lane.
  The PostgreSQL-only reference profile is already a product requirement.
- Finite acceptance: fresh native migrations/startup; complete public journey;
  unverified/wrong-password denial; replay/input-conflict denial; callback/origin/
  tenant isolation; atomic signup/confirmation/signout rollback; missing-CSRF
  signout denial; credential redaction; authenticated read then revocation;
  persisted risk charges, replay, contention, rotation and unavailable denial.
- Focused commands: risk/postgres `go test -race -tags=integration -run
  'TestDurableCounter' .`; reference `go test -race -tags=integration -run
  'TestReferenceServerNativePasswordSignup|TestReferencePostgresBaseline' .`;
  affected native unit tests; runnable example build and clean public-consumer
  walkthrough. All Go runs use one bounded task-owned disposable cache session.
  Exact command/source outcomes will be recorded as produced, not preclaimed.
- Source baseline: identity main 063dc38 (all selected nested owners). Existing
  primitive/module pins remain unchanged unless an actual consumed boundary
  requires a committed correction; no Tools publication or historical repair.
- Closure: prove the real consumer journey and affected security/regressions,
  obtain one independent final-diff review, resolve concrete findings, commit
  and push the coherent main checkpoint with applicable required CI. Then B2,
  then B3; do not add neighboring profiles before closing B1.
- Hosted check scope: documentation-only run 38513309150 passed Required on
  `833df6f`; prior run 38501126112 failed historical secret classification.
  Neither runtime qualification nor repair of that historical result is claimed.
  Start safe B1 work on activation, assess its actual affected checks and isolate
  any reproduced supporting-tool defect needed for delivery.

## Continuity

### B1 local checkpoint (2026-10-14)

- Fresh PostgreSQL-only public HTTP journey now passes locally in
  `TestReferencePostgresBaseline`, including the existing rollback, replay,
  callback/tenant isolation, unverified-login and CSRF/signout checks. This
  lane does not invoke Valkey recovery or backdate any history.
- New durable admission regression passed against real PostgreSQL, including
  concurrent matching replay and unchanged original timestamps; its initial
  race run also passed; the frozen source-runner integration and affected
  command race checks subsequently passed.
- The journey exposed an existing coordinator rejection of sealed signup
  commands through the generic Feature accessor. New original/generated
  signup regressions failed at that exact boundary, then passed using the
  existing closed command selector. Existing generic admission tests passed.
- The executable command now has init/migrate/serve/exercise operations,
  private restart-stable owner keys, loopback TLS, native PostgreSQL operator
  bootstrap and private file-delivery destination. Its actual HTTPS consumer
  passes with wrong/unverified-password denial, CSRF rejection, original-cookie
  revocation and clean command shutdown. Only external HIBP IO is synthetic in
  this integration test; the command uses the real client/provider by default.
- Durable rollback, capacity and key-rotation/old-owner denial checks pass under
  race. Affected postgres unit tests and reference/command unit tests also pass
  under race. Exact per-unit qualification remains unclaimed.
- Reproducible immutable-supplier wiring and the consumer walkthrough are now
  provided by `scripts/identity-baseline.rb` and `reference/BASELINE.md`; the
  runner's frozen real-PostgreSQL/race integration passed. This is supported
  source-consumer proof, not public-download/release qualification.
- Independent complete-diff review of tree `09aefd2` requested changes for
  directory acknowledgement before native migration Apply and capture-mail
  acceptance/replay. All three focused failure/recovery regressions failed
  before correction, then passed with the runnable journey/shutdown under race.
  The resulting complete slice requires final re-review before delivery.
- Changed-content secret scanning passed against base `063dc38`; repository,
  config, cohesion, local docs and offline specification checks passed. The
  whole-history secret scan failed on unchanged historical content and remains
  a full-release qualification gap, not a passing runtime or history result.
- Source is local and uncommitted. B1 remains open for final review and main
  delivery. No neighboring profile or supporting-tool change has been added.
- Test dependencies use disposable local bindings to committed checkpoints;
  several historical remote pseudoversions are unavailable. This is development
  compatibility evidence, not downloadable/public-release qualification.
  Full-unit qualification and the 67-unit requirement remain unchanged.

### B1 delivery (2026-10-14)

- Complete final-diff review by `/root/b1_complete_review` (GPT-6.1 Sol medium)
  approved base `063dc38` to tree `17cccd0b65d70bccac929f648ba2568fbcedddff`.
  Both prior filesystem-durability findings are resolved. The final native
  immutable-supplier integration passed all selected packages under race;
  updated-tree changed-content/current-tree secrets and command vet passed.
- Delivered commit `90d4f2cb271926ace09eb36487163036e4fd756a` to origin/main.
  Required CI passed in run `38527264686`. Hosted CI proves its declared
  structure/change-range checks; the real runtime proof is the local native
  PostgreSQL/HTTPS integration, not a hosted runtime or deployment claim.
- B1 closes the selected runnable local source-consumer baseline. Whole-history
  secret failures, public-download compatibility and full-unit qualification
  remain explicit debt. No unit or full platform is newly declared verified.
- The disposable B1 PostgreSQL cluster was stopped and its databases, captured
  credentials, supplier archives and Go caches removed after evidence capture.
- Next: freeze and finish B2 reset request → captured delivery → completion →
  old-password denial → new-password signin → required session invalidation.
  B3 password change remains subsequent; no neighboring profile was added.

Existing reviewed email-OTP runtime behavior and prior native results remain
in their owning commits/historical records. Refer to an applicable original
result with its source/input identity; do not copy the historical ledger,
rebuild evidence machinery or rerun unchanged package matrices.

Maintain [IDENTITY_PROGRESS.md](IDENTITY_PROGRESS.md) for delivered behavior,
remaining consumer gaps, source commits and pending qualification. Keep this
note compact and update the current milestone rather than creating plan versions.
