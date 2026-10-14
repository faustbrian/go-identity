# Identity Implementation — Current Milestone

Activated on 2026-10-14. B1 and B2 are closed; B3 is next.

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
