# Identity Implementation — Current Milestone

Activated on 2026-10-14. B1 is in implementation; no milestone is closed.

## Active: B1 runnable authentication baseline

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

Existing reviewed email-OTP runtime behavior and prior native results remain
in their owning commits/historical records. Refer to an applicable original
result with its source/input identity; do not copy the historical ledger,
rebuild evidence machinery or rerun unchanged package matrices.

Maintain [IDENTITY_PROGRESS.md](IDENTITY_PROGRESS.md) for delivered behavior,
remaining consumer gaps, source commits and pending qualification. Keep this
note compact and update the current milestone rather than creating plan versions.
