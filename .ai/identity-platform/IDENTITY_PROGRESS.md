# Identity Platform Progress

## Current TL;DR — 2026-10-24 01:01 UTC

- **Whole goal: ~25% (low-confidence estimate); 11/39 milestones closed.**
  All 67 units remain required; no additional fully qualified unit is claimed.
- **Working/delivered:** the baseline authentication journeys and retained
  passkey enrollment/signin/read/logout/inventory/rename/removal profiles below.
- **Current M16:** passkey-first, no-email/no-password signup. Protocol support,
  actual kernel account creation, request types and known-empty MFA initialization
  are main-pushed with Required CI green (latest identity `808999e`).
- **Latest delivered components:** session persistence `94e5a95`, explicit
  signup issuer `1d7f872` and protected risk projection `b030e8e` are main-pushed
  with Required CI green. PostgreSQL/race, copied-request single delivery and
  original scope/expiry checks cover their respective boundaries.
- **Outbox delivered:** reviewed `4279fe5` is on main with exact push-triggered
  Required `40045947903` green. Earlier manual-dispatch green did not satisfy
  GitHub rulesets; the minimal carrier trigger preserves the identical gates.
  No PR, Tools programme or protection bypass was used.
- **Protected counters delivered:** reviewed risk PostgreSQL `5910465` is on
  main with Required `40047612425` green. Real PostgreSQL/race proves options
  charging, sixth-attempt denial, unchanged replay and preserved migration state.
- **Current actual Go work:** primary owns native signup composition and its
  real journey test. Kernel third-event staging has completed focused tests and
  independent review; actual session/outbox consumption is next.
  Local native source is not yet passing
  or delivered. Its first test must prove no pre-verification account/handle,
  genuine registration, readable session and all three lifecycle events.
- **Next:** finish native counters, prove signup/session/read/logout/new signin,
  rollback/replay/recovery and Reference/HTTP composition. M16 remains open;
  no user decision is needed. The rejected unpublished Authentication-class
  shortcut was replaced with the original 5/15m protected deny policy.
- **Remaining:** conditional passkey signin, other open milestone profiles and
  the platform's full-unit, journey/shared-issuer and release qualification.

## TL;DR — updated 2026-10-23 22:28 UTC

- **Overall: approximately 25% complete, low confidence; 11/39 milestones closed.**
  This estimates delivered outcomes plus remaining scope/qualification, not file
  counts. All 67 units remain required; no new full-unit qualification is closed.
- **Newly delivered:** existing-account passkey enrollment -> identified or
  identifier-free HTTP signin -> safe inventory -> session read/CSRF logout.
  Keyed options retries retain original metadata without another challenge.
- **Delivery:** independently reviewed Reference `c1f9342` and HTTP `abfee651`
  are on main with green Required CI. A separate clean public-module consumer
  passes all four fresh/upgrade x signin-mode PostgreSQL/race journeys (33.602s),
  without replacements; dependencies verify and changed archive files match.
- **Newly delivered native management:** genuine fresh proof -> keyed label
  rename -> updated inventory -> same passkey new signin/read/logout. Native
  `fa925a3` is reviewed/main-pushed/CI-green; a separate downloaded-public consumer
  passes the journey and populated migration runner under PostgreSQL/race (5.156s).
  Mapping1/signin2 remain unchanged; metadata3 is an explicit forward suffix.
- **Newly closed consumer profile:** native and HTTP Reference label rename ->
  metadata-only retry -> changed inventory -> same passkey new signin/read/logout,
  on fresh and populated-upgrade PostgreSQL. Reviewed `19a0ef9` is on main with
  Required CI `40026477944` green. A clean consumer of the authenticated public
  Reference module passes all four management journeys under race (30.836s),
  with no replacements; all 346 public files match committed source.
- **Deletion delivered:** genuine native proof/recovery -> atomic removal ->
  affected-session denial -> original-password-session retry passes locally,
  including PostgreSQL/race rollback, ambiguity and retained inventory/rename.
  Native review is closed; `e175ffe` is main-pushed with required CI green. A
  clean downloaded-public consumer passes the genuine journey under race
  (6.076s). Reviewed Reference `85c7651` is on main with Required CI green.
  Its clean public consumer passes native/HTTP fresh+upgrade removal, session
  denial and password-session retry/read/logout, plus management-off native
  removal, under PostgreSQL/race (42.348s) without replacements. The local
  deletion/retained 13-journey cohort passes race (106.362s). This closes the
  finite deletion profile, not full M16 or another unit's qualification.
- **HTTP deletion leaf delivered:** reviewed `5bb695c` is main-pushed with
  Required `40031504986` green. Race tests and bounded parser fuzz pass;
  rate-denial counterfactual detects bypass. Public archive authenticates and
  all 12 changed files match. This transport alone is not the usable native/
  Reference deletion journey and does not close M16 or qualify another unit.
- **Next/remaining:** passkey-first signup, then conditional signin. Other
  roadmap families and full-unit/
  release qualification remain open. No user decision is needed. Full M16 stays open.

## Retained checkpoint — 2026-10-23 19:22 UTC

- **Whole goal: approximately 25%, low confidence; 11/39 complete milestones.**
  All 67 units remain required. Finite delivered profiles are not full-unit
  qualification; this update does not close full M16 or add a qualified unit.
- **New working consumer behavior:** explicit `Session.Passkey` lets genuinely
  issued identified or identifier-free passkey sessions use the existing common
  native and HTTP session read/logout paths. Default-off selection stays off.
  Fresh and populated-upgrade journeys pass over real PostgreSQL/loopback TLS,
  including wrong-CSRF/foreign-origin denial, exact cookie deletion and native/
  HTTP post-logout rejection.
- **Delivered:** independently approved main `1d2fcbd`; Required `40010533635`
  green. A separate clean external module passes all four downloaded-public
  Reference journeys under race (19.166s), without replacements. SumDB/Origin
  authenticate the public module; all 341 archived source files match commit.
- **Next:** finish actual passkey enrollment/signin HTTP composition. Its leaf
  worker identified missing portable request records, original-ceremony rate
  custody and shared rate/CSRF variants; no substitute authority or scaffold was
  introduced. Signup, conditional signin, management and full M16 remain open.

## Retained checkpoint — 2026-10-23 18:48 UTC

- **Whole goal: approximately 25% complete (low-confidence estimate),
  11/39 consumer milestones closed; all 67 units remain required.** Milestone
  profiles are not full-unit/release qualification.
- **New passkey backend:** existing-account fresh password reauthentication ->
  real resident/UV enrollment -> identified assertion -> issued session -> safe
  inventory -> read -> cookie-CSRF logout passes locally against public
  suppliers. Independent review approves; native `97cb16c` is main-pushed.
  The separate downloaded-public-module consumer also passes the whole journey
  and five current-owner withdrawal cases under PostgreSQL/race (19.116s).
- **Security corrections:** options no longer disclose account eligibility;
  genuine enrollment of key 101 no longer disables signin with existing/new
  keys. Original browser, identifier and authority cannot be refreshed.
- **Delivered finite native profile:** public archive authenticates and matches
  all 37 source files; all 144 consumer modules verify without replacements.
  Workspace correction `2912f67` is main-pushed with exact Required CI green.
  This is selected native behavior, not a release or full passkey milestone.
- **Newly delivered reference integration:** real baseline registration,
  captured verification delivery and password signin now lead to passkey
  enrollment, signin, safe inventory, session read and cookie-CSRF logout.
  Fresh-install and populated-upgrade external consumers pass PostgreSQL/race
  (7.765s) using the authenticated public Reference module without replacements.
  Main `bacc2e6` is independently approved and Required CI `40000721264` green;
  all 342 public archive files match the committed source.
- **Newly delivered identifier-free native signin:** actual enrolled resident
  credentials now sign in without any identifier input and produce a usable
  session/inventory/read/logout. Main `955b370` and risk prerequisite `a13a682`
  are independently approved and exact-CI green. A separate authenticated public
  module consumer passes PostgreSQL/race (33.567s), including mode-switch and
  opt-out denials plus retained identified/current-owner checks. All 41 native
  archive files match source. No new
  browser/hardware interoperability or whole-unit qualification is claimed.
  Full M16 still needs signup, conditional signin, management and remaining
  Reference/HTTP integration;
  remaining roadmap families and whole-unit/release qualification stay open.
  No user decision needed. This is a backend library, not a UI.
- **Identifier-free Reference adoption delivered:** real baseline registration,
  captured verification, password signin and fresh-proof passkey enrollment now
  lead to identifier-free assertion and usable session/inventory/read/logout.
  Both modes pass fresh and populated-upgrade journeys in a separate downloaded
  public Reference consumer (PostgreSQL/race14.327s, no replacements, authenticated
  modules). Reviewed main `0acc093` is pushed with Required `40005974807` green;
  all342 public archive files match source. HTTP remains unfinished. A bounded
  native worker is implementing keyed options required by the HTTP contract;
  it does not own Reference/HTTP or shared identity contracts. Full M16 and the
  11/39/~25% low-confidence whole-goal estimate are unchanged.

## Retained checkpoint — 2026-10-23 17:23 UTC

- **Whole goal: approximately 25% complete, low confidence; 11/39 consumer
  milestones closed.** All 67 units remain in scope. This is a whole-outcome
  estimate, not a claim that the full units or release gates are qualified.
- **Current passkey delivery hold:** independent native review confirmed that
  identified options exposed account/passkey eligibility. The real PostgreSQL
  regression reproduces all four partitions (eligible/absent/unverified/no-key,
  0.812s). Correction uses account-independent resident discovery while keeping
  original private identifier/authority snapshots; no dummy principal or reset
  of account/factor epochs. Native source compiles against the local supplier
  correction (0.307s), not yet public-module proof. Supplier review then found
  the exact missing forward schema allowance; its PostgreSQL/race cohort fails
  (0.731s), so downstream cases are not passing evidence. A narrow migration 3
  and original-expiry regression are being added. No passkey delivery or M16
  closure is claimed. Earlier local/browser journeys describe the prior tree.
- **Newly delivered: native and Reference OTP disable.** A genuine OTP session
  obtains a delivered disable-specific proof, disables one/all factors and
  atomically erases recipient references, retires recovery codes and revokes
  sessions. Password signin and real delivered email reset remain usable.
  One-target preserves pending OTP siblings; all-target erases them.
- **Delivery:** MFA `5fd8f73`, native MFA `8fbebd6`, OTP `3864860` and Reference
  `e20c606` are independently source-approved, main-pushed and exact-CI green
  (final Required `39959871742`). Six public-supplier PostgreSQL/race journeys
  pass (181.707s). A separate no-replacement public consumer passes OTP
  one/all/COMMIT recovery and retained TOTP one/all disable (127.790s), with
  module checksums verified. This closes the finite profile, not all of M12.
- **Newly delivered:** explicitly selected confidential clients can exchange
  genuine human code/PKCE-issued access for narrower children and descendants,
  introspect and verify them, and enforce source/ancestor/current-owner withdrawal.
  Original-command retry and real COMMIT recovery preserve lineage and return
  no replacement secret. OAuth root `599225f` and native `3b58e4c` are independently
  source-approved, main-pushed and exact-CI green (`39967343443` / `39968402888`).
  Five actual downloaded public-native PostgreSQL/race journeys pass (64.253s),
  with authenticated modules and all 105 native archive files matching source.
  This closes the finite human-exchange profile, not full M33; API-key and
  organization sources, HTTP/reference and remaining variants stay required.
- **Primary implementation:** M16 existing-account passkey enrollment ->
  identified assertion -> usable session/read/logout is the frozen next slice.
  Enrollment proof-custody, factor authority, initial credential persistence and
  atomic one-use proof consumption now pass focused pinned-Go1.27.2 checks,
  including rollback and retained organization actions. WebAuthn same-Work
  assertion participation is independently source-approved, main-pushed as
  `b64dd7d` and exact-CI green (`39968403285`); protocol PostgreSQL/race and
  retained standalone assertion checks pass. Root passkey issuance and native
  session persistence/read/revocation now pass focused tests locally. Actual
  logout preserves current-owner denials and atomically revokes the session;
  a counterfactual missing owner check is caught. The shared prerequisite diff
  is independently approved and main-pushed as `219499b`, exact CI green.
  MFA owner fence `1d7a572` is main-pushed and exact-CI green. `go-passkey`
  now passes real password-proof -> WebAuthn UV enrollment -> atomic credential,
  reference and mapping locally. Original ceremony authority cannot be refreshed;
  denial, one-winner concurrency and required-effect rollback tests pass. The
  canonical creation-event correction `9a09aa4` is independently approved,
  main-pushed and exact-CI green. Real before/after-COMMIT disconnect recovery
  now also passes locally, without reconstructed verification or a second
  journal. Later enrollment cohort passes PostgreSQL/race (39.320s).
  Native identified assertion now issues a real persisted session with the
  original browser remember choice. Authenticated safe inventory, current
  session read and actual cookie/CSRF logout pass together locally under
  PostgreSQL/race (4.345s). Five current-owner withdrawal cases pass; inventory
  keyset/cancellation/foreign-scope tests pass (13.058s). WebAuthn preauth actor
  prerequisite `693d54b` and exact safe-read risk classification `9b97d1d` are
  independently approved, main-pushed and exact-CI green. The native signin
  denial/race/rollback cohort passes (53.254s); original-flow final-expiry fix
  and transport/remember extensions are undergoing affected checks. Go-passkey
  remains local/unreviewed; public adoption, interoperability and final review
  remain open. M16 is not closed and no fully qualified unit is added.
- **Remaining:** OTP replacement and remaining management/method/composition
  profiles; the other open roadmap families; full-unit/release qualification.
  The earlier unexplained prerequisite 503 and failed full-history secret scan
  remain qualification debt. No user decision is currently needed.

## Delivery checkpoint — preserved 2026-10-23 12:20 UTC

- **Whole goal: approximately 25% complete, low confidence.** Consumer
  milestones are **11/39 closed**; retained scope is **67 units**. These are
  delivered consumer profiles, not full-unit/release qualification.
- **New M12 inventory profile delivered:** consumers can list safe pending,
  confirmed and revoked native OTP/TOTP metadata and unused recovery counts,
  through native composition or independently selected HTTP. MFA `855d87d`
  and Reference `f822677` are independently approved, main-pushed and exact
  current-change CI green (`39925806306` / `39926332305`). The downloaded
  public Reference module passes all three PostgreSQL/race native/HTTP/TOTP
  journeys (40.289s). Mixed-method metadata, corruption and logout denial are
  covered; this does not close M12's remaining factor-management scope.
- **New native device profile delivered:** explicitly enabled public/Basic
  clients can request a device code, a genuine recent password-session user
  can inspect and approve it with explicit comparison/CSRF, and the device can
  poll for one access/refresh-token winner. Denial, expiry, cancellation,
  cross-client isolation, human/client/consent withdrawal, rollback and original
  commit recovery are covered. OAuth root `dba3167`, child `ca7b0b8`, workspace
  correction `f0d0a88` and native `c1d476a` are main-pushed and independently
  approved. Final Required `39935662993` succeeds. Public-only native
  PostgreSQL/race checks pass (88.436s); downloaded public-native consumer
  journeys pass (30.396s). Base OAuth needs no device tables or selected factory.
  Full M34 remains open for retained variants and HTTP/reference composition;
  no UI, full-unit qualification or platform completion is claimed.
- **New M12 OTP rename profile delivered:** a genuine password/OTP session can
  request and receive an action-bound OTP, obtain its original one-use proof,
  rename the factor, invalidate old sessions and sign in again with the renamed
  inventory. Attempt exhaustion, mismatched custody/current recipient, expiry,
  required-effect rollback and actual lost-COMMIT recovery are covered. Complete
  source review APPROVES. Suppliers `6bc1800`, `cdca7c4`, `ef49eb3`, `8954d0d`
  and Reference `5235852` are main-pushed with exact Required CI green (final
  `39947940239`). Six public-supplier PostgreSQL/race journeys pass (295.782s).
  The actual downloaded public Reference archive matches all 333 committed files;
  a separate no-replacement consumer passes rename/recovery under PostgreSQL/race
  (131.047s), and module verification passes. Full M12 remains open for remaining
  OTP management and retained method profiles; no full-unit qualification added.
- **New M12 OTP removal profile delivered:** consumers can remove the sole
  active OTP factor using a fresh action proof while preserving real email
  recovery. Recipient references are erased, recovery codes retired and sessions
  revoked atomically. Password signin works before reset; actual delivered reset
  still works afterward. Native `f67a836` and Reference `e4ae9ab` are main-pushed,
  independently approved and exact-CI green (`39951283337` / `39951836008`). Four
  PostgreSQL/race journeys pass (136.429s), including competing commands, true
  COMMIT recovery, fresh-key denial and retained TOTP removal. Public-supplier
  checks pass (106.701s); the actual downloaded Reference consumer passes both
  normal/recovery journeys (72.209s), with modules verified. Full M12 stays open.
- **New native workload-exchange profile delivered:** an owning Basic workload
  client can exchange reusable access tokens for independently narrower children,
  retaining root/parent lineage, immutable admission deadlines and exact-intent
  retry/recovery. Live client/ancestor withdrawal denies, including after
  preflight. OAuth `9969c9d` / native `5c597f4` are main-pushed and independently
  approved; final exact CI `39952121519` is green. The downloaded public native
  consumer passes five PostgreSQL/race journeys (44.086s), modules verified.
  HTTP/reference, human/API-key/organization sources and remaining M33 stay open.
- **Qualification remains open:** scheduled full-history secrets run
  `39925320307` failed; the separate current-change push checks above passed.
  No whole-history clearance, new full-unit qualification or platform
  completion is claimed.
- **Newly delivered:** trusted abandoned-guest cleanup/anonymization in native
  `anonymous/postgres`, main `d2f004f`, exact Required CI `39908869694` green.
  Current standalone PostgreSQL/race coverage includes stored policy, holds,
  concurrent upgrade, required-effect rollback and original COMMIT recovery.
- **M09 consumer milestone closed:** native/HTTP/reference guest signin, read,
  self-deletion, protected permanent upgrade and abandoned cleanup are delivered.
  Reference `64cee17` is independently approved, main-pushed and exact-CI green
  (`39914521812`). All five journeys pass against the actual downloaded public
  Reference module under PostgreSQL/race (16.170s); module verification passes.
  The historical intermittent startup failure remains unattributed qualification
  debt, not a claimed fix or a passing historical run.
- **Parallel OAuth logout:** retained-output activation regression is corrected;
  affected PostgreSQL/race checks pass and complete source review approves
  without findings. Root/child contracts are main-pushed (`ef452a3`, `8f25462`).
  Native adapter `03b57e3` is also main-pushed and independently approved.
  Its downloaded public PostgreSQL/race consumer passes (37.888s), including
  exact-source denial, sibling preservation and original COMMIT recovery.
  Root/child/native CI is green, including exact native run `39915425644`.
  This finite native profile is delivered; full M31 and HTTP/reference remain open.
- **M11 consumer milestone closed:** secondary-OTP enrollment/delivery/
  confirmation, password/OTP signin and usable session/read/logout are delivered.
  MFA `665a40f`, session `c4d031c` and Reference `f721a66` are independently
  approved, main-pushed and exact-CI green. The actual downloaded public
  Reference module passes both real PostgreSQL/race OTP journeys (37.995s),
  including changed-authority denial, rollback/recovery and separate enrollment
  selection. Canonical public-dependency TOTP compatibility also passes.
  Broader MFA variants and whole-unit qualification remain open.
- **Next:** continue M12 with explicitly selected OTP disable and its required
  session/recovery effects, preserving the delivered removal and rename profiles
  without restarting delivered MFA behavior. No Tools, evidence framework,
  whole-repository verification or user decision is needed.

## Earlier checkpoint detail — preserved 2026-10-23 05:29 UTC

**Estimated whole-goal completion: approximately 20–25%, with low confidence.**
**Consumer milestones: 9/39 closed** (23.1% unweighted); full scope remains
67 units. Consumer delivery is separate from complete unit/release qualification.
The working authentication baseline, thirteen email profiles, native username
authentication, organization/team lifecycle, selected OAuth code/PKCE and machine
credentials, and four CAPTCHA adapters are delivered as bounded profiles.
Most platform families and final package qualification are not closed;
queued work is not counted as delivered.
This is an effort/scope estimate, not a measured percentage or an ETA.

**Latest delivered outcome:** exact OIDC `prompt=consent` requires protected
approval even when prior approval is reusable. Genuine approval produces a
one-use S256 code and independently verified ID token/UserInfo; denial produces
neither. OAuth root `dff2a90`, OIDC `cab1968` and native `f84d721` are independently
reviewed, main-pushed and exact-CI green. Actual downloaded-native public,
pairwise and denial partitions have observed race passes; all 85 native archive
files match Git and consumer checksums verify. This finite profile is CLOSED,
not full M30/M31 or unit/release qualification.

**Qualification caveat:** the initial native cohort failed on a prerequisite
password-signin 503; its exact unchanged partition then passed (6.742s). The
initial downloaded consumer failed on second-user registration 503; its exact
unchanged pairwise partition then passed (14.618s). Both causes remain unknown;
neither initial combined command is represented as passed. Other selected
partitions passed, including all five new native consent cases. No code,
configuration, timeout or security limit was relaxed to obtain those passes.

**Retained anonymous outcome:** consumers can run real PostgreSQL guest signin,
unprivileged read, self-deletion and upgrade into an existing verified password
account, followed by permanent-session read/logout. Native initiation works
without HTTP; browser routes remain explicitly opt-in. HTTPab3f4a2 and
Referencebbda009 are independently approved, pushed to main and exact-CI green.
The actual downloaded public Reference module passes all three native/HTTPS
journeys under race (7.224s), with public sums verified and no replacements.
The delivery auditor independently matches source/review/public-artifact/CI.
Full M09 remains open specifically for abandoned-guest expiry cleanup and
anonymization, including stored retention/legal holds, concurrent-upgrade fences,
atomic owner effects and interrupted/unknown recovery. That is the next primary
implementation, not another review of delivered signin/read/delete/upgrade.

**Current implementation:** abandoned-guest cleanup, using trusted maintenance
authority rather than expired guest credentials. Local PostgreSQL/race proof now
covers the protected kernel/lifecycle/session owners, disposal policies, pruned
sets, required-effect rollback and actual pending/retained-evidence recovery.
Review found a receipt-only expiry could falsely commit without kernel disposal;
the regression reproduced it and the existing actual-mutation guard now rejects
it. Shared kernel, session and anonymous owner batches are now independently
approved, main-pushed as `50a36bd`, `24a0cbb` and `71baace`, and exact-CI green.
Standalone public-dependency PostgreSQL/race checks cover expiry owner effects
and retained browser deletion/upgrade. The new local public maintenance service
now selects a bounded oldest-expired page, anonymizes the selected guest,
retains original-command retry/recovery and reports the remaining backlog.
Current policy denial, held-subject deferral/cursor progress, unavailable-policy
denial, batch limits/cancellation, post-admission hold races, required-outbox
rollback and actual before/after-COMMIT loss recovery pass the focused real
PostgreSQL/race group (6.271s). The first group exposed held-callback error
redaction and missing typed unknown errors; both reproduced and are corrected.
This service remains uncommitted and unreviewed. Reference composition and
remaining cleanup acceptance/public delivery are unfinished. No M09 increment
or complete cleanup delivery is claimed.

**Parallel implementation:** OIDC logout core/transport checks pass under race.
Published identity/session owners have unblocked the native worker. Current
native focused PostgreSQL/race checks cover exact-source logout, required-effect
rollback and actual before/after-COMMIT recovery (41.122s). Direct-native
issuer/environment and original sealed read-start regressions first failed,
then passed after the owning correction (13.598s); the root race and compact
fuzz checks also pass. These are worker-attributed results, not reviewed or
delivered native OAuth behavior. Remaining affected controls, independent review
and public-consumer delivery remain pending. Neither active lane closes another
consumer milestone. The 20–25% estimate and 9/39 count are unchanged.

**Retained delivered behavior:** native OIDC `prompt=none` reuses original bounded
explicit consent without interaction or renewal, then issues a one-use code for
S256 exchange and independently verified ID-token/UserInfo. Root `9f0f023`, OIDC
child `284bf8e` and PostgreSQL `723fdfd` are on OAuth main; exact Required CI
39576005546 is green. The downloaded native public module passes the real
PostgreSQL/race RP journey (6.351s), without workspace or replacements. The
public-dependency required-effect/commit-loss cohort also passes (30.581s).
Independent regression, compatibility, correctness and delivery audits close
this **finite native silent profile**, not full M30/M31 or release qualification.
Activation requires forward history and positive consent TTL on every accepting
writer; mixed/zero-TTL writers after activation are unsupported.

**Current implementation:** M09 anonymous HTTP/reference now passes a genuine
PostgreSQL/HTTPS/race journey: guest signin/read/deletion; separate target signup
→ captured verification → password signin → fresh action proof → guest upgrade
→ permanent session read/logout. Required key/dual custody denial, consuming
outbox rollback, one-use proof rejection, exact protected effects and original
metadata-only HTTP retry/native recovery also pass (reference cohort6.922s).
Guest recognition never becomes verified authentication; permanent-cookie
presence never falls back to a guest. Upgrade requires one Idempotency-Key and
both original synchronizers. HTTP and Reference are now delivered on main with
exact-source CI and actual public-consumer proof as summarized above.
No milestone increment.

**New native OAuth/OIDC delivery:** opt-in verified-phone UserInfo is on main
(child513df9f/native20d7c1b), both exact Required checks green. Real public-pin
PostgreSQL verification/removal/replacement, public/pairwise RP and existing
email fences pass74.437s; actual downloaded-native RP consumer passes16.565s.
Independent correctness/adoption/delivery audits support this finite profile.
ID tokens remain minimized; pending contacts are omitted and cascades remain
pending, not acknowledged cleanup. Full M31 and release qualification remain.

**Anonymous delivery correction:** original upgrade delivery expiry and alternate
writer protection passed independent rechecks. Final correctness review found
that forwarded201/403 responses still bypassed the GET expiry check. That
remaining variant now has executable red/green proof, including a failing-clock
control. Complete C2/C3 reviews are APPROVE and both sources are main/CI-green.
Finite transport/reference delivery adds no unproved whole milestone count.

**Retained delivery:** native guest upgrade `51b6de2`, supporting owners
`a33b0df`/`2eafc25` and capability `183afe9` remain independently reviewed,
main-pushed, public-consumer proven and applicable-CI green. The finite native
upgrade and selected HTTP/reference profiles are **CLOSED**; full M09 scope
and unit/release qualification remain separately assessed.

**Retained M09 runtime evidence, source now native-main delivered:** the selected public
guest-upgrade journey and its affected PostgreSQL/race acceptance pass92.978s.
Real signed target password proof and durable one-use capability drive guest
disposal, all18 guest sessions/19 families revoking and a usable permanent
session preserving the ULID target, historical authentication and remember
policy. Wrong credentials/CSRF, late hold/ban/session/factor withdrawal,
audit/outbox rollback, competing commands, final pre/post-COMMIT recovery and
metadata-only replay after original grant expiry pass. A new transport-key
rotation regression first failed conflict1.381s, then passes2.776s and the race
group: retained original keys no longer change retry identity.
Pruned live guest-session payload recovery and wrong-possession denial now pass.
Issuance before/after-COMMIT ambiguity passes8.895s after the capability owner
added this exact profile to its existing fenced absence proof (the original
case demonstrated unresolved recovery). Its native race/vet passes3.530s; the
three-file prerequisite is independently APPROVED and main-pushed183afe9, with
protected-main CI39562261222 green. Retained
public signin/self-deletion/full-upgrade controls pass22.585s; native ordinary
race/tagged vet and complete78file secret checking pass. The complete78file
identity candidate and its public-pin/KeepTarget delta are independently approved
and native-main delivered as summarized above. Final full M09 composition remains.
HTTP/reference remains. This is not M09 closure; no count increment for an
unfinished delivery.

**Newly delivered OAuth client discovery:** a fresh, currently authorized
platform manager lists/gets safe client IDs and versions, then rotates/deletes
using those discovered versions. Root39061aa and nativee429531 are independently
APPROVED, main-pushed and exact-CI green (39549697571/39550056456). Public-root
PostgreSQL/race discovery/custody/original-deadline acceptance passes45.503s;
the downloaded public-native fresh discovery -> rotation/delete consumer passes
10.273s without local replacements. All68 root/69 native downloaded files match
committed source. Denial, pagination, actor-scoped cursor, late withdrawal and
unchanged mutation recovery checks pass. This finite profile is CLOSED; full M30,
HTTP/reference and unit/release qualification remain open. Still9/39 milestones.

**Newly delivered OAuth client replacement — finite profile CLOSED:** fresh
manager discovery -> complete redirect/scope replacement -> old-grant denial ->
new explicit consent/code/token works with unchanged Basic custody. Root3d1ae94
and nativeb9a37e4 are independently APPROVED, main-pushed and exact-CI green
(39559012902/39562093099). Public-root PostgreSQL/race journey and populated-
history compatibility pass29.271s; the actual downloaded public-native journey
passes12.868s without replacements. All70 root/75 native artifact files match
committed source (native LICENSE inherits the root). Secret generations and
original overlap expiry are preserved. The reviewed oracle defect is corrected;
all ten affected race cases have observed passes, while the original fixture503
group remains recorded as failed and its unchanged exact rerun as passed.
Full M30, HTTP/reference and unit/release qualification remain open; still9/39.
The bounded next-lane readiness pass is complete and the OIDC silent-
reauthorization worker is active. Enterprise SSO/SCIM remain parked for missing
atomic owner composition.

**Active M09 — guest signin/self-deletion native profile delivered:** genuine public signin creates the kernel
identity, anonymous lifecycle and session atomically, with pre-auth/risk and no
verified-user elevation. Own bearer/CSRF self-deletion applies retention/legal
hold, all three disposal owners and session/family revocation atomically.
Original metadata replay/fresh-instance recovery works without renewing or
revealing credentials. Combined native PostgreSQL/race17.222s and tagged vet pass,
including denial, late audit/outbox rollback, contention and real pre/post-COMMIT
faults. Independent complete-source review is APPROVE. Its TTL precision
finding is corrected: focused expected RED, full core race1.208s/vet0 GREEN.
The added genuine-source fixture proves all18 sessions/19 families revoke across
two pages, including an expired active sibling and an empty family. Fresh-service
original recovery still succeeds after all live session payloads are pruned;
wrong possession and restored guest authority deny. The reviewer reconciled the
final complete89-path source. Permanent upgrade and HTTP/reference remain;
no M09 closure is claimed. Root/session/risk46ae607, kernel607749d,
anonymouscoreabfaf01, sessionnativecec88f4 and anonymousnative5a00abc are
main-pushed and exact-CI green. Independent final source/public-pin review
APPROVE; final checkout public-dependency PostgreSQL/race PASS11.195s, tagged
vet and module verification pass. Actual downloaded native
v0.0.0-20261021024534-5a00abc431cb matches all23 files against source; its genuine
PostgreSQL/race self-deletion baseline/lost-COMMIT consumer PASS5.259s without
local replacement. Final exact Required39534807911 is green. No unit increment.

**Newly delivered OAuth client management profile:** a genuine current platform
manager can create a confidential client, use it through two already-running
ordinary code/S256 services, and terminally delete it. Old credentials and
descendants then deny. Root023e5fe and native089714d are main-pushed, exact CI
39537009275/39537703223 green and independently APPROVED. All three concrete
review findings are corrected. Actual public-root failure/recovery consumer
PostgreSQL/race43.997s and downloaded public-native warm consumer5.707s PASS;
all64 root/60 native downloaded files match source. This finite profile is CLOSED,
not full M30: remaining management and HTTP/reference remain open. The later
rotation delivery is summarized below.

**Earlier guest-upgrade component checkpoints (superseded above):** local typed
merge plans and protected risk counters pass focused/full-core race/vet/fuzz.
The existing password-proof owner now frames the permanent target independently
from the guest resource; focused framing/compatibility race1.427s and vet pass.
These are unfinished, unreviewed prerequisites, not native upgrade delivery.
The closed kernel upgrade declaration and guest-only disposal now also pass
actual PostgreSQL/race2.626s alongside retained self-deletion, including permanent
ULID target preservation and late rollback. These kernel tests use explicit
capability/counter probes; real cryptographic consumption, anonymous mapping,
session replacement and HTTP/reference remain unfinished. No M09 closure.

**New guest-upgrade component result:** real PostgreSQL/race 3.205s proves guest-only
kernel disposal plus revocation of all 18 guest sessions/19 families, one new
permanent session and unchanged permanent ULID target. Late failure rolls back
both owners; an existing prospective-family collision now denies. These tests use
explicit capability/counter probes, not actual signed-proof orchestration. Native
proof issuance/consumption, full upgrade service and HTTP/reference remain open.
Its capability verification prerequisite e01a370 is now main-pushed and exact
Required 39544505289 green; the authenticated public adapter matches source.
Primary adapter adoption remains pending.

**OAuth rotation finite profile CLOSED:** approved native rotation f5ae7d0 and
patched-toolchain metadata d130abc are main-pushed; exact Required 39545663160
is green. The actual public-root PostgreSQL/race consumer passes 31.296s without local
replacement. Clients can rotate with explicit bounded predecessor overlap;
rotation invalidates older grants, and new explicit authorization is required.
The original retained authentication deadline defect is corrected and independently
reviewed. All 65 authenticated public-native files match source; that downloaded
module's actual rollback and original pre/post-COMMIT recovery consumer passes
PostgreSQL/race 23.681s without local replacement. Full M30, HTTP/reference and
unit qualification remain open; closing this profile does not increment 9/39.

**Delivered OIDC email profile:** consented email UserInfo works through actual
code/PKCE/access-token and independent-RP consumers. Rootd80acf5, child9d8cd36
and native8a1518be are approved, main-pushed and exact-CI green. Default
openid-only and minimal ID tokens are unchanged. This profile is CLOSED;
full M31/HTTP/reference and release qualification remain open.

**Delivered own-consent narrowing:** a genuine fresh same-browser user can
reduce an existing consent's scopes; every older code/access/refresh/UserInfo
descendant then denies, while a new explicit narrow authorization succeeds.
Root8fdea7a and nativeb89d656 are independently approved, main-pushed and exact-
CI green. Crash recovery and post-lock original expiry findings are resolved.
The actual downloaded native module passes its keyed consumer under race9.332s;
all52 authenticated files match source. This profile is CLOSED, not full M30.

**Delivered OAuth protected-resource profile:** actual code/S256 access can now
reach a demanded-scope-only resource read; refresh tokens, withdrawn authority
and raced consent narrowing deny. Independent complete-source/public-pin review
APPROVE; rootbfb5499, native0e3a9eb and documentation correctiona3ec583 are
main-pushed. Actual authenticated public-native consumer passes PostgreSQL/race
5.411s, with all55 downloaded files matching source. Native runtime/security
checks passed; the sole spelling failure was corrected without runtime edits.
Final exact-head Required39530758363 is green. This finite profile is CLOSED;
full M30, HTTP/reference and unit qualification remain open.

**Delivered organization domain-proof authority:** rootf7d9a1a and native4eac678
are independently approved, main-pushed and exact-CI green. Real consumers can
apply an observed proof, read exact current authority, revoke and recover without
renewing expiry; archive/restore cannot resurrect proof. The authenticated public
native module's genuine consumer passes PostgreSQL/race8.039s. Risk0e56be2 supplies
the two exact privileged owner actions. DNS challenge/observation, SSO integration
and full M25 remain open. The source check confirmed a kernel-owned typed
participant-admission gap for atomic challenge consumption; that successor is
parked, and no SSO worker/code is active. The dependency-ready OAuth lane is
platform-owned confidential-client creation, ordinary code/S256 use and terminal
deletion; creation, rotation and private discovery profiles are now delivered as
described above. A fresh bounded check confirms SSO/SCIM remain parked for actual
primary-owned atomic challenge/provisioning admission, not missing parsers.
Primary-owned M09 continues independently; its full native upgrade is unfinished.

**Qualification gap:** whole-tree secret scanning flags11 unchanged delivery
test/documentation locations; changed-path findings are zero. This is not a
passing whole-tree scan or an established new credential leak. It does not
block the current M09 implementation. Disposable initial-run resources are removed.

**New delivered consumer:** the full selected phone-reset reference journey
now passes real PostgreSQL/HTTPS under race (final group216.846s: success,
required-audit rollback, lost-COMMIT recovery and retained phone-removal
HTTPS/commit-custody profiles). Actual preceding registration/verification,
verified phone and confirmed TOTP lead to captured SMS/link, reset, old-password/
session denial and new-password+TOTP session read/logout. Rollback preserves old
credentials; unknown commit is recovered through the exact original completion.
Complete independent review found two defects; the existing removal assertion
and conflicting email/phone reset schema handling are corrected. The otherwise-
valid mixed-schema control now rejects phone enablement without rewriting email
history, while email-only and matching combined schemas remain accepted. Final
source and public-pin review is APPROVE. Prerequisites are main-pushed `387cc56`
and native workflow plus opt-in HTTP are main-pushed `da005d5`; both exact CI
runs are green. Native PostgreSQL/race12.607s, ordinary race2.125s/tagged vet0 and
HTTP-phone race5.890s/vet0 pass against authenticated public dependencies without
local replacements. Reference public-pin adoption is now independently APPROVED;
its genuine public-supplier PostgreSQL/HTTPS/race success, rollback and lost-COMMIT
group PASS53.032s. Ordinary reference/cmd race8.624s/7.622s, tagged vet and module
verification pass. The accepted reference profile is now main-pushed as
`d5156d8`, exact Required CI `39505315426` green.
All313 downloaded public-reference files match source; the downloaded module's
actual PostgreSQL/HTTPS/race recovery consumer PASS14.243s with GOWORKoff.
This finite recovery profile is CLOSED, not another implementation in progress.
M08's assigned existing-account consumer outcome is CLOSED: verified enrollment/
change, OTP/password signin and reset have successive reviewed public-reference
deliveries. Independent scope reconciliation distinguishes that roadmap row from
whole-unit completion. Phone signup and privacy remain full-goal obligations,
not implicitly supported. No verified unit, tagged release or deployment is added.

The entries below retain earlier checkpoints; their pending/local wording is
historical where superseded by this current summary.

**Current checkpoint:** organization archive/restore is now main-pushed in both
owners: public root `d3aab92` (exact CI green) and native PostgreSQL `ab44333`
(exact CI `39483890213` green). One complete independent review approved the
final source and public-pin reconciliation. Actual native public-root consumption
passes PostgreSQL/race 14.465s without local replacement. Current owners can
archive and restore with genuine signed action proofs; archive denies local
organization authority and restoration preserves terminal child decisions.
HTTP/reference, external cascades, hard deletion and full M22 remain open.

**Phone reset now works through the real native transaction locally:** original
keyed request -> actual SMS/code-and-canonical-link dispatch -> distinct
completion risk -> SMS plus independent TOTP -> HIBP/password replacement ->
all-session revocation -> original metadata replay/code-free recovery. Actual
Final affected PostgreSQL/race phone-request/source/completion, receipt and
phone/email generation group now PASS13.111s; earlier native ordinary race2.154s and
integration-tagged vet exits0. Each wrong SMS/TOTP conjunction charges
one original SMS attempt without advancing TOTP replay, changing password/
authority or revoking sessions. The rollback oracle proves successful audit
persistence was reached after provisional reset effects before rollback.
Fresh-service replay neither rehashes nor renews evidence; changed device,
network, origin, evidence, issuance or password under the command is rejected.
Outbox main493107bf already supported this profile; adopt its authenticated
public module rather than reimplement it. Its exact CI is green; focused supplier
race1.244s, ordinary race1.142s and vet0 pass. All diagnostic source changes in
kernel/OTP were removed exactly. Native phone code remains local, unreviewed and
uncommitted. Matching completion-risk retries now survive their own consumed
browser/factor state without provider re-evaluation or renewed evidence. Changed
network/device/issuance/new attempts deny. Original rate metadata is likewise
authenticated after consumption without restoring current mutation authority.

**HTTP implementation is now local:** request/completion handlers, closed OpenAPI,
original flow/device custody, staged rate admission, enumeration-safe request
acknowledgments and submitted-secret cleanup pass the full phone HTTP race suite
(5.952s) and vet. Recovery preauth focused race passes2.170s. Reference
selection/guarded handles, recovery-browser method,
shared-rate lifecycle and native migration/readiness wiring compile and pass
focused history/selection plus ordinary reference/cmd race8.807s/6.695s and
tagged vet0. These are not real reference reset journey proof. Next is genuine
PostgreSQL/HTTPS reset acceptance including old/new-password signin, revocation,
rollback/lost-COMMIT and original retry. Independent whole-slice review and
commit/push remain unfinished. No whole milestone
or qualified-unit increment is claimed; primary continues the complete reset
slice rather than delivering isolated helpers.

**Retained request checkpoint (before native completion above):** public keyed
phone-reset request and owned initiation-risk evaluation
now reach actual encrypted SMS/code-and-canonical-link dispatch through the real
PostgreSQL delivery worker. Fresh-instance replay queues no duplicate message;
terminal receipt replay survives original TOTP withdrawal. Actual PostgreSQL/
race passes3.049s. This remains local, unreviewed and uncommitted. Completion,
HIBP-screened password replacement and session revocation were unfinished at
that checkpoint; their current native proof is above. HTTP/reference and full
reset/milestone closure remain unfinished.

Organization archive/restore's real password/MFA proof prerequisites are
independently approved and main-pushed132bbe2; exact Required39478223109 is green
(structure/secrets, not hosted PostgreSQL). Both authenticated public modules
match the committed changed files and manifests. The organization worker is
implementing/testing the actual archive/restore business workflow against these
suppliers. This prerequisite does not itself deliver archive/restore or M22.
M10's existing confirmed-TOTP enrollment/signin consumer is now counted after
source/acceptance reconciliation; this corrects a stale row, not new development.

**New working consumer:** verified-phone/password -> independently enrolled TOTP
-> authenticated session read -> logout/code-free recovery is delivered through
published reference `577df95`, independently approved and exact Required-CI green.
All 307 downloaded reference files match source; its actual PostgreSQL/race
consumer passes6.026s without local replacements. Four phone profiles plus
retained email/phone-SFA/username consumers passed33.409s using public suppliers.
Phone-only and coexisting selection, denial, rollback and lost-commit recovery
are covered; no new TOTP HTTP variant or weaker fallback is enabled.

**Remaining:** full phone reset is still disconnected. Native MFA/session,
password and joint OTP prerequisites are delivered/CI-green, including corrected
terminal TOTP-receipt enforcement. Primary now connects request/delivery and
completion through those real owners. Organization direct custom roles are now
delivered: root `c86393f`, PostgreSQL `8028455`, independent approval and exact
Required CI `39464598005` green. The downloaded native adapter's genuine-session
consumer passes PostgreSQL/race 7.277s; all 69 public files match owning source
(including inherited root license). Managers can create/update/delete roles,
assign/revoke direct bindings, discover binding versions and check current
permissions. Team-derived permissions are also delivered below; HTTP/reference
and full M23 remain open.
No whole milestone or qualified-unit increment is claimed for either family.

**Primary local work:** actual phone-reset request composition now passes
PostgreSQL/race2.926s: genuine original recovery browser, verified phone/current
password/enrolled TOTP and real initiation risk -> one-use risk consumption +
SMS + canonical reset capability + two encrypted delivery intents, atomically,
then original receipt replay. No risk provider re-evaluation/expiry renewal;
foreign-user original resolution denies. Required-audit failure rolls back SMS/
delivery and does not finalize risk; success plus rollback pass PostgreSQL/race
4.454s. Ordinary native race2.305s, tagged vet and module authentication pass.
This phase is uncommitted/unreviewed. Keyed public orchestration and actual
delivery dispatch now work locally as recorded above; protected completion/
session revocation remain disconnected, so this is not usable full reset or
another closed milestone.

**Parallel:** WebAuthn same-Work registration prerequisite is independently
approved and main-pushed4667db4; exact Required CI39471467101 is green. Its
negative scope/digest cases pass real PostgreSQL and detect removed guards.
Passkey enrollment still needs real identity/proof integration; no M16 closure.
Organization team-derived roles are independently approved and main-pushed:
root892822a and native489fd67. Exact Required CI39473905207 is green
(structure/secrets, not hosted PostgreSQL). Genuine PostgreSQL/race consumption
of the authenticated public root passes7.588s; unchanged direct/team race
suite42.042s is retained. Current team members inherit bounded custom permissions;
removal/readmission, deletion and revocation do not preserve stale grants.
HTTP/reference and full M23 remain open. Migration proof covers install/replay,
not upgrade over populated organization/team/role tables.

**Retained earlier checkpoint:** phone-reset request contracts/kernel preparation are
main-pushed at `eb40883` with exact Required CI green. The phone-MFA canonical
history/recovery prerequisite is independently approved, main-pushed at `d2d1fa5`
and exact Required CI green. Genuine native SMS request
persistence and canonical reset-grant/SMS delivery pass locally. The capability
phone-MFA-origin prerequisite is main-pushed at `34ff029`, with exact green CI.
The selected reference phone/password -> confirmed TOTP -> usable authenticated
session -> logout/code-free recovery consumer now passes locally under race,
including independent/coexisting selection, wrong-code accounting, foreign
scope/owner denial and secret-free replay. Actual rollback/lost-COMMIT cases
pass10.901s; existing email/username/phone baseline consumers pass15.956s.
All four phone/TOTP profiles additionally pass20.198s with the real authenticated
public capability supplier instead of its removed task clone.
These are local coimplementation results, not final independent review,
public-supplier adoption or delivered reference support. The initial passing
harness had skipped enrollment; that result is
withdrawn as TOTP proof and the corrected harness now requires actual completion.
M08/reset remains unfinished; no whole milestone or unit is added.

**Current phone-reset gap:** request -> delivered SMS/capability -> joint
completion -> HIBP-screened replacement -> session revocation is not connected
end to end. No new whole milestone has closed. Native SMS/TOTP conjunction tests
now prove one existing attempt budget, no charge for stale/withdrawn authority,
rollback and ambiguous-commit behavior; they caught and corrected a late-expiry
charge after a lock wait. Protected consuming integration now passes locally:
actual MFA verification/replay CAS, exact same-transaction successor checking,
OTP finalization and pre-auth consumption commit together. Its five PostgreSQL/
race cases also compose the actual session-revocation effect: active and expired
local stored rows revoke, another tenant stays unchanged, and failed or expired
completion rolls back replay, credential and session effects (4.379s). Session
payload fixtures do not prove authenticated session use; capability/risk peers
and the domain marker remain labelled seams, not the full reset workflow.
The risk adapter's current-counter/expiry/writer-fencing behavior is reviewed,
main-pushed at `81bbbbb` and exact Required-CI green (structure/secrets, not
hosted PostgreSQL). Its real PostgreSQL proof uses a labelled domain-effect
fixture, not the complete reset. Capability preparation is independently approved
and main-pushed at go-capability `64bed7f`, with exact Required CI green and its
downloaded artifact matching source. The first CI attempt failed obsolete root
checksums; the reviewed two-line tidy correction passed. Local phone request
contracts pass focused race and bounded fuzz, but
contracts alone do not enable a workflow or endpoint. Remaining MFA/OTP,
password/session, native service and opt-in HTTP/reference composition stay open.
Original-risk resolution and HIBP preparation are independently approved and
main-pushed at `6d5c539` / `ddf1c0f`, both exact Required-CI green. The password
module selects the authenticated public risk supplier and passes standalone
race/vet/tidy/module verification; all 92 downloaded risk files match source.
The joint kernel/OTP/MFA/session changes are independently approved; kernel/core
OTP are main-pushed `5c1b014` with standalone public-supplier checks. Its initial
Required run flagged two public protocol identifiers as a secret; the reviewed
formatting-only follow-up `ff72a5b` is main-pushed and Required-CI green. Native
MFA/OTP/session public pin integration remains open. The outbox formatter is
main-pushed `493107b`, Required-CI green, and all 28 public files match source;
its task clone is removed. Real enrolled-factor SMS generation/restoration now
passes locally, but actual request Work exposed missing kernel preparation gates.
The exact initiation-risk/SMS/capability preparation regression is now locally
green; genuine request persistence remains in progress. Actual SMS/capability
request/delivery, canonical password
material, full native service and opt-in HTTP/reference composition remain open.

**Newly delivered organization reservation profile:** a genuine owner/admin can
reserve a canonical domain, read its current claim and withdraw it, with global
uniqueness, current authority and original recovery. Root `2ee78bf` and native
`bbf7a6e` are independently approved, main-pushed and exact Required-CI green
(structure/secrets, not hosted runtime tests). Actual public-root PostgreSQL/race
passes (13.557s); all 64 final native public files match committed source, and
the downloaded adapter's genuine PostgreSQL/race consumer passes (11.227s).
Apply `DomainClaimMigrationSource` after the base organization migration before
selection. This is reservation, not verified ownership, DomainProof or SSO.
Full M25 and HTTP/reference remain open; no whole milestone is added.
An earlier final-public run failed at bootstrap signin503 before domain behavior.
Diagnostic-only execution confirmed one inner signin deadline, but not the slow
phase/cause. That failure is retained; unchanged subsequent acceptance does not
prove a reliability repair. No timeout or security limit was relaxed.

**Newly delivered organization profile:** authorized static member-role changes
now atomically update membership/scoped authority and organization policy, with
last-owner protection, current-role enforcement and original recovery. Root
`5f52a2e` and native `93f15a5` are independently approved, main-pushed and exact
Required-CI green. Actual public-root PostgreSQL/race suite passes (24.149s);
the downloaded adapter's genuine-session consumer passes (10.719s), with no
local replacements. Existing schemas suffice. Full M22/M23 and HTTP/reference
remain open. The earlier broader suite's signin503 remains unexplained, not fixed.

**Newly delivered organization profile:** authorized administrators can explicitly
expire an invitation with a registered reason, before or after its deadline.
Terminal expired2 invalidates the original proof; natural expired1 stays a
projection. Root `a2f65b2` and native `51f98f3` are reviewed, pushed and CI-green.
A separate downloaded-module consumer passes real PostgreSQL/race expiry,
including rollback, contention and lost-commit recovery (13.030s). Apply the
forward expiry migration before enabling it. M22 and HTTP/reference remain open.

**Newly delivered organization profile:** the intended verified recipient can
reject an invitation without membership or bearer proof. Durable rejection
denies later acceptance, including the original proof after reconstruction;
replay/recovery, faults, contention and current-authority checks pass. Root
`0035389` and native `5483038` are independently approved, pushed and Required-CI
green. Their public artifacts match committed source. A separate no-replacement
public consumer passes genuine PostgreSQL/race rejection (19.677s). Apply the
forward rejection migration before enabling it. Organization HTTP/reference and
the remaining M22 lifecycle remain open; this is not a new full milestone.

**Newly delivered selected profile:** verified-phone replacement, from authenticated
new-number SMS to atomic replacement, old-number denial and retained recovery.
Its compound directory transition and exact request/consuming-plan contracts
are reviewed and root/phone contracts are pushed at `cb4384b`, with green CI.
Native CAS/retirement/pending-cascade storage is reviewed and main-pushed at
`33871a2`, with green Required CI and a byte-matched public artifact. Real
PostgreSQL/race proves the directory prerequisite, not genuine phone possession.
Local native orchestration now completes new-number SMS -> distinct fresh
update proof/original OTP -> atomic replacement/retirement/old-number notice ->
old-session and retired-phone denial, usable new-phone and retained-email
sessions, independent reset request and code-free recovery. Twelve genuine
PostgreSQL/race cases pass (31.998s), including bearer/cookie, rollback/lost
COMMIT, contention, late factor withdrawal and provider outage. The outage and
withdrawal regressions caught invalid result projections and now pass without
charging OTP or consuming the proof. Affected five-module ordinary race passes.
The contention fixture now uses its coordinator IO budget rather than the
500ms lease selected for prompt ambiguous-outcome recovery; the earlier
intermittent no-winner failure is not attributed to a proven lock-order defect.
Retained native enrollment/password/OTP-signin checks subsequently passed
(118.196s). Independent review identified missing keyed completion replay and
wrong audit action/retention. The local fixes now pass all twelve genuine
PostgreSQL/race cases (39.087s), including lost wrong-code and successful-response
recovery under the original key, changed-code conflict and canonical persisted
identifier events with standard retention. Four affected ordinary modules pass
race. Fresh review confirmed those fixes and exposed a concurrent-retry disclosure
gap. The native correction now passes eight deterministic bearer/cookie races
(23.389s): allowed history is replayed, and withdrawn account, credential or
query authority receives no receipt. Full eighteen-case PostgreSQL/race now
passes (61.953s), with all five affected ordinary race suites and tagged vet green.
Final complete-source re-review approves the corrected workflow. Phone/kernel/MFA
prerequisites are main-pushed at `b1c611f`, with exact green CI. OTP-native public
adoption passes standalone race/vet/module authentication and its publication
addendum approves the thirteen-path prerequisite; `110c9b6` is committed.
Password-native `1600f09` is now independently approved, main-pushed and exact
Required-CI green. Its full eighteen-case genuine public-dependency PostgreSQL/
race run passes (45.751s). An earlier run failed before the forced concurrency
schedule; only that test rendezvous budget was corrected, with no production
limit or security assertion change. The earlier failure is not called fixed.
Opt-in replacement-only reference `10eb07f` is now independently approved,
main-pushed and exact Required-CI green, with transport `b301f87` and contract
prerequisite `481045f`. Its actual downloaded public module passes the genuine
PostgreSQL/HTTPS/race consumer (12.085s): populated upgrade, captured SMS, exact
wrong/successful key recovery, replacement, old session/phone denial, usable new
phone and retained email, old-number notice and independent reset delivery.
All 307 public reference files match committed source, including inherited
license. Apply the forward native migrations before enabling replacement.
This selected replacement profile is closed; full M08 and unit qualification
remain open. No new whole milestone is counted.

**Newly delivered organization resend profile:** core `9b574e6`, kernel `08705b0`
and native `a20a7b9` are independently approved, main-pushed and exact Required-CI
green. Authentic public modules match committed source. The downloaded native
adapter's genuine PostgreSQL/race consumer passes (15.617s): two supersessions,
old-proof denial/new-proof acceptance, original delivery history, current
authority, rollback/contention and lost-commit recovery. Apply the forward resend
migration after expiry before enabling it. This selected native profile is
closed; full M22, HTTP/reference and unit qualification remain open. Its worker
fixtures and caches are removed. No shared phone files were assigned.

**Newly delivered native OIDC profile:** code/S256 -> ID token ->
independent relying-party/JWKS -> same-subject UserInfo consumer in
go-oauth-server. It uses the existing genuine session/consent/grant owners;
The genuine native PostgreSQL/RP consumer and selected race checks pass locally.
The complete corrected candidate is independently approved. Core extension and
signing contracts are main-pushed at `1cbd6cc`, with exact Required CI green and
an authenticated, byte-matched public artifact. The optional OIDC child is now
main-pushed at `9c51845` after standalone public-root race/vet/module verification
and its dependency/publication review; exact Required CI is green and its public
artifact matches committed source. Native `56f3281` is now reviewed, main-pushed
and exact Required CI green (attempt 2; attempt 1 had a Go proxy transport error,
not a source/test failure). Actual public-root/child native PG/race selection
passes (90.427s); all 33 downloaded native files match committed source. The
downloaded adapter's genuine independent-RP and durable-signing-restart consumers
pass under PostgreSQL/race (10.295s), without replacements. Install the forward
signing migration before selecting OIDC. This closes the selected native public-
subject/ES256 profile, not full M31. HTTP/reference, pairwise/logout/private exchange
and full provider/unit qualification remain open. All worker PG/cache/scratch
resources are removed. No full milestone or unit count is increased.
**Newly delivered pairwise OIDC profile:** registered single-host sectors keep
stable ID-token/UserInfo subjects across grants, reconstruction and key rotation,
including refresh after old-key retirement. Public subjects remain unchanged.
Root `f1cec65`, child `33943e5` and native `2aa074c` are independently approved,
main-pushed and exact Required-CI green. Actual public-dependency PostgreSQL/race
acceptance passes (126.398s); the downloaded native module's independent-RP
consumer passes (15.081s). Apply the forward pairwise migration before selection.
Multi-host sector URI, HTTP/reference/logout/private exchange and full M31/unit
qualification remain open. No new whole milestone is counted.

**New WebAuthn backend delivery:** opt-in Ed25519 registration and identified/
discoverable assertion, preserving legacy ES256 and original ceremony policy.
Root `ed89b24` and native `43ab7e1` are independently reviewed, main-pushed and
exact Required-CI green. Seven focused actual-public-root PostgreSQL/race cases
pass, including retained ES256, current subject, rollback, lost-COMMIT and
populated upgrade. All 36 root and 18 native public files match committed source.
The downloaded native module's Ed25519 consumer passes PostgreSQL/race (5.238s),
without replacements. Root CI's first scanner startup timed out; attempt 2
passed without source changes or bypass. Actual Ed25519 browser/authenticator
interoperability remains unverified; this is experimental backend support, not
full M15, passkey orchestration or unit qualification. No whole milestone added.

**Active:** primary phone-password recovery. Canonical capability scope, joint
password/capability/SMS/TOTP custody and sessionless pre-auth prerequisites are
now independently approved, main-pushed and exact Required-CI green at
`928f9b7` / `c9ff4fb`. The actual downloaded native adapter passes real
PostgreSQL/race issuance/recovery (2.513s), with no session or invented remember
policy. Native reset request/completion, atomic consumption/revocation and HTTP
remain unfinished and disabled; no whole milestone is added.
Organization's selected reservation/read/withdrawal profile is delivered above;
genuine challenge/evidence authority must still precede verified claims or SSO.
OAuth fresh-login continuation's complete source review now approves all 38
affected paths. Shared kernel `67fa690` and OAuth root `ed0600f` are main-pushed;
kernel exact Required CI is green. Public-supplier kernel race (7.099s)/tagged
vet and OAuth-root race (1.557s)/vet pass. Child/native public-pin adoption,
exact final CI and downloaded consumer acceptance remain pending; this is not
delivery of the full fresh-login profile or M31. Actual native expiry cases pass
locally, with the earlier pre-OAuth confirmation503 retained as unexplained.

**Qualification limit:** scheduled full-history scan `39394030689` has untriaged
secret candidates. Current-change checks and exact publication CI pass, not
full-history security/release qualification. No scanner bypass or history repair.

**Newly delivered native OIDC profile:** actual HTTPS sector registration now
supports multiple callback hosts with stable pairwise ID-token/UserInfo identity.
Root `960e143` and adapter/child `5f2242b` are reviewed and pushed; exact final
Required CI is green. The public-root PostgreSQL/race selection passes new and
retained RP flows (17.374s), and the downloaded final adapter passes the multi-host
consumer (6.412s), without replacements. An outbound-address filtering defect
found in review is fixed with a failing/passing regression. The earlier root CI
failed a spelling check, not runtime tests; corrected final CI passes. No new
migration; existing signing/pairwise histories remain required. Full M31,
HTTP/reference and unit qualification remain open, so the count stays 8/39.
Next parallel profile is real fresh-login continuation for prompt/max_age;
primary work remains the complete phone-password recovery journey.

**Newly delivered M08 profile — phone self-removal:** fresh action-bound proof
removes the verified phone atomically with its retirement, pending cascade and
required old-number notice. Old sessions/phone signin deny; original-key replay
and reconstructed recovery preserve history; actual email/password signin/reset
remain usable. Native bearer/cookie and separately selected cookie HTTP are
supported. Independently approved root `91beaaf`, prerequisites `e97faf1`, native
and HTTP `6dbd35b`, and reference `62ee204` are on main with exact Required CI
green. The downloaded reference artifact matches its committed source. A separate
consumer with no replacements passes real PostgreSQL/HTTPS/race removal and
populated upgrade (79.635s), using only the published modules. See the
[consumer guide](../../reference/PHONE.md#independently-selected-phone-self-removal).

**Retained uncertainty:** one public-dependency aggregate failed during router
startup. The unchanged upgrade case subsequently passed alone and through the
downloaded module; the cause/stability is unproved, not fixed. Completed cases
retain their individual results; the failed aggregate is not reported as green.
Full M08 and final unit qualification remain open; 8/39 is unchanged.

**Parallel WebAuthn:** resident-required registration/discoverable assertion root
API `479cf9a` and native adapter `f9533eb` are independently approved, main-pushed
and Required-CI green (39216149866 / 39217738873). The adapter consumes the actual
public root; PostgreSQL/race/Chromium, late mapping withdrawal and lost-COMMIT
checks pass. Its public artifact matches every committed adapter file. The
downloaded adapter's actual external PostgreSQL/Chromium discoverable and retained
identified consumers pass (1.651s / 1.239s), with authenticated dependencies and
no local replacements. Task resources are removed. This protocol prerequisite
is delivered; passkey/session integration and M16 remain open.

**Retained delivered M08 profile:** verified-phone SMS-code signin through the
reference HTTPS backend, from genuine registration/email verification and
fresh-proof phone enrollment to encrypted SMS, one consuming signin, usable
browser/persistent session read and logout. Wrong-code debit, original target
and browser custody, replay, credential-free recovery and mixed phone-password/
username composition are proven. Independently reviewed reference `fba0485` is
on main, Required CI [39209602841](https://github.com/faustbrian/go-identity/actions/runs/39209602841)
passes, and its actual public module matches all 285 Go/manifest files. The
downloaded module's genuine PostgreSQL/HTTPS race consumer passes (15.324s).
Independent delivery audit supports that bounded claim. See
[the consumer guide](../../reference/PHONE.md#independently-selected-phone-sms-code-signin).
**M08 remains open** for reset, phone change/signup and its remaining assigned
profiles. No whole-unit qualification or new full-roadmap closure is claimed:
8/39 and the approximate 20% whole-goal estimate remain unchanged.

**Retained native/HTTP delivery evidence:** phone SMS-code signin. Prerequisites
`60bd1ec` and native adapter `c50fb10` are independently reviewed, main-pushed,
Required CI green and publicly downloadable. The actual public native module
matches all 130 Go/manifests. Its genuine enrollment -> encrypted SMS -> signin
-> session read/logout consumer passes PostgreSQL/race without local workspace
substitutions (39.514s), including late authority, contention, real lost-COMMIT
recovery and populated migration histories. Native publication has independent
delivery approval. The public-pinned caller is reviewed and main-pushed
`2d4f755`, Required39202608349 green, with independent delivery approval.
HTTP prerequisites are reviewed/main-pushed `807a786`, Required39203184983
green. The actual public HTTP dependency is adopted; canonical standalone OTP
HTTP race/vet/module verification pass. Review caught a real mixed email/phone
OpenAPI scheme collision before HTTP publication; its mixed-selection RED now
passes with separate names and unchanged cookies, as does the complete affected
module race suite (22.053s). Corrected HTTP is independently approved,
main-pushed `b88e709`, Required39204171362 green and publicly downloadable.
The actual downloaded module's mixed phone/email route/schema/dispatch test
passes with race detection (2.967s); independent delivery audit matches the
approved source and public artifact. The complete native-to-HTTPS reference
journey is now delivered above; broad M08 is not closed. Earlier enrollment
fixture intermittency is unexplained; these passes do not prove stability.

**Earlier M08 outcome:** native verified-phone/password signin is main-pushed
`650d24f`, Required CI green, and exercised through its downloaded public module.
HTTP/session and HTTP/password are main-pushed `422b56d`, Required CI green;
their public modules match all 69 reviewed Go/manifests. The real reference
PostgreSQL/HTTPS journey now passes against those public dependencies for browser
and persistent sessions: genuine registration/email confirmation, encrypted SMS
delivery/phone verification, target-bound initiation, password signin, session
read and logout. Retargeting and replay disclose no credentials. Focused HTTP
schema/binding and reference migration/lifetime tests pass. Independent review's
combined-username readiness defect is fixed and proven RED -> GREEN, including
username TOTP and missing-successor probes. Canonical reference ordinary race
and actual PostgreSQL/race pass. Final public-pin review APPROVE covers snapshot
`5430a606`; reference is main-pushed `d65ed4c`, Required CI 39187551070 green.
Its actual downloaded public module matches all 279 Go/manifests and the genuine
phone/password plus combined username/TOTP PostgreSQL/HTTPS consumer passes with
race detection (13.824s). The selected phone/password consumer slice is delivered.
M08 still includes later OTP/reset/change/removal profiles and is not closed.

**Parallel delivery — M15 selected profile closed:** identified-user WebAuthn
none/ES256 registration/assertion and durable credential validation are reviewed
and main-pushed `75a475e` in go-webauthn. Current Required 39188665554 attempt 2
passes after the first scanner timeout; no source or scanner bypass intervened.
Canonical public-root PG/race, real commit-loss and actual Chrome/WPT results
retain their original execution identities. New actual account-suspension
characterization passes PG/race (1.659s) and tagged vet: valid responses deny with
no credential/success-effect mutation or ceremony consumption. Independent final
review and delivery audit approve the bounded claim; the actual public native
module matches all nine Go/manifests. No M16/passkey/session integration,
whole-unit qualification, tagged release or production claim. Worker resources
are removed. The selected phone SMS-code reference consumer is delivered above.

### Earlier checkpoints — historical evidence, not current pending state

**Previous phone-native evidence:** phone/password signin after verified enrollment. Original
identifier-bound pre-auth custody now passes core/native race and the actual
PostgreSQL component journey for legacy and bound browser/persistent flows,
including changed-command conflict, durable read and credential-free recovery.
The integration fixture's role-dependent outbox installation schema is fixed.
Pre-auth core/native custody is independently reviewed and main-pushed
(`7f0a19e`, `6f08283`); final Required CI is green. Canonical public-pin PostgreSQL
proof passes 1.717s and the downloaded native consumer passes 1.729s. The exact
phone/password command is separately reviewed, main-pushed `c5205a3`, CI green.
Its native coordinator delegation/paired-custody/rehash mapping is independently
reviewed and main-pushed `38974dc`, Required CI green. Review caught and fixed
an alternate-owner admission defect before delivery. Phone canonical-target
binding, native discovery/password verification, session issuance/read/logout
and credential-free restart recovery now pass locally through the genuine
enrollment consumer, for browser and persistent sessions. The selected denial,
late-authority, atomic rehash/outbox rollback and real lost-COMMIT matrix passes
PostgreSQL/race 17.339s. Concurrent use of one browser and six populated history
profiles additionally pass 5.170s; affected six-module race/vet checks pass.
Independent review reproduced a stored normalization-profile bypass. Explicit
stored-profile discovery and transactional fences now deny missing, incompatible
and late-changed profiles: three real RED cases -> GREEN; complete 18-profile
native PostgreSQL/race passes 22.387s. Review's optional reset-query projection
inconsistency also reproduces RED -> GREEN in the actual Work selector; the full
affected reset-recipient issuance matrix passes 1.588s. Published minimum
root/kernel pins are adopted by the MFA adapter; its standalone race/vet pass.
The corrected complete source has independent approval. Upstream admission is
main-pushed `2fb0351`, session provenance/migration `6d77f3a`; both Required CI
runs pass. The final native password adapter now selects real public dependencies
without replacements: whole ordinary race 2.138s, tagged vet exit 0, and the
complete genuine phone-signin PostgreSQL/race matrix passes 25.280s. Independent
final public-pin review approves; native publication/CI is pending. HTTP/reference composition and
full M08 remain open; no additional milestone is closed.

**Parallel result:** public identity-error localization consumer and adoption
guidance are independently reviewed, main-pushed `46d7a68` and Required CI
39178082723 green. Locale precedence/fallback, typed safe parameters, original
error identity and exactly-once HTML escaping are proven. This is a bounded
M36 consumer profile, not durable preferences, localized HTTP/delivery or M36
closure. That worker finished.

**Previous WebAuthn implementation evidence:** a GPT-6.1 Sol high worker was building the
selected WebAuthn none-attestation/ES256 registration-to-assertion PostgreSQL
profile. Its committed-contract check found no missing upstream owner; the
primary inspected its initial public service/store boundary. The first actual
PostgreSQL/race none/ES256 registration -> signed assertion round-trip passes
(worker-reported 1.696s), including restart/original recovery and credential
withholding on replay. Expanded adverse/counter/contention/outbox checks pass
2.328s; a real committed-acknowledgement-loss check passes 1.593s. Latest expanded
native adversity passes 3.253s; actual Chrome/WPT registration/assertion through
PostgreSQL passes 2.251s; restart-strengthened lost-ack recovery passes 1.855s,
tagged vet exits 0. These are worker-reported local results, not independently
reviewed or public-native adoption. The first complete independent review found
that native recovery erased an ambiguous reconciliation commit's classification.
The worker is reproducing/fixing that defect and adding negative signature and
two-ceremony credential-CAS oracles within the same finite profile. Public-root/
native publication remains. No M15 closure.

**Newest delivered behavior:** an existing account can enroll and verify a phone
through the actual reference HTTPS backend: register/email-confirm/signin ->
fresh action proof -> captured encrypted SMS -> counted wrong-code denial ->
atomic phone verification -> code-free original recovery -> old-session denial
-> fresh signin/logout. Native bearer/cookie owners and optional cookie HTTP
compose without a substitute domain engine. See [adoption guide](../../reference/PHONE.md).
Independent final review approved `cc21422`, main-pushed with Required CI
39176981277 green. Selected PostgreSQL/race phone/baseline/username compatibility
passes 6.773s; ordinary reference race passes 8.597s, integration vet exits 0.
The actual downloaded reference module's genuine phone consumer passes 4.359s;
all 273 Go/manifests match committed source. Review's independent HTTP atomic-rate
migration omission and migration-guide defect are fixed. HTTP response-custody
serialization regression is separately delivered in `6bcebc2`, CI green.
**Still open in M08:** phone change/removal, signup/signin/password-reset profiles
and full phone-unit qualification. This accepted enrollment profile does not
close broad M08; whole-goal estimate and 6/39 count remain unchanged.

**Latest delivery:** M07 email OTP -> captured encrypted delivery -> one consuming
signin -> browser/persistent session read/logout, with original retry and
code-free lost-COMMIT recovery. Genuine enrolled, missing or changed MFA authority
denies without a weaker session or attempt charge. The demonstrated enrolled-TOTP
bypass is fixed in the native owner, not hidden by test policy. MFA `63cb08d`,
native OTP `8008afd` and reference `00ca1bb` are independently reviewed,
main-pushed and Required CI green. Canonical PostgreSQL/race 17.905s and actual
downloaded-reference consumer 18.347s pass. This closes the selected email signin
profile, not OTP-MFA continuation, phone/reset variants or whole-unit qualification.

**Previous delivery:** M06 magic-link signin/signup -> captured encrypted delivery ->
scanner-safe explicit consumption -> authenticated session read/logout. Existing
signin, new signup and signup-intent login of an existing account pass through
actual public owners. Lost-COMMIT acknowledgement recovery withholds credentials
and cannot duplicate accounts, sessions or token use. Independently reviewed,
main-pushed `647ac4b`, Required CI 39160360457 green; canonical PostgreSQL/race
19.056s and separate downloaded-reference consumer 18.108s pass. This closes the
selected browser single-factor/signup milestone, not enrolled-TOTP variants,
real provider delivery or whole-unit qualification. No production engine was
rewritten: this adoption connected existing behavior to reproducible consumer proof.

**Earlier delivery:** username/password -> genuine enrolled TOTP -> authenticated
session read/logout (`4315bbf` reference, `3b0fd6b` native password/HTTP).
Independent review is approved, both commits are main-pushed and Required CI
green. Canonical public-dependency PostgreSQL/race passes 48.976s; a separate
external consumer of the actual downloaded reference passes 31.145s. Browser,
persistent and standalone username-only selection, wrong browser/code/origin,
rollback, primary/completion recovery and authority withdrawal are covered.
Review caught and fixed a standalone session-reader/revoker omission before
delivery. M05's assigned required-email, Latin-v1 signup/signin/availability/
fresh-proof rename consumer profile is now closed, including selected TOTP signin.
Broader typed-catalog alternatives and whole-unit qualification remain pending.

**Parallel delivery:** recipient-owned invitation listing (`30e95ff` root /
`93df26f` PostgreSQL), independently reviewed, main-pushed and Required CI green.
Authenticated recipients can page through their own retained invitations without
organization membership; current verified identifiers and late session/policy
withdrawal control disclosure. Canonical public-root PostgreSQL/race passes
9.148s; the downloaded native module's genuine consumer passes 9.430s. This
closes the selected listing profile, not full M22 or package qualification.

**Also delivered:** opt-in OAuth discovery (`127c7db` root / `7292fbe` PostgreSQL),
independently reviewed and main-pushed, with final Required CI green. A genuine
metadata-driven independent client completes consent -> code/S256 -> exchange ->
refresh -> revocation through the actual public modules. Canonical native
PostgreSQL/race passes 8.881s; the downloaded adapter consumer passes 9.210s.
No shipped OAuth HTTP server, resource verifier, OIDC or full M30 claim follows.

**Earlier username delivery:** optional username reference composition (`db193b6`),
independently reviewed, main-pushed and Required CI green. Real PostgreSQL/race
proves the full HTTPS journey through signup, original email confirmation,
signin, fresh-proof rename, old-session denial, new-name signin and logout.
Native-only registration/confirmation/signin and availability with independent
counter schema also pass. The actual downloaded public module matches all 262
Go/manifests; its username checks pass. The later TOTP delivery above completes
the selected M05 consumer profile, not full package qualification.

**Other latest delivery:** organization invitation cancellation (`a3a9254` root /
`51a9b5e` PostgreSQL). Current owners/admins can terminally cancel an exact pending
invitation; its old proof cannot admit membership. Current authority remains
required for original receipt recovery, including prepared replay. Independently
reviewed, main-pushed and Required CI green; actual public-root PostgreSQL/race
checks and downloaded-native genuine cancellation consumer pass. This is partial
M22, not the complete organization family.

**Username transport is delivered:** signup/signin/availability/rename HTTP
(`91ea1f9`), public native HTTP consumer (`42d9222`) and shared email/username
original-registration confirmation routing (`ac96ffd`) are reviewed, main-pushed
and CI green. Actual public-module PostgreSQL/race proof covers original rename
recovery after session invalidation and both registration confirmation profiles.
**Historical position (21:37 UTC, superseded by delivery above):** M08 was being implemented, not merely connected:
there was no phone workflow to adopt. Number canonicalization and distinct SMS
purpose are main-pushed (`5abf389`, workspace correction `b4557a2`, CI green);
the actual downloaded phone consumer passes. Kernel pending-attachment/CAS and
signed action-primary phone custody are independently reviewed, main-pushed
`7323a83`, CI green. The worker completed that bounded password prerequisite
while the primary implemented kernel/OTP behavior. Retained encrypted SMS
generation/restoration and the populated forward purpose migration pass locally.
Kernel initial verification/CAS, pre-debit target admission and the actual
known-empty-MFA guard are reviewed, main-pushed `a651d1b`, CI green. Native OTP
now preserves original session custody and derives only the exact enrollment
successor; canonical race and selected real-PostgreSQL compatibility checks pass.
That native/core API batch is uncommitted. Independent review found actual
nested-diagnostic disclosure and pre-copy input-bound defects; fixes now pass
focused/ordinary/race checks and independent final review is approved. Final selected
PostgreSQL migration/old-session compatibility checks pass, not yet the selected
phone protected workflow.
The actual enrollment/confirmation service and selected HTTP/reference journey
remain disconnected. **M08 is not closed** and the
overall estimate remains ~15%, 6/39 consumer milestones. Full-unit qualification
is not inferred from these prerequisite results. Organization resend and OAuth
device successors still need their separate shared contracts.

**Other recent usable native outcomes:** username rename (`afe3f92`) and organization
self-leave (`f54f10a`) are independently reviewed, pushed to their owning main
branches and have green Required CI. Clean public-module PostgreSQL/race checks
pass for both. Rename enforces original action-bound proof, current MFA/CSRF,
thirty-day cooldown and identifier-session invalidation, including lost-COMMIT
recovery. Leave tombstones only the authenticated member, protects the final
owner and cannot revive old team bindings after readmission.

**Next acceptance boundary:** complete selected M08 phone/password signin:
verified phone → original canonical-number-bound pre-auth → normal password
verification/risk/current authority → authenticated session read/logout, with
browser/persistent remember preserved. This first profile requires native
known-empty MFA and denies enrolled factors; phone-origin TOTP remains later
M08 work, never a weaker fallback. Phone change/remove/signup, OTP signin/reset
and privacy also remain M08 obligations; enrollment does not close the row.
Recipient invitation listing, OAuth discovery and the username
reference outcome are closed as selected profiles.
Organization HTTP/dynamic roles and complete OAuth composition remain separate
work; those native profiles do not close their full milestones. No additional
whole-unit qualification is claimed.

| Measure | Current position |
| --- | --- |
| Complete consumer milestones | **11/39 closed**: B1 authentication, B2 reset, B3 password change, M05 selected username journey, M06 selected magic-link journey, M07 selected email OTP journey, M08 existing-account phone lifecycle/signin/reset, M09 anonymous lifecycle/cleanup, M10 confirmed TOTP enrollment/signin, M11 secondary-OTP enrollment/signin, M15 selected WebAuthn ceremony. The unweighted count is 28.2%; it is not the whole-goal effort estimate. |
| Remaining milestones | **28/39 not closed**: M04, M12–M14 and M16–M39. Existing implementation is not assumed absent. |
| Additional delivered behavior | **13 email-lifecycle profiles**, listed below. These are partial M04 deliveries, not thirteen additional closed milestones. |
| Full package scope | **67 units: 61 product units + 6 primitive extensions.** No additional full-unit qualification has closed during this implementation run. The older 2/67 verified baseline is historical, not a current cross-repository audit. |
| Last consumer milestone closure | **23 October:** M11 secondary-OTP enrollment, delivered confirmation and password/OTP signin with usable session/read/logout. Final Reference `f721a66`, independent review, exact green CI and downloaded public-module PostgreSQL/race37.995s proof. Broader profiles and whole-unit qualification remain open. |
| Last complete email-profile delivery | **18 October:** independently selected hooks for managed change links and email OTP verification/change, including first-primary and TOTP paths. Pushed reference `ca26306`, Required CI 39110688213 passes; all 30 selected public-native PostgreSQL/race cases pass. |
| Delivered organization profiles | **Native invitations, metadata, team lifecycle, ownership transfer, self-leave and current-subject organization listing.** Root `956176f` / native `804dbe8` adds bounded policy-filtered pages with original freshness and post-callback primary/scoped authority checks. Green CI; canonical PostgreSQL/race and downloaded-native genuine-session checks pass. This is partial M22/M23, not the complete organization family. |
| Delivered username profiles | **M05 consumer profile closed:** required-email registration/signin, advisory availability, protected rename and explicitly selected TOTP signin through `4315bbf`. Original retry/recovery, CSRF, session effects and independent/coexisting selections are proven through real PostgreSQL and public modules. Broader catalog profiles and package qualification remain open. |
| Current unfinished deliverables | M04 lifecycle/privacy contribution, retained factor-profile limits and final qualification remain open; confirmation-hook variants are delivered. Full M22/M30/M35, organization HTTP/reference selection and final package qualification remain open. Next lanes must consume proven contracts, not restart delivered profiles. |

### What consumers can already do

- Register, receive/confirm verification, sign in, read a session and log out.
- Explicitly select email OTP signin for a verified account with actual
  known-empty factor authority. Receive encrypted delivery, consume the code
  once, read the browser/persistent session and log out. Original retries and
  ambiguous outcomes cannot duplicate effects or redeliver credentials. See
  [the consumer guide](../../reference/EMAIL_OTP.md).
- Explicitly select magic-link signin or optional signup through public native/
  HTTP reference owners. Receive the committed encrypted delivery, consume only
  by an original-browser POST, read the resulting session and log out. Scanner
  GETs do not consume; supersession, replay and ambiguous commitment cannot
  create duplicate accounts/sessions or redeliver credentials. See
  [the consumer guide](../../reference/MAGICLINK.md).
- Reset or change a password, with old-password denial and session invalidation.
- Explicitly select required-email username registration using the existing
  native password service: reserve email and normalized username atomically,
  retain exact retry spelling and comparison profile, receive the actual
  verification email and confirm only that email. Neutral name collisions do
  not leave durable partial accounts, credentials or queued delivery. Native
  `1a83b18` also supplies username/password signin through the existing session
  owner, including browser/persistent remember, metadata-only restart/lost-commit
  recovery and atomic hash upgrade. Its prerequisites are reviewed/pushed with
  green CI; the canonical public-dependency PostgreSQL/race journey passes.
  A separate downloaded-API check proves public composition and forward-history
  compatibility, not another standalone PostgreSQL journey. Native `c640e0d`
  adds explicit advisory availability with durable tenant/network quotas,
  fail-closed canonical audit and actual canonical occupancy/cooldown checks.
  It is not a reservation; counter/audit/storage failures never report a free
  name. Native `afe3f92` also supplies fresh-proof self-rename: display edits
  preserve verification, canonical changes retire the old name for thirty days,
  and both invalidate identifier-bound sessions. Actual cookie/CSRF, current MFA,
  contention, rollback and lost-COMMIT recovery pass through the existing owners.
  Opt-in HTTP/reference composition is delivered. Separately selected username
  TOTP signin is also delivered through `4315bbf`; rename's known-empty-factor
  policy remains unchanged.
- Manage email through delivered profiles: (1) list/get/add/resend/link verification/
  primary change, (2) safe self-removal, (3) explicit replacement-primary removal,
  (4) audited administrative reads, (5) administrative removal, (6) pending-address
  OTP verification, (7) primary replacement by OTP, (8) first-primary establishment
  by OTP, (9) TOTP-protected email change, and (10) verification-to-signin when
  current authoritative MFA state is known empty, and (11) verification-to-signin
  through genuine enrolled TOTP with atomic session effects, including HTTPS
  browser/persistent, exhaustion, late-authority, recovery and populated upgrades.
- Explicitly configure ordered verification policy and success observation for
  signup and managed-address links. Before may reject before reservation;
  observer failure retains commit/recovery without confidential projection or
  following signin. Native and existing HTTPS paths, scanner/replay/recovery,
  rollback, unknown acknowledgement and final authority denial are covered.
  This is profile (12). Profile (13) adds independently configured managed-change
  link and email OTP verification/change callbacks, including first-primary and
  TOTP changes. Veto/error prevents durable wrong-code accounting; observer
  failure preserves commit/recovery and withholds the address through native
  and HTTPS paths. Lifecycle/privacy contribution remains undelivered.
- Use genuine authenticated sessions for native organization create/get/add/list/
  remove, with last-owner protection and scoped denial. Owners can send member
  invitations to existing verified recipients, deliver through the actual queue,
  and recipients can accept atomically into membership/scoped authority. Current
  policy denial, concurrent acceptance, rollback and fresh-session/new-service
  interrupted-send recovery are proven through the downloaded public module.
- Current owners/administrators can replace organization names/slugs with
  tenant-scoped uniqueness and expected versions. Native audit/lifecycle effects,
  concurrent-update exclusion, late-authority denial and authorized lost-commit
  recovery are proven, including genuine password-issued sessions. This is a
  native profile, not organization HTTP/reference composition or full M22.
- A current owner with a fresh action-bound password proof can transfer
  ownership to an existing active member. Roles and scoped authority change
  atomically, the former owner loses management rights, and the last owner
  remains protected. Current factor activation/generation changes deny through
  commit. Native `1773298` has green CI and a separate external downloaded-module
  genuine-session consumer; organization HTTP/full M22 remain unfinished.
- An authenticated member can leave only their explicitly selected organization
  through native `f54f10a`. The last recovery-capable owner cannot leave; scoped
  membership/team authority is withdrawn without revoking global sessions or
  independent organization-owned credentials. Readmission does not revive old
  team bindings. Current-membership recovery denies the departed member; bounded
  exact terminal retries retain historical metadata without removing a newer
  membership. Canonical and downloaded-native genuine-session checks pass.
- Current owners/administrators can create bounded native teams and add/list/
  remove actual organization members. Removed or readmitted members cannot
  revive old team bindings. Current session, organization policy and scoped
  authority are checked through commit and after recovery callbacks; a separate
  genuine session can recover the original outcome. Reviewed root `e28502d`
  and native `d5b058b` are pushed with green Required CI. Canonical affected
  PostgreSQL/race and a separate downloaded-native consumer pass. This is
  membership-only, not dynamic roles, HTTP/reference selection or full M23.
  Successor roote1ef03d/nativedc12ee7 also delivers native team read, versioned
  name update and terminal deletion without resurrecting old IDs/bindings.
  Both Required runs and a downloaded-native genuine-session lifecycle
  PostgreSQL/race consumer pass; full M23 remains open.
- Select bounded Turnstile, reCAPTCHA v3, hCaptcha Publisher/Pro or CaptchaFox Free
  provider-fact adapters. Durable risk/canonical-event/reference composition and live-provider
  qualification remain open.
- Compose native public or configured confidential-Basic authorization-code/S256
  flows from a genuine password session through independent consent, one-use
  exchange, refresh and
  revocation, with atomic audit/outbox effects and metadata-only recovery.
  Confidential Token/Revoke/Recover require actual current configured secret
  verification; adding a confidential client preserves installed public grants.
  Startup secret/version configuration is not hot or fleet-wide secret rotation.
  Explicitly selected confidential owning clients can also introspect their
  actual opaque access/refresh tokens through the native adapter. Current
  subject/grant authority, blocking and expiry are checked; unknown/foreign/
  inactive results disclose no metadata. Browser-only logout does not revoke
  an independent approved grant. Root `6e1d2a4` and native `66e0e47` are pushed
  with green Required CI; canonical PostgreSQL/race and separate downloaded
  consumer checks pass. This is read-only introspection, not a cached resource-
  authorization verifier, HTTP composition or completed M30/M32.
  A separately selected workload profile is now delivered: configured Basic
  clients issue bounded access-only machine grants, introspect and revoke
  without any human signup/session/consent. Root476cce3/docd2b0740 and native
  28444ed are pushed; Required39126209191/39126680619 succeeds. Canonical
  native public-root PostgreSQL/race81.978s and a separate actual downloaded-
  native consumer4.380s pass. Current directory/service-account authority and
  original lineage remain binding. Client management, OIDC, device, restricted
  exchange and complete reference/HTTP/provider qualification remain open.
- Read/list and withdraw a genuine session owner's OAuth consent through native
  `f15beb4` and root `86b5973`. Withdrawal invalidates previous code/access/refresh
  generations without affecting unrelated approvals; explicit reconfirmation
  cannot resurrect old grants. Populated migration, authority/CSRF/freshness,
  rollback/contention and metadata retry/recovery are covered. Native source is
  independently reviewed/pushed with green Required39133593943; public-root
  PostgreSQL/race57.936s and a separate downloaded-native consumer17.633s pass.
  Adoption requires an exclusive forward migration and retirement of every
  older/unselected accepting instance. HTTP, client administration, OIDC and
  complete M30/provider qualification remain open.

### What remains before the whole goal is done

- Finish M04 email lifecycle/privacy
  contribution, retained factor-profile limits and qualification;
  the selected enrolled-TOTP continuation profile is delivered.
- Close passwordless/phone/anonymous, complete MFA/recovery/trusted-device,
  WebAuthn/passkey and social-OAuth milestones.
- Close API-key, organization/team/role, administration/privacy, enterprise SSO/
  SAML/SCIM and OAuth/OIDC-server/exchange/device milestones.
- Complete broader risk/CAPTCHA, localization, advanced sessions, reference/consumer
  composition and all mandatory package, journey and shared-issuer qualification.

### Earlier implementation checkpoints (retained evidence)

- Frozen native username profile is delivered: kernel/MFA/sessioncore6fadb5e,
  native-sessione3b8aff and native-password1a83b18 are reviewed/pushed, Required
  CI39126898589/39127255016/39127504485 succeeds. Canonical public-dependency
  native ordinary race2.233s, complete username plus retained signin/MFA
  PostgreSQL/race21.094s and taggedvet0 pass. Separate downloaded public-API/
  normalization/forward-history compatibility passes race1.297s; it is not a
  separate complete PostgreSQL consumer journey. Availability, fresh-proof
  rename and HTTP/reference were subsequently delivered above. Disposable
  PostgreSQL has no leftover databases/roles and is stopped.
- Native team get/update/terminal deletion is delivered: roote1ef03d
  and nativedc12ee7, Required39124272324/39124935558 succeeds. Canonical actual
  public-root PostgreSQL/race41.963s and taggedvet0 pass. A separate consumer
  using the downloaded native archive passes the genuine password-session/team
  lifecycle journey with PostgreSQL/race16.460s. Full M23,
  dynamic roles and HTTP/reference remain open.
- OAuth workload policy ownership is corrected and independently approved.
  Root476cce3 is pushed; documentation-only successord2b0740 has green Required
  CI39126209191 after fixing two spelling failures. Canonical actual public-root
  native28444ed is pushed, Required39126680619 succeeds. Public-root workload
  plus retained human-flow PostgreSQL/race81.978s and taggedvet0 pass; separate
  downloaded-native machine issuance/introspection/revocation consumer passes
  PostgreSQL/race4.380s. Frozen native profile delivered; full M32 is open.
- Native owning-client introspection is closed: root `6e1d2a4` and native
  `66e0e47` are reviewed/pushed, Required39112523877/39113109840 succeeds.
  Canonical public-root PG18.6/race96.083s and taggedvet0 pass; a separate
  consumer using the downloaded native adapter passes real-PG/race18.784s.
  Source inputs match the reviewed commit, and owned PostgreSQL/caches are
  removed. Full M30/M32, resource-verifier/HTTP and final unit gates remain.
- M05 username is active: fixed normalization/validation policy7f53201 is
  independently reviewed/pushed with green Required39115559726; a separate
  actual downloaded-policy consumer passes race1.197s. Atomic email-plus-username
  reservation/normalization-storage and exact original-operation password
  custody prerequisites are now reviewed/pushed as31fca27/bb8a8b0, with green
  Required39116660625/39117167622. Canonical real-PG/race6.848s and native
  password race2.182s/taggedvet0 pass. A separate actual downloaded-policy/kernel
  consumer passes real-PG/race1.371s for populated upgrade/replay and bound reads,
  preserving old identifiers. These remain prerequisites of the delivered native
  username journey above. Availability, fresh-authorized rename and HTTP/reference
  were subsequently delivered; see the current TL;DR for milestone disposition.
- The finite native organization team profile is delivered as `e28502d`/
  `d5b058b`, Required39119579015/39120039161 succeeds. Public-root affected
  PostgreSQL/race48.870s/taggedvet0 and a separate downloaded-native genuine
  password-session consumer16.233s pass. Complete independent review's recovery
  withdrawal finding is resolved and its30 denial regressions pass. No full
  milestone or unit qualification is added. Its team-lifecycle successor and
  OAuth workload profile are also delivered above; the primary continues M05,
  not another repetition of registration or team membership.
- Remaining confirmation hooks are closed: email `8130ced`, native adapters
  `f9de2fd` and reference `ca26306` are independently reviewed and pushed.
  Required CI 39109239579/39110169561/39110688213 succeeds. Public-native,
  workspace-disabled reference race9.160s/runner6.788s, taggedvet0 and all30
  actual PG18/race cases85.717s pass; the original development run104.224s is
  separate evidence. Wrong-code placement counterfactual fails6.449s as expected.
  A separate module builds the actual published reference version and all three
  configuration paths without replacements; that proof is compilation, not
  another database boot. No further hook variants are being added to this slice.
- Organization metadata update is closed: root `6d66f39` and native `152a232`
  are independently reviewed/pushed, Required39109587423/39110371962 succeeds.
  Canonical public-root entire native PG18.6/race suite22.268s and taggedvet0
  pass. A separate module using actual downloaded native/root versions passes
  metadata and genuine password-session consumers under PG/race17.091s, including
  rollback, current policy, concurrency, risk and lost-COMMIT recovery. No new
  full milestone or full-unit qualification is claimed by either delivery.

- Verification-hook prerequisites root `9464527`, email `ad66e5e` and native
  `0ffbde0` are independently reviewed/pushed; Required CI passes for each.
  Reference now consumes those actual public versions with workspace disabled:
  ordinary race11.502s/CLI9.597s, taggedvet0 and all eleven real-PG/race hook
  cases93.043s pass. Native/public HTTP rejection, observer failure with known
  commit, scanner/replay/recovery, rollback, lost acknowledgement and late
  authority cases are exercised. Final six-path independent review approves
  candidate5f358674; reference `e53b0d7` is pushed with Required39107091680
  success. A separate clean consumer builds the actual published reference
  version and both hook configuration paths without workspace/replacements.
  That last proof is compilation, not another database boot. This finite
  profile is closed; full M04 and package qualification remain open.
- Configured confidential OAuth core `0fc6835` and native `47f61eb` are
  independently reviewed/pushed with green Required CI. Actual public-root
  native PG/race suite51.211s and taggedvet0 pass; original owning-module
  race180.348s and parser fuzz466839 executions remain attributed to their
  original run. The separate downloaded-native public consumer passes real
  PostgreSQL/race17.125s for confidential code/S256/refresh/revoke, installed
  public-grant compatibility and actual lost-COMMIT metadata-only recovery.
  An initial scratch compile omitted two maintained fixture helpers; copying
  them unchanged fixed the fixture, without repository edits. This finite
  profile is closed, not full M30 or new package qualification.

- Native invitations `6847272` are independently reviewed/pushed, Required
  39103645549 success. Actual public native/root/kernel consumer passes real-PG
  race15.292s without replacements; native entire retained PG race17.167s,
  ordinaryrace1.308s and taggedvet0 pass. Root policy `8d91c42` and kernel original
  correlation `538b443` are reviewed/public with green Required CI. Both concrete
  review findings have real failing regressions and corrected public-consumer
  proof. Full M22 and unit qualification remain open; do not restart this profile.

- Identity prerequisites `bb569ec` and `615ac00` are pushed to main with their
  exact-head Required CI passing.
- The capability prerequisite is now on **main** at `bf9ca8a`; exact-source
  Required CI passes. Reviewed native session adapter `bb37a49` is pushed and
  its public-only race/static and populated-history checks pass; Required CI
  passes. Password/postgres continuation `6128551` is also pushed with Required
  CI passing. Reference consumes both public pins in reviewed `02c6195`, now
  pushed with Required CI passing.
- HIBP now rejects and never caches provider results whose deadline expires
  during response cleanup: reviewed fix `75e10d9` is on main with Required CI
  passing. This does not close a further milestone or full-unit qualification.
- Organization membership profile is reviewed and pushed as `d781363`: real HTTPS
  signup/verification/password signin for two users drives native create/get/add/
  list/remove; nonmember Get and removed-member Get/List deny. Full affected
  public-only PostgreSQL/race suite passes9.893s and tagged vet passes; exact-head
  hosted CI39094622600 passes. Root invitation preparation/read prerequisite
  `d3aef10` is also public, Required39097597518 passes; native invitation
  storage/read `5d143b4` is public with actual PostgreSQL/public-pin race2.176s
  and Required39098233407 passing. Invitation send/accept, teams, domain
  authority and the whole M22 row remain open.
- OAuth core `a7762b9` and native adapter `92689f2` are independently reviewed and
  pushed. The selected public-client authorization/code/S256/refresh/revocation
  profile has actual public-core PostgreSQL/race consumer proof26.037s and tagged
  vet passing, including independent consent lifecycle, rollback and ambiguous
  commit recovery. Required39101419937 passes. The actual downloaded native
  module's four real-PG/race consumers pass24.150s and clean external construction
  passes1.232s without replacements. Full M30/provider qualification remains open.
- Neutral CAPTCHA1aacfcc/d05eba7, Turnstile d10a829 and reCAPTCHA21458ee are
  public/main with Required CI passing. Turnstile's actual public module consumer
  passes race1.254s; reCAPTCHA public consumer passes race1.292s. hCaptcha
  Publisher/Pro neutral48ab343 and childcb04798 are reviewed/public/main with
  Required CI passing; public-dependency child race3.286s/vet0 and docs0.237s
  pass. Its postpublication actual public child consumer passes race1.256s.
  CaptchaFox Free neutralb43abdf/child911f261 are also reviewed/public/main with
  Required39101323444 passing; public-only race3.700s/vet0/docs0.256s and actual
  published-child external callback consumer race1.242s pass.
  Canonical audit and durable/reference consumers are not delivered by those
  provider-fact modules; no M35 or whole-unit closure.

### Earlier diagnostic checkpoints (historical, not current status)
- Organization's exact active-target/version prerequisite `4035a0e` is pushed
  with Required CI passing. Its native worker now consumes the public API;
  actual PostgreSQL race proof now includes last-owner contention, scoped
  recovery, whole-transition rollback and a real lost-COMMIT response. The
  aborted-replay oracle was corrected against the upstream terminal-outcome
  contract, not by changing production behavior. Review/publication remain.
- OAuth consent continuation risk classification is reviewed and pushed in
  `26fb47a`; full risk race/vet and Required CI 39092382688 pass.
- The earlier populated MFA-first router rejection remains an unclassified
  observation; later selected checks and final review identify no outstanding
  mandatory gap for the delivered TOTP profile. No diagnosed-fix claim is made.
- All selected TOTP authority/contention/recovery/rollback/populated-upgrade
  cases pass on public dependencies under race (72.520s). Original-expiry failed
  once at setup with a deadline error; diagnostic repeats pass (18.436s), but
  its cause is not proven. Independent final reference review approves the
  finite slice, with these observations retained, not relabeled fixed. No
  production budgets changed. The selected profile is delivered, not full M04.
- Organization review found and reproduced a post-policy read expiry/cancellation
  gap. The corrected root passes all four regression cases and full race/vet;
  independent corrected-final-diff review approves it. Root `a875bb9` is public
  main with Required CI passing. Its real public pin now supports native standalone
  race/vet and PostgreSQL/race3.211s. Native quota denial classification is now
  corrected with genuine red/green and denial-audit proof. Final19-path review
  `/root/organization_postgres_final_review` APPROVE includes the real login
  consumer, current public pins and the unchanged corrected production code.
- **Next:** publish reviewed organization/CAPTCHA profiles with real public pins,
  finish OAuth native consumer proof and select the next remaining M04 outcome. Do not
  count another milestone or inflate the estimate for prerequisite commits.

Maintain this dashboard first at material checkpoints and at least every six
hours of active work. Use the [milestone table](#consumer-outcomes-39-unweighted)
for the full task breakdown; the history below is not the current status.

<details>
<summary>Detailed execution history — historical checkpoints, not current totals</summary>

Implementation activated by the user on 2026-10-14. B1, B2 and B3 are closed;
M04 email lifecycle is active.

- Verification/TOTP prerequisites (2026-10-18 01:31 UTC): foundation
  `bb569ec` is committed/pushed on identity main and passes public-dependency
  focused tests/static checks; its Required CI is pending. Independent review
  approves the lower contracts but rejects complete-slice readiness because
  an intermittent populated MFA-first router-construction failure reproduced.
  Later narrow diagnostics passed without establishing the cause. Adapter and
  reference delivery remain unfinished; full milestone count stays3/39.

- Verification/TOTP checkpoint (2026-10-18 01:21 UTC): both real populated
  upgrade histories now pass together, preserving existing sessions, issuance
  and migration records. Retained native/HTTPS magic-link and genuine password
  MFA journeys also pass. Reference race/static checks finish successfully.
  The implemented slice remains local/uncommitted pending independent review,
  public dependency pins, clean-consumer/runtime proof and main delivery; no new
  full milestone or unit closes. Earlier intermittent constructor/setup errors
  have not reproduced in the focused reruns, but their causes are not proven.

- Verification/TOTP checkpoint (2026-10-18 00:53 UTC): real expiry, late
  authority denial, concurrent completion and interrupted-preparation recovery
  now pass locally. The combined regression exposed a wrong test expectation
  for exhaustion, not a new product defect: the corrected check proves terminal
  revocation, no remaining attempts, no child use and no additional session.
  Three retained Valkey-profile tests did not run because their disposable
  service inputs were absent; those remain unverified. Full populated reference
  upgrade, remaining affected checks, independent final review/public pins and
  main delivery remain. The slice is uncommitted; no new milestone closes.

- Verification/TOTP working locally (2026-10-18 00:31 UTC): original signup
  browser -> committed email verification -> pending TOTP -> genuine enrolled
  factor -> session read/logout now passes both native APIs and selected HTTPS,
  preserving browser/persistent choice. Wrong browser/unselected HTTP variants
  deny; wrong code spends one shared attempt; replay and actual lost challenge/
  session commit acknowledgements disclose no replacement credentials. A real
  post-snapshot parent-custody defect was reproduced and corrected with protected
  current checks. Source remains uncommitted; remaining failure/migration/
  compatibility checks, independent review and main delivery are not complete.
  No new full milestone/unit closes:3/39 delivered. Whole-goal estimate remains
  rough5–10%, low confidence, based on delivered baseline/reset/password-change
  and partial email lifecycle, not code or test counts.

- Registration verification-to-signin source delivered (2026-10-16
  13:04 UTC): foundation `af740fb`, native/HTTP `ad15f57` and reference
  `88c8106` are pushed to main; all three exact-head Required checks pass.
  Original-browser link confirmation can immediately establish a separately
  committed email-possession session, retaining the original remember choice,
  then reach authenticated read/logout through native and selected HTTPS.
  Verification-only defaults are unchanged. Failed/unknown signin cannot erase
  committed verification or disclose replacement credentials; current MFA and
  original expiry are fenced. Independent source/coverage/public-pin reviews,
  public-only PostgreSQL/race/HTTPS acceptance and an empty public-consumer
  runner initialization pass; test execution was primary-observed.
  This closes the selected known-empty-MFA profile, not full M04: enrolled
  continuation, other email/privacy variants and final qualification remain.
  Full milestones stay3/39; no newly qualified unit. Whole-goal estimate stays
  rough5–10%, low confidence, based on baseline/reset/password-change and partial
  email lifecycle rather than a measured effort fraction.

- Registration verification-to-signin implemented locally (2026-10-16
  12:44 UTC): original-browser link confirmation now reaches a separately
  committed email-possession session, authenticated read and logout, retaining
  the original browser/persistent choice through native and selected HTTPS.
  Sixteen selected scenarios plus retained baseline/shared-email journeys pass
  PostgreSQL/race; failure, replay and changed-MFA paths disclose no credentials
  and preserve independently committed verification. Independent coverage and
  contract findings are resolved. Complete source review, authenticated public
  module pins, public-only runtime and main delivery remain; not yet delivered.
  Whole-goal estimate remains rough5–10%, low confidence;3/39 milestones and
  no newly qualified unit. Most capability families and final qualification
  are still outstanding.

- TOTP-protected email-change profile delivered (2026-10-16 11:30 UTC):
  `a462729`, `a2bc669`, `0d3608f` and reference `c3744e2` are on public main;
  all exact-head Required checks pass. Real password/TOTP or recovery signin,
  fresh email-action proof, independent link delivery/confirmation, primary
  replacement, old-address notice and old-session denial work through native
  and explicitly selected HTTPS APIs. Public-dependency PostgreSQL/race/HTTPS
  regression and published empty-consumer initialization pass; independent
  source/pin and delivery reviews accept this bounded profile. Full M04 remains
  open for other factor/auto-signin/privacy/lifecycle requirements and final
  qualification. Full milestones remain3/39; no newly qualified unit. Overall
  estimate remains rough5–10%, low confidence, based on the delivered baseline,
  reset/password-change and partial email lifecycle, not a measured effort share.

- TOTP email-change correction (2026-10-16 10:59 UTC): real MFA-origin signin
  now reaches request, independent link delivery/confirmation, old-address
  notice and session denial. Review had exposed an SFA-only derivation that
  the prior enrollment-session tests missed. Both password/TOTP and recovery
  signin are now covered, including selected HTTPS; combined MFA route boot is
  also repaired. Final affected PG18/race regression passes147.313s and native
  module race/vet checks pass. Independent final review, public dependency pins
  and main delivery remain. No newly delivered milestone: still3/39, rough
  whole-goal5–10% estimate with low confidence, not a measured effort fraction.

- TOTP-protected email-change local checkpoint (2026-10-16 10:36 UTC): genuine
  confirmed TOTP now supports original-session-bound request, independently
  delivered link, primary replacement, old-address notice and required session
  denial through native and explicitly selected HTTPS APIs. PostgreSQL/race
  acceptance passes, including rollback, contention, actual stale authority,
  original expiry and lost-commit recovery; affected owner race/static,
  bounded fuzz and changed-source secret checks pass. Source compatibility and
  implemented-coverage audits approve their bounded source scope; complete
  correctness review, public module pins/consumer proof and main delivery remain.
  This is local/uncommitted, not delivered: full milestones remain3/39,
  full M04 and all remaining platform families/qualification stay open.

- First-primary OTP profile closed (2026-10-16 08:57 UTC): foundation
  `099b837`, native `80e379c`, reference `ed8135f` are pushed to main and
  exact-head Required CI passes. A normal verified/password-signed-in account
  with no primary can explicitly establish one using genuine fresh-password
  change provenance and an independently delivered new-address OTP. Native and
  separately selected HTTPS paths preserve the old mailbox/history, notify it
  after confirmation, invalidate old sessions and retain metadata-only recovery.
  Default configurations still deny this transition. Public-dependency real
  PostgreSQL/HTTPS/race acceptance, affected owner checks and published-runner
  initialization pass; complete source/pin review and delivery audit approve.
  Tests are parent-executed, not auditor-rerun. This closes a usable profile,
  not full M04 or unit qualification. Full milestones remain3/39; no new
  qualified unit. Overall estimate is still rough5–10%, low confidence:
  complete baseline/reset/password-change plus partial email lifecycle are
  delivered; most platform capability families and final qualification remain.
  No Tools changes, historical migration, release, deployment or production claim.

- Primary-email OTP profile closed (2026-10-16 07:44 UTC): foundation
  `33c559f`, native/HTTP `7cda935`, reference `43b46d1`; all exact-head Required
  checks pass. Consumers can use genuine fresh-password change provenance,
  independently deliver a new-address OTP, atomically replace the primary,
  notify its original old mailbox and invalidate old sessions through native
  APIs or explicitly selected HTTPS. Original revoked/expired authority cannot
  be renewed by newer signin; recovery remains metadata-only. Public-dependency
  PostgreSQL/HTTPS/race and published empty-consumer initialization pass.
  Independent source and delivery audits approve. Full M04, stronger-factor/initial-primary/
  auto-signin/privacy variants and unit qualification remain; full milestones
  still3/39, no new qualified unit. Overall estimate remains rough5–10%, low
  confidence, based on delivered baseline plus partial email lifecycle rather
  than files/tests or an equally weighted milestone percentage.

- Initiating-session security fix (2026-10-16 07:04 UTC): real regressions first
  reproduced new issuance and an extra code debit after original-family
  revocation despite a newer valid signin. The corrected native guard now
  blocks both, conserves original expiry, and preserves metadata-only recovery.
  Happy path, selected HTTPS and unknown-commit checks pass15.257s. This is
  implementation progress, not a delivered slice: final affected regression,
  re-review, public pins and main delivery remain. Full milestones3/39, no new
  fully qualified unit; overall rough5–10%, low confidence.

- Primary-change review checkpoint (2026-10-16 06:28 UTC): supported intervening
  candidate/previous-primary changes now prove wrong and correct stale OTPs deny
  without debit or additional protected effects; actual OTP recipient is observed
  at delivery. Both HTTPS paths and a corrected valid link/OTP race pass24.332s.
  Earlier race evidence had an invalid link competitor and is superseded, not
  retained as proof. Public lower-module checks pass; updated reference regression,
  final review, public native/reference pins and main delivery remain. No new full
  milestone/unit closure; still3/39 and rough5–10% whole-goal estimate.

- Primary-email OTP replacement now also works through documented direct HTTPS
  and explicitly selected reference HTTPS (2026-10-16 06:14 UTC). Real native
  expiry/exhaustion and generic-pending-origin denial pass without renewing
  authority or changing primary/session/notice on denial. Existing canonical
  operation contracts are preserved; distinct recovery has typed native input.
  This slice remains local/uncommitted pending final regression/review, public
  dependencies and main delivery. Full milestones remain3/39, no new fully
  qualified unit; rough whole-goal estimate5–10%, low confidence.

- Primary-email OTP replacement now works locally through native reference
  composition (2026-10-16 05:26 UTC). A real verified/password-signed-in user
  performs a keyed fresh-password change request, independently receives the
  new-address code, confirms one primary replacement, receives one notice at
  the original old address and observes old-session denial. Code-free recovery
  does not compare/debit again, disclose an address or renew authority. Eight
  real PostgreSQL/race scenarios cover genuine success, missing/enrolled/changed
  MFA, late rollback, lost actual commit acknowledgement, OTP/OTP and link/OTP
  contention; both contention scenarios also pass three repeated runs. Foreign,
  noncommitted and wrong-possession sources deny without issuing OTP state.
  Retained pending-email OTP journeys pass with the common native orchestration.
  Domain configuration is frozen into issuance custody; changed comparison/key
  configuration cannot restore old preparation. Focused owner race/static and
  redaction tests pass. These are development-workspace results, not clean public
  dependency qualification. All changes remain local/uncommitted; opt-in HTTP,
  remaining expiry/attempt/origin partitions, independent reviews, public pins
  and main delivery remain. Full milestones3/39, no newly qualified unit; rough
  overall5–10%, low confidence. No Tools work or historical-evidence repair.

- Pending-email OTP profile closed (2026-10-16 03:43 UTC): source `cf3f5a4`,
  native/HTTP `92f2dae` and reference `612ab05` are pushed to main; corrected
  adapter/reference Required CI passes. Consumers can independently deliver and
  submit a purpose-bound code for an existing pending nonprimary address via
  native APIs or selected reference HTTPS. Verification, protected audit/lifecycle
  and code consumption are atomic; old sessions deny. Original Send/recovery
  retain metadata without retargeting, extra comparisons, address disclosure or
  renewed authority. No login/session issuance or weaker-MFA fallback.

  Thirteen OTP scenarios and affected password/link/retained-signin-reset
  journeys pass against real PostgreSQL/HTTPS/race with public dependencies,
  GOWORK off (70.044s). Affected owner/reference/runner race/static, bounded fuzz,
  scoped secrets, docs/structure and complete independent source review pass.
  The published runner initializes from an empty consumer directory without a
  database/listener. A public inventory checksum false positive in the first
  Required run was corrected by accurately naming private provenance; no scanner
  weakening or history repair. Inherited full-history qualification still fails.
  Full M04 remains open for stronger-factor, auto-signin, privacy/lifecycle and
  final unit qualification. Full milestones3/39, no new qualified unit; rough
  overall5–10%, low confidence, not a measured fraction. No Tools work or release.

- Administrative-removal profile closed (2026-10-16 00:43 UTC): foundation
  `9785b1c`, native password/HTTP `9ee4c44` and reference `ffc3b47` are pushed
  to main with exact-head Required CI green. Consumers can explicitly authorize
  real actor A to remove B's versioned email via native/opt-in HTTPS, using A's
  original fresh password proof/session while preserving A's authority. B's
  old sessions/removed signin deny and remaining configured signin/reset works.
  Exact grant withdrawal denies unfinished/recovered preparation; terminal
  historical replay remains available. Eight real public-dependency PostgreSQL/
  HTTPS/race journeys, affected race/vet, bounded fuzz, secrets and structure
  pass; complete independent review approves the published source graph. The
  published runner initializes with no local overrides or database/listener.
  Full M04 stays open: stronger-factor, OTP/auto-signin, privacy/lifecycle
  completeness and unit qualification remain. Full milestones remain3/39;
  overall estimate5–10%, low confidence, not a measured fraction of effort.

- Administrative removal local checkpoint (2026-10-16 00:28 UTC): genuine
  administrator/target PostgreSQL/HTTPS journeys pass under race, including
  native/HTTP removal, rollback, contention, unknown commit and lost preparation
  acknowledgement. Target sessions/removed signin deny, remaining signin/reset
  works, and actor authority/session/proof ownership remain independent. Exact
  grant withdrawal denies both original and restored unfinished preparation;
  committed/known-rollback historical replay remains unchanged. First independent
  review identified that permission gap; both real regressions were reproduced
  and corrected outside database locks. Complete corrected review, public pins
  and main delivery remain pending. Nothing from this profile is pushed yet;
  full M04 stays open, delivered full milestones remain 3/39, no unit qualification.

- Administrative-read profile closed (2026-10-15 15:27 UTC): native `6f013f9`
  and HTTP `15b4764` are on main with Required CI green. Reference `91397a7`
  is on origin/main with Required `38760195512` green; its public published
  runner initialization succeeds without a database/listener. Consumers
  can explicitly authorize real actor A to list/get B's email addresses through
  native/opt-in HTTPS with mandatory PostgreSQL access audit; failed/unknown
  acknowledgements withhold data. Default self routes stay closed to overrides.
  Six public-dependency SQL/HTTPS/race journeys pass13.355s, affected public
  race/vet and bounded query fuzz pass, and complete independent source review
  approves the final public dependency graph. Primary versions, commands and
  one-use usage remain unchanged by reads. Full M04 remains open: administrative
  removal/stronger-factor, OTP/auto-signin, privacy/lifecycle completeness and
  full-unit qualification remain. Still3/39 full milestones; no Tools changes,
  tags or deployment. Runtime checks are local; hosted CI proves structure and
  changed-content secrets, not whole-platform runtime qualification.

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

</details>

## Consumer outcomes (39, unweighted)

The rows below record actual milestone closure, not helpers or release counts.
An unassessed row is not a claim that its existing code is missing. Do not
restart old slices merely to fill this table; adopt applicable prior proof.

| ID | Consumer outcome / owning units | Current disposition |
| --- | --- | --- |
| B1 | Runnable registration/verification/signin/session/logout baseline: identity, identity/postgres, identity/password, identity/password/postgres, identity/session, identity/session/postgres, identity/delivery, identity/delivery/postgres, identity/http, identity/reference; required primitive contracts | Closed: reviewed native PostgreSQL/HTTPS journey, reproducible consumer walkthrough, main 90d4f2c and Required CI 38527264686. Public-dependency journeys and published runner initialization subsequently pass at 1ae0790; full-unit qualification pending. |
| B2 | Reset and required session invalidation using the baseline owners plus identity/risk/hibp | Closed: reviewed native PostgreSQL/HTTPS reset, two-session revocation, original audit recovery and populated upgrade; main fd439aa and Required CI 38547848026; full-unit/release qualification pending |
| B3 | Password change and fresh reauthentication through baseline owners | Closed: reviewed PostgreSQL/HTTPS verification/change, two-session revocation, populated upgrade, original auditing, rollback/recovery and combined reset/change; main 24b1b08 plus CI-only 47a3ee0, Required CI 38559659144; full-unit/release qualification pending |
| M04 | Email add/change/verify/list/get/remove with session/lifecycle policy: identity/email | Thirteen delivered profiles, including enrolled verification→TOTP→session/read/logout and independently selected verification/change hooks (latest reference `ca26306`, green Required CI). Lifecycle/privacy contribution, retained factor-profile limits and final qualification remain open. Full row not closed. |
| M05 | Username availability/signin/rename: identity/username, stable identifier contracts | Closed selected consumer profile: required-email Latin-v1 signup/verification/signin, metered advisory availability, fresh-proof rename/session invalidation and opt-in TOTP signin. Reference `4315bbf`, independent final review, green Required CI, canonical public-dependency PostgreSQL/race 48.976s and downloaded-reference consumer 31.145s. Broader typed-catalog variants and whole-unit/release qualification remain pending. |
| M06 | Delivered magic-link signin and session: identity/magiclink | Closed: selected browser-SFA signin/optional-signup public-reference journey `647ac4b`; independent review, green CI and downloaded-module PostgreSQL consumer. Full-unit qualification remains open. |
| M07 | Purpose-bound email OTP request/delivery/completion: identity/otp, identity/otp/postgres | Closed selected email-signin profile: genuine registration/verification, original browser, encrypted delivery, counted consumption, session read/logout and code-free unknown recovery. Native `8008afd` and reference `00ca1bb`, independent reviews, green Required CI and actual downloaded-reference PostgreSQL consumer. OTP-MFA/phone/reset variants and full-unit qualification remain separate. |
| M08 | Verified phone enrollment/change, OTP/password signin and reset: identity/phone, OTP/password owners | Enrollment/verification, distinct phone/password signin, SMS-code signin, fresh-authenticated self-removal and verified-phone replacement are delivered through actual public-reference PostgreSQL/HTTPS consumers, independent review and green CI; latest replacement reference `10eb07f`. Signup, phone password reset, remaining assigned variants and full qualification remain open. One intermittent router-startup failure remains unproved, not a claimed fix. |
| M09 | Anonymous session, self-deletion and collision-safe permanent upgrade: identity/anonymous, identity/anonymous/postgres | Closed selected native/opt-in HTTP/reference profile, including abandoned cleanup with stored policy/holds, upgrade fences, atomic owner effects and original recovery. Native `d2f004f`, reference `64cee17`, independent reviews, exact green CI and downloaded-public Reference five-journey PostgreSQL/race16.170s. Unsupported transfer/authentication profiles and full unit/release qualification remain separate; historical startup uncertainty remains disclosed. |
| M10 | Confirmed TOTP enrollment and TOTP signin: identity/mfa, identity/mfa/postgres | Closed selected cookie/password-primary TOTP profile, including username-primary composition: genuine registration, fresh proof, pending enrollment, reveal-once URI, explicit confirmation, challenge-only primary, TOTP completion and usable session/read/logout. Reviewed/pushed reference `4315bbf` and `02c6195`, green CI and original canonical/downloaded consumers retained. Fresh source audit at `d65ed4c` found the closure row stale; current downloaded combined phone/username/TOTP consumer also passes (13.824s). Broader MFA profiles and unit/release qualification remain separate. |
| M11 | Confirmed secondary-OTP enrollment, delivered-code signin and session: MFA/OTP/password/session owners | Closed selected email/password-primary profile: genuine pending enrollment, delivered explicit confirmation without a session, challenge-only primary, counted delivered-code completion, session read/logout and original recovery. Reviewed MFA `665a40f`, session `c4d031c` and Reference `f721a66` are main-pushed/exact-CI green; actual downloaded public Reference PostgreSQL/race37.995s. Enrollment without login and retained TOTP controls pass separately. Broader MFA variants and full-unit qualification remain open. |
| M12 | Factor listing/update/removal/disable/replacement with fresh proof: MFA owners | Safe native/HTTP mixed OTP/TOTP inventory and TOTP management profiles delivered. Native action-bound OTP rename (`5235852`), sole-active removal with email recovery (`e4ae9ab`) and explicit one/all disable (`e20c606`) are independently approved, main-pushed and exact-CI green. Actual downloaded-public PostgreSQL/race consumers pass (131.047s / 72.209s / 127.790s). OTP replacement and remaining method/composition profiles keep the full row open. |
| M13 | Recovery-code reveal/use/regeneration and independently approved administrative recovery: MFA owners | Closure not reassessed |
| M14 | Trusted-device issuance/use/revocation and step-up: MFA/session owners | Closure not reassessed |
| M15 | WebAuthn register/assert ceremony and durable credential validation: webauthn, webauthn/postgres | Closed selected identified-user none/ES256 profile: reviewed/pushed `75a475e`, canonical public-root PG/race, real commit-loss recovery and actual Chrome/WPT consumer; account-suspension negative proof PG/race 1.659s, tagged vet, actual public native byte equivalence and exact green Required CI. Independent native review and delivery audit retained. Other protocol profiles, M16 and full unit/release qualification remain pending. |
| M16 | Passkey-first registration, discoverable signin and credential management: passkey, passkey/postgres | Existing-account enrollment, identified/identifier-free signin, safe inventory, label rename and session read/logout are delivered through native/Reference/HTTP. Keyed retries retain original metadata. Signed-proof deletion is also delivered: native `e175ffe`, HTTP `5bb695c`, Reference `85c7651`, independent reviews and exact Required CI green. A clean public Reference consumer passes native/HTTP fresh/populated and management-off deletion, affected-session denial, metadata retry and retained password-session read/logout under PostgreSQL/race (42.348s). Signup, conditional signin and remaining qualification keep the full row open. |
| M17 | Social OAuth authorization-code/S256 callback to session: identity/oauth, identity/oauth/postgres, identity/oauth/providers | Closure not reassessed |
| M18 | Social account linking/unlinking and stored provider-token refresh: OAuth owners | Closure not reassessed |
| M19 | Verified One Tap to identity/session: identity/oauth/onetap | Closure not reassessed |
| M20 | Bounded OAuth proxy callback to the intended application: identity/oauth/proxy | Closure not reassessed |
| M21 | User/organization API-key issue/import/verify/rotate/revoke: identity/apikey, identity/apikey/postgres, identity/apikey/valkey | Closure not reassessed |
| M22 | Organization create/manage/join/invite/remove and authority lifecycle: organization, organization/postgres | Native creation/membership/invitations/metadata/ownership transfer/self-leave delivered through `f54f10a`, with independent review, green CI and canonical/downloaded-native genuine-session PostgreSQL/race proof. Organization HTTP/reference, active selection and remaining lifecycle/role requirements are not closed. |
| M23 | Teams and dynamic roles/permissions enforcement: organization, authorization contracts | Native team creation/membership/read/update/terminal deletion delivered through `dc12ee7`, with green CI and downloaded-native genuine-session PostgreSQL/race proof. Dynamic roles/permissions and HTTP/reference remain; full row not closed. |
| M24 | Bans/session administration and bounded audited impersonation: identity, session, identity/impersonation, identity/impersonation/postgres | Closure not reassessed |
| M25 | Verified domain/provider registration and federation policy: sso, sso/domain-verification, sso/postgres | Closure not reassessed |
| M26 | Enterprise OIDC/OAuth federation, mapping/JIT/linking and session: sso/oidc, sso/oauth2 | Closure not reassessed |
| M27 | SAML federation including replay/lifecycle policy: sso/saml | Closure not reassessed |
| M28 | Authorized SCIM discovery/User CRUD/filter/PATCH/pagination: scim, scim/postgres | Closure not reassessed |
| M29 | SCIM Groups, organization reconciliation and deprovisioning effects: scim/organization and organization owners | Closure not reassessed |
| M30 | OAuth client/consent, authorization-code/S256 grants and refresh rotation: oauth-server, oauth-server/postgres | Selected native configured public/confidential code/S256, consent, refresh, revocation and owning-client introspection delivered. Dynamic client/consent management and complete HTTP/reference remain; full row not closed. |
| M31 | OIDC discovery/JWKS/ID-token/userinfo consumers: oauth-server/oidc | Closure not reassessed |
| M32 | Workload client-credentials issuance, introspection and revocation: OAuth server owners | Configured access-only native machine profile delivered as `28444ed`, green CI and downloaded-native PostgreSQL/race consumer. Full row qualification/composition not closed. |
| M33 | Restricted token exchange with lineage/non-expanding authority and bounded cache validity: OAuth server, authentication, API-key and organization owners; SI-01 through SI-10 | Native Basic workload-only opaque exchange is delivered through OAuth `9969c9d` / native `5c597f4`, independently approved and final exact-CI green. Downloaded-public PostgreSQL/race consumer passes five journeys (44.086s), including reusable sources, original pending recovery and withdrawal after preflight. Human/API-key/organization sources, HTTP/reference and cached shared-issuer profiles keep the full row open. |
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
