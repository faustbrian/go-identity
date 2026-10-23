# Changelog

## Unreleased

- Revoke password/OTP sessions using their actual confirmed OTP factor and
  verified recipient, rather than the TOTP factor table. Existing TOTP and
  recovery-code revocation remains unchanged; use the matching MFA adapter.

- Add source-free expired-guest session/family disposal after actual same-Work
  kernel disposal, including already-pruned or fully revoked sets. Append
  `AnonymousExpiryMigrationSource` after the selected anonymous history;
  browser delete/upgrade still require their original source custody.
- Add exact-source OIDC logout as an effect in the existing OAuth transaction,
  reusing single-session revocation and retained original-record evidence.
  Append `OIDCEndSessionMigrationSource` after single-session history. The
  separate RP-logout disposition survives payload pruning without changing
  ordinary browser-signout grant policy; protocol/hint/transport composition
  remains required and unsupported authentication profiles deny.

- Add the closed anonymous-upgrade session effect: revoke the complete guest
  session/family set and issue exactly one new permanent-target session in the
  same protected Work. Preserve target authentication age, original authority,
  guest remember policy and earliest deadline; reject family collisions. Append
  `AnonymousUpgradeMigrationSource` after selected anonymous histories. Actual
  guest/target authentication, target reauthentication and one-use consumption
  remain mandatory native workflow responsibilities, not authority from fields.

- Add explicit anonymous-source mapping and same-Work disposal of the complete
  anonymous session/family set after actual kernel disposal. Retained effect
  evidence supports metadata-only recovery without restoring revoked access.
  Install `AnonymousDisposalMigrationSource` before selecting the native workflow;
  verified-user source admission and unrelated session methods stay unchanged.

- Add explicit anonymous-only session mapping and same-Work persistence/final
  checks against actual kernel creation, directory and guest policy authority.
  No credential reference or verified proof is fabricated. Append the forward
  anonymous issuance-purpose suffix after the explicitly selected installed
  history; base issuance needs no unrelated login method. Anonymous lifecycle,
  risk, public workflow and current-session reader remain separately required.

- Explicitly select session issuance after verified-phone/password and confirmed
  TOTP in one protected transaction. Require the original phone browser purpose
  and current verified-phone recipient; existing email completion stays separate.

- Select the existing all-session revocation and retained-effect owner for the
  exact joint phone-password-reset command. No session can be preserved and
  recovery retains the original operation. Install the forward session-owned
  `PhonePasswordResetMigrationSource` after password-reset effect history;
  existing email-reset rows and installed migration bytes remain unchanged.
  The complete workflow must still establish every factor and atomic effect.

- Bind sessionless phone-recovery pre-auth use to its exact native completion
  while preserving the original request action, identifier commitment, policy,
  cookie and expiry. Request issuance and other profiles cannot consume it;
  no installed storage or migration bytes change.

- Preserve explicit no-session phone-recovery pre-auth purpose in durable
  records, native issuance and original recovery without a remember choice.
  Existing login payloads and installed migration bytes remain unchanged.

- Decode the closed phone OTP signin session projection without accepting
  email authentication metadata. Add the forward `PhoneOTPSigninMigrationSource`
  after the explicitly selected password/signup/magic-link/MFA/verification
  purpose history and any selected username or phone/password suffixes. Existing
  rows and selected methods remain unchanged; no HTTP route is enabled.

- Restore the original session projection from closed phone/password signin
  commands and retain its password-specific issuance commitment for recovery.
  Install the forward phone/password purpose suffix against the exact selected
  predecessor history; username signin is optional and old rows stay unchanged.

- Preserve optional original identifier commitments in pre-auth record storage
  and command custody, including restart/retry conflict checks. Legacy unbound
  bytes remain unchanged; old binaries fail closed on bound records rather than
  discarding the commitment. No new table, journal or renewal path is introduced.

- Retain the exact consumed username-signin browser origin during MFA
  completion and denial accounting. Match its original committed command,
  fingerprint, generation, cookie and exclusive expiry without consuming or
  renewing the primary again. Existing password and email origins are unchanged.

- Restore the existing session projection from exact username-signin paired
  password commands without rewriting their original scope. Native workflow
  admission and forward issuance-purpose storage remain separately required.

- Add a forward MFA issuance-purpose extension for populated verification-first
  history without replaying or changing older purpose migrations.

- Fence already-consumed signup browser custody during selected verification-
  origin TOTP completion without reactivating or consuming signup again.

- Persist selected post-verification email-possession sessions with immutable
  confirmation-parent lineage and at most one child per tenant/confirmation.
  Install the forward `EmailVerificationSigninMigrationSource` after the
  selected email-grant/MFA issuance history before enabling the new effect;
  legacy rows, SQL paths and applied migration checksums are unchanged.

- Add explicit original password/MFA admission expectations without weakening
  the single-factor profile. Native consumers must retain and fence the source
  session's original factor enrollment and authority, separately from any fresh
  action proof, and preserve the original session/family and validity.

- Compose supported envelope v2 custody and matching public native participants.
  Callers supplying envelope/keyring services must use `/v2` types; stored
  ciphertext, original authority lifetimes and transaction ownership stay intact.

- Compose current public kernel, risk and MFA participants with matching
  authentication v2 and authorization v3 values; session authority remains native.

- Align owned capability dependencies with the v2 issuer-scoped contracts.

- Add closed password/secondary-OTP session mapping and a same-Work completion
  effect requiring actual checked OTP/child custody and recorded shared MFA
  transition. Original credential, remember and optional synchronizer remain
  bound; recovery uses a distinct OTP issuance digest. Full public completion,
  selected storage migration and live OTP session validation remain in development.

- Extend native consumed-primary reading to explicitly selected secondary-OTP
  sending as well as completion. Keep the original browser read-only and
  require the exact anonymous MFA operation and factor target.

- Add read-only original consumed-primary fencing for native secondary OTP.
  Require exact MFA operation/browser lineage and unchanged absolute expiry;
  never reactivate, reserve, release or finalize the primary again. This guard
  grants no successful factor authentication or session by itself.

- Add native original-session/CSRF custody for pending TOTP replacement URI and
  confirmation. Continuations obtain real current authority without extending
  original proof/ceremony limits or copying expired evidence. Confirmation
  revokes all bounded subject sessions in the protected MFA transaction, with
  retained outcome evidence and optional forward-only disposition v4.

- Add exact native disable session custody and all-subject disposition ownership,
  retaining original cookie/CSRF/deadlines and primary authority. Append optional
  disposition v3 after v2; older regeneration/update purposes and receipts remain
  unchanged. Deliberate source revocation never renews or replaces a session.

- Admit native factor removal in the existing protected whole-subject session
  disposition. Revocation and retained outcome evidence commit with MFA's
  proof/factor/recovery effects; no source session is refreshed or revived.

- Extend the existing native MFA primary/disposition owner to exact
  factor-update Work, retaining original cookie/CSRF/session custody and
  atomic whole-subject revocation. Install the optional forward-only
  factor-update disposition v2 suffix after v1; regeneration-only selection
  stays unchanged. Successful rename deliberately revokes its source session.

- Add session-owned atomic whole-subject revocation for native recovery-set
  replacement, including command-bound retained disposition evidence and the
  original source's intentional revocation. The bounded 1024-session profile
  fails closed on excess; it never preserves or silently upgrades the source.
  Apply `MFARecoverySessionMigrationSource` for selected regeneration graphs.

- Provide native password/password-MFA primary custody for authenticated TOTP
  step-up, with actual session-cookie reads and unchanged synchronizer checking.
  Retain original scalar session/deadline snapshots inside MFA-owned encrypted
  preparation and repeat current owner checks in preparation and final commit.
  No caller-written session reader or authentication fallback is accepted.

- Add exact native authenticated MFA-action session admission for password,
  password/TOTP and password/recovery sessions. Retain credential, factor,
  session and family fences, command-frozen observation expiry, submitted bearer
  possession and unchanged CSRF custody. This does not yet expose a usable
  step-up or recovery-code regeneration workflow.

- Admit complete recovery-code provenance through selected MFA session readers
  and revocation mapping, retaining original credential/factor authority and
  single-factor isolation. New cache profiles reject prior profile custody
  rather than promoting or renewing evidence. Extend original consumed-browser
  fencing to exact native recovery completion and its distinct denial callback.

- Add forward recovery-code record profiles for password and magic-link MFA,
  preserving populated historical records and rejecting malformed set epochs.
  Add native recovery completion effects requiring the same Work's recorded
  code burn, original primary/remember/factor/set custody and current authority;
  retained recovery issuance evidence stays distinct from TOTP evidence.

- Map and restore complete recovery-code session provenance, including original
  primary, factor enrollment and recovery set epoch. Recovery-use and TOTP
  completion mappings remain disjoint; partial or cross-method records deny.
  Durable recovery-session constraint installation and issuance remain separate.

- Extend explicit selected session reads and revocation admission to genuine
  password/TOTP records, retaining both credential and factor fences without
  single-factor fallback. MFA-only and combined readers have separate cache
  custody; current read deadlines are not renewed by profile dispatch.

- Add explicit password-primary TOTP session persistence with original credential,
  primary time and current authority fences. The consumed-browser guard admits
  only committed password or magic-link signin origins; it never consumes or
  renews the original flow. Public password-to-TOTP orchestration remains unfinished.

- Fence explicitly selected known-empty password factor intent before browser
  consumption, retaining the native factor-before-browser lock order shared by
  MFA challenge creation. Unselected legacy password commands remain unchanged.

- Add explicit native password/TOTP session reads with current credential and
  confirmed-factor admission and separate cache custody. Install the additive
  `PasswordMFAMigrationSource` after the existing MFA history for schemas11/12;
  historical records and single-factor readers retain their existing behavior.
  This reader does not enable the unfinished password-MFA login workflow.

- Preserve password-primary TOTP provenance in complete native command mappings
  and durable session records. Keep historical schemas unchanged, distinguish
  the new profile explicitly, and reject missing or mixed factor metadata rather
  than restore a weaker session. Mapping does not authenticate the password or
  factor; native protected completion still owns those checks.

- Add opt-in MFA-aware self-revocation with the same current factor fence for
  caller and target. Retain an oversized self-target record once with an explicit
  source reference instead of weakening the 128-field command input bound;
  legacy source/target encodings remain unchanged.

- Add an opt-in combined primary session reader for selected single-factor and
  magic-link/TOTP profiles. Dispatch MFA provenance before single-factor methods,
  keep exact common owner profiles and distinct cache custody, and preserve
  legacy single-factor selection. Combined logout/reference wiring is pending.

- Exercise native MFA denial with real protected risk counters, proving atomic
  wrong-attempt charging and rollback for correct-code probing, invalid browser
  admission and failed denial audit. Public MFA composition remains unfinished.

- Fence TOTP completion and counted denial against the original already-consumed
  browser flow and exact committed primary command custody. Invalid browser
  possession cannot charge the factor budget; retrying a recorded wrong code
  cannot charge twice. Completion never consumes or renews that browser flow.

- Add an explicitly selected native magic-link/TOTP session reader. Require
  the exact confirmed enrollment and current MFA-owned factor generation along
  with every existing authority dimension; single-factor factories stay
  disjoint. Preserve the original at-most-20-second evidence deadline through
  cache reuse and deny expired evidence when bounded refresh is unavailable.

- Adopt the native outbox's paired magic-link signup lifecycle contract so
  account creation and authentication events can share the protected transaction.
  Install the complete selected capability adapter history, including original
  issuance and supersession extensions, before selecting native MFA composition.

- Add the native original-primary TOTP completion session effect and retained
  recovery domain. Require the recorded factor/continuation handle, original
  scope, exact MFA-owned factor authority and current verified recipient/policy
  before session writes. No primary/browser credential is consumed again.
  Public MFA completion and positive protected-path integration remain pending.

- Bind complete prospective TOTP-completed magic-link sessions into the native
  completion command. Preserve distinct primary and completion identities,
  factor/child provenance, remember policy, authority and synchronizer state;
  incomplete or foreign mappings deny rather than enter primary-only issuance.

- Add forward-only complete MFA record and retained issuance-purpose constraint
  extensions. Preserve populated legacy records and recovery bytes, reject
  missing/substituted factor state and remember-policy changes, and retain only
  closed factor-completion purposes. Upgrade readers before selecting the new
  record schemas; native MFA issuance and reference composition remain pending.

- Retain explicit magic-link/TOTP completion provenance in record schemas9/10
  and closed original-session command fields. Reject lossy factor metadata,
  malformed scope digests and mismatched primary/factor policy during decoding.
  Database schema admission and the native MFA session effect remain pending;
  these codecs alone do not enable durable MFA issuance.

- Extend explicitly selected transactional self-signout to OTP and magic-link
  sessions. Preserve their original possession provenance and identifier/security
  versions through command mapping; revoke, audit and lifecycle effects remain
  atomic. Cookie signout retains exact synchronizer validation. Nil selection
  remains verified-only; reference composition is still being connected.

- Add an explicitly selected single-factor primary reader that performs one
  digest lookup and dispatches on the stored password, OTP or magic-link kind.
  All selected deployment, policy and audience profiles must agree; unselected
  methods deny without fallback. Cache custody binds the method set and complete
  native profiles. Method-aware transactional self-signout remains in development.

- Add native magic-link session mapping and same-transaction issuance after
  capability consumption. Preserve the original email grant, anonymous command,
  remember policy and CSRF; consume pre-auth with the session/family and retain
  method-specific recovery evidence after payload cleanup. Current account and
  address authority and original exclusive expiry remain required. Install
  MagicLinkSigninMigrationSource after password-signup issuance history.
  Proof, cookie, callback and factor/risk validation remain magic-link-owned;
  this native adapter does not expose a public passwordless login endpoint.

- Bind native session cache admission to the selected method, schema and
  authority configuration. Shared wrapping keys cannot transfer warm positives
  across profiles. Earlier unbound entries refresh from primary; persisted
  session records and their lifetimes are unchanged.

- Preserve magic-link grant provenance in new session record schemas 7/8 and
  add an explicit primary reader that checks the original verified address and
  current account authority. Install MagicLinkMigrationSource after credential
  continuation history and upgrade readers before selecting these records.
  Existing storage bytes/checksums remain unchanged; atomic magic-link login
  and reference composition remain workflow-owned and in development.

- Add reset-specific transactional all-session revocation with no source-session
  preservation. Bound the complete active-state set, retain original effect
  evidence including empty sets, and roll back with credential/audit/lifecycle
  failure. Install the forward reset-effect migration after kernel reset history.
  Public password-reset orchestration remains in development.

- Add signup-specific session mapping and same-transaction issuance effects.
  Correlate the newly staged account, pending identifier and password reference
  with the original registration command; preserve anonymous scope, complete
  session/remember/CSRF and consume original pre-auth atomically. Keep signin's
  verified-identifier admission unchanged. Install the additive signup issuance
  migration after password-signin history. Historical signup identity remains
  inspectable after payload cleanup without credential recovery or access.
  Native password policy, material, HIBP and possession remain owner obligations.

- Add original-signin hash-upgrade session admission: lock directory authority
  before the kernel's exclusive predecessor reservation, then issue only from
  that Work's exact applied successor. Preserve independent security epochs,
  original observation/proof/lifetime, remember/CSRF and anonymous scope.
  Native password comparison, replacement material CAS and signed proof remain
  the password owner's responsibility. Both upgrade and direct Apply reject
  substituted command custody and poison prior provisional writes. Existing
  original-command behavior and Recover are unchanged. Requires the additive
  kernel hash-upgrade and exact-command contracts.

- Add bounded primary inspection of retained password-signin user/session/family
  identity. Validate the original command and password-specific commitment even
  after live session deletion, without reconstructing credentials or granting
  disclosure permission. Existing OTP identity inspection remains unchanged.

- Add native password-signin session effects that consume original pre-auth
  state atomically with session, family and retained issuance evidence. Preserve
  anonymous command scope while fencing the selected credential and authority.
  Install the forward password-signin migration after OTP issuance history;
  existing issuance records remain unchanged. Password verification, cookie
  possession and proof/risk orchestration remain the native password owner's
  responsibility; this storage seam is not a complete login service.

- Add closed password-signin session mapping for original paired custody.
  Preserve the selected user separately from anonymous command scope, complete
  authentication/authority/remember/CSRF state and exact times. Unsupported or
  malformed records deny without creating authority. Atomic signin issuance and
  its consuming password service remain under development.

- Add native bounded password-change session effects in the original consuming
  transaction, with exact current-owner admission, selected continuation or
  revocation and retained command-linked recovery after payload cleanup. Install
  the additive password-session migration after continuation and kernel
  replacement histories. Mixed unsupported preservation profiles deny rather
  than drop authority checks. Public password-service integration remains pending.

- Add explicit bounded password-change session-disposition mapping. Freeze the
  complete original session and preserve/revoke-other/revoke-all choice into
  the original command without renewing authentication or unrelated authority.
  Mapping is structural only; same-transaction execution remains in development.

- Preserve password credential continuation through durable reconstruction,
  native command mappings, rotation and revoking other sessions. Current
  admission uses the effective credential version without rewriting original
  authentication or advancing unrelated authority. Install the additive
  credential-continuation migration after OTP history and upgrade relevant
  readers/writers before selecting the new stored profile.
  Fresh credential-proof issuance rejects continuation rather than allowing
  historical proof linkage to substitute for the current credential version.

- Add closed original-session admission mapping for native cross-module
  workflows. Preserve credential or OTP authentication, complete authority,
  remember and CSRF state without copying the session codec into other owners.
  Malformed or incomplete fields deny; mapping grants no authentication.

- Add bounded primary inspection of the retained OTP sign-in user/session/family
  identity, including after live session payload deletion. Validate the original
  command and record commitment without reconstructing a session or credential;
  historical inspection remains separate from disclosure authorization.

- Add the native consuming OTP session effect within the original coordinator
  transaction, preserving verified recipient, authority, remember and CSRF state
  and denying stale owners or expired authentication. Retained recovery binds
  actual user/session/family and record identity after live-payload cleanup.
  Install `OTPIssueMigrationSource` after existing issuance/OTP record history;
  old proof-based evidence remains unchanged. Public OTP sign-in and recovery
  composition remain under development.

- Add closed scalar OTP sign-in session mapping, preserving anonymous command
  scope separately from the selected user and retaining exact authentication,
  remember policy, authority and optional CSRF state before reservation.
  Existing proof-based mappings remain unchanged. Mapping is structural only;
  consuming session effects and public sign-in remain under development.

- Add an explicit owned OTP session reader using the exact verified identifier
  and current primary authority without requiring a persistent credential.
  Preserve original authentication and bounded evidence deadlines; historical
  OTP expiry does not expire an issued live session. Existing proof-only
  composition stays unchanged. Apply the OTP record migration before selecting
  this profile; native consuming signin and restart recovery remain pending.

- Preserve original OTP authentication provenance in durable session schemas
  3/4, including optional synchronizer state, without changing historical
  schemas 1/2 or renewing authentication time. Apply `OTPMigrationSource` after
  the CSRF migration and upgrade readers/writers before OTP writes. Native OTP
  authentication and atomic sign-in composition remain under development.

- Add an explicit owned cookie-logout executor with named-key selection and
  CSRF checks inside the original primary mutation transaction. Keep raw tokens
  ephemeral, retain a strict-profile command discriminator, and reject legacy
  dispatch rather than downgrade protection. Existing direct execution remains
  compatible for requests without CSRF custody. Apply the existing CSRF migration
  before selecting this profile; HTTP/browser enforcement remains pending.

- Add borrowed-transaction synchronizer-token admission against the exact
  primary session and active family, retaining invalidation fences through
  protected work. Callers must abort on denial and preserve other authority
  and terminal-time checks. Native workflow and HTTP wiring remain pending.

- Preserve session synchronizer CSRF state in stored records, native command
  projections and rotation recovery. Keep tokenless historical bytes unchanged.
  Add a forward-only CSRF record migration; apply it and upgrade relevant
  readers/writers before enabling the new profile. Old binaries fail closed on
  CSRF-bearing records. HTTP token/origin enforcement remains in development.

- Add identifier-admission profile validation and original-session authority
  derivation for native participants. Preserve exact owner expectations without
  IO, refreshing epochs, authenticating a bearer or granting permission.

- Compose the public owned pre-auth issuer with native atomic initiation and
  restart-safe outcome recovery. Persist the unchanged server-generated cookie
  commitment and remember choice; only fresh commitment permits core delivery.
  Use the core canonical operation descriptor without changing stored command
  shapes or migration history. Native OTP continuation remains under development.

- Add pre-auth issuance results distinguishing sole-reservation execution from
  replay, pending observation and conflict. Concurrent identical commands grant
  fresh-execution eligibility to only the committing owner; historical receipts
  never permit cookie delivery. Existing receipt-only calls remain compatible.

- Add owned pre-auth initiation execution and restart-safe receipt recovery
  with exact service policy, original flow, audit and lifecycle in the sole
  kernel transaction. Preserve original metadata on replay and deny retired
  flow-ID resurrection under new commands. Install forward
  `PreAuthIssueMigrationSource` after the kernel/pre-auth histories; retained
  issuance evidence survives live-payload retirement. Flow generation, cookie
  delivery and OTP continuation composition remain under development.

- Freeze complete original pre-auth initiation state in a closed native command
  vocabulary, with separate anonymous-flow target and service actor. Reject
  substituted scope, incomplete fields, narrowed versions and noncanonical
  timelines without changing remember policy or cookie commitment. Public
  issuance and command-recovery composition remain under development.

- Add terminal pre-auth release through the exact owner's sealed coordinator
  noncommit callback, including expired reservations. Preserve original flow
  intent and cookie while fencing rollback/recovery generations and terminal
  replay. Install forward `PreAuthReleaseMigrationSource` after the initial
  pre-auth migration during a bounded constraint-update window; existing rows
  and applied migration checksums are unchanged.

- Add structural primary pre-auth loading, exact reserved-owner admission and
  predecessor-only generation transfer. Preserve the original cookie, intent,
  remember policy and expiry across takeover; stale owners and terminal flows
  cannot transfer or finalize. Transfer requires live coordinator authority,
  not elapsed time or a caller-supplied generation.

- Add canonical pre-auth primary storage and exact locked admission, one-winner
  reservation and same-transaction consumption. Preserve original intent,
  remember policy, nanosecond expiry and named cookie digest; fence exact
  command/fingerprint/generation and deny terminal replay without renewing or
  automatically releasing state. Install additive `PreAuthMigrationSource`
  after the base session schema. Public initiation/recovery and native workflow
  registration remain under development.

- Add native self-session device-label CAS with unchanged bearer, activity,
  authentication, remember choice and unrelated authority. Commit metadata,
  version, audit/lifecycle and receipt atomically; retain exact replay and
  bounded outcome-only restart recovery. Install `UpdateMigrationSource` for
  both update and list paths. The additive tables preserve older session row
  writes/codec; current labels cascade with payload deletion and historical
  evidence stores label digests rather than duplicating plaintext. Browser
  transport and complete privacy/release verification remain pending.

- Add bounded, owner-scoped database-time expiry cleanup with current service
  authorization, locked refresh-safe selection, terminal digest retirement and
  same-commit audit/lifecycle effects. Preserve natural-expiry authority versions
  and retained command/rotation/revocation evidence. Exact retries and restart
  recovery return historical deletion count/lag rather than selecting another
  batch. Install `CleanupMigrationSource` after the base/rotation history; its
  transactional owner/expiry index installation requires a bounded write window.
  Scheduling and general privacy erasure remain separate platform work.

- Add explicit protective retired-token replay checking with current trusted
  service policy and primary lineage-derived ownership. Commit one exact family
  revocation with protected audit/lifecycle effects, preserve exact retry
  receipts, and recover historical outcomes after restart without a bearer.
  Active, absent, foreign and expired tokens reserve no command. Ordinary
  session reads remain read-only; transports must explicitly enable the guard
  and enforce origin/CSRF policy. Reuse the existing rotation/family migrations.

- Add restart-safe rotation receipt recovery using the original safe command
  scope and current access policy. Preserve historical version/audit metadata
  without original authentication admission or live session payloads; never
  return a session or credential, renew live leases or reserve missing commands.

- Add owned source-bound session rotation with atomic digest retirement,
  successor persistence and audit/lifecycle effects. Preserve absolute lifetime,
  original authentication and every non-session authority. Reveal credentials
  only through the core rotator after a new successful commit; replay/recovery
  never redeliver them. Install `RotationMigrationSource` after existing history;
  its populated-row backfill and digest guards cover old/direct session writers.
  Retained exact-intent evidence supports historical recovery without live
  session payloads. Retired-token family-replay revocation and other remaining
  session profiles still require implementation before full lifecycle completion.

- Compose public credential-based bulk session revocation through the owned
  primary reader, native command executor and core service. Original admission
  bounds final commit; retained counts/disposition replay without new mutations.
  Restart recovery uses current result-access policy, survives payload pruning
  and rejects corrupt native metadata without erasing a known command outcome.
  Install the bulk migration before use; no application domain stores or final
  signin-proof issuer are required. Full session lifecycle remains unfinished.

- Add bounded transactional revoke-other/revoke-all effects to the configured
  native contributor. Select the complete tenant/user set across audiences,
  reject over-limit sets without partial changes, and retain counts and source
  disposition with command recovery evidence. Preserve surviving source bearer,
  lifetime and authentication while advancing its session version; never bump
  user-wide authority. Install `RevokeSetMigrationSource` after the base history.
  Owned bulk execution/public factory composition remains under development.

- Add owned authenticated session listing with an indexed, bounded primary
  tenant/user/audience keyset query and safe active/inactive device projections.
  Apply `ListMigrationSource` after the base session install at a permanent
  history slot; it adds an index without rewriting session records or earlier
  migrations. Construction needs no application store or command journal.
  Device labels, remaining session profiles and complete lifecycle remain pending.

- Compose public idempotent self-logout through `NewSignOutService` with the
  owned primary reader and native transactional executor. One execution profile
  selects schema, authority, clock and policy; no application stores or fresh
  login are required. Clear only the selected transport after committed or
  already-inactive success; operational failure never becomes cookie deletion.
  Historical recovery remains on the native executor. Full session lifecycle
  and release verification remain unfinished.

- Add owned single-session execution using original opaque caller admission,
  current policy and same-transaction source/target owner checks. Freeze both
  records and original validity in command intent, order session locks to avoid
  cross-revocation deadlocks, and bound commit by primary-observed remaining
  admission time even with application-clock skew or slow audit/outbox work.
  Replays and scoped restart recovery retain historical outcomes without a new
  transition. Revocation does not require final-signin proof composition;
  public idempotent signout and absent/expired target handling remain pending.

- Add exact single-session revocation through the existing coordinator with
  complete original-record mapping, locked directory/credential/policy/session
  admission, target-only CAS and retained terminal successor evidence. Sibling
  records, family authority and original snapshots remain unchanged. Install
  `RevokeOneMigrationSource` alongside the selected issuance history before
  using this configured native operation. Caller authentication and public
  idempotent logout orchestration remain unfinished.
- Permit later independently issued sessions in an existing active family
  while retaining its original creation timestamp. A session cannot predate
  its family; corrupt or future family timestamps still fail closed.

- Add owned single-factor stateful session validation using the committed core
  service and native primary directory, user, identifier, exact credential,
  authorization and session/family owners. Deny ambiguous retained-key lookup,
  revoked or stale authority and unsupported dimensions without cache fallback.
  Preserve original read-start freshness and exclusive credential/session
  expiry. Construction borrows the primary pool and requires existing migrations;
  remaining profiles, rotation and complete login remain under development.

- Add restart-safe issuance reconciliation from exact historical scope and
  trusted current caller, without retaining original authentication proof or
  bearer custody. Return only command metadata under current policy; preserve
  live leases and reconcile expired intent through the existing kernel owner.
  Missing or conflicting participant evidence cannot prove rollback or success.

- Add owned authenticated cookie-issuance execution and original-request
  recovery using the kernel command owner and production audit/outbox adapters.
  Bind current self-service access and atomically persist the original session,
  proof use and mandatory effects; core token custody reveals only after a new
  committed result. Historical replay/recovery never reveals a credential.
  Consume the committed core issuer and exact-input recovery contracts.
  Process-restart recovery, browser-container policy, rotation and complete
  login/session authentication remain unfinished.

- Add explicitly configured authenticated session issuance through the existing
  protected coordinator. Preserve the complete original record, remember policy,
  proof/credential linkage and authority vector; compare native current owners
  before effects and terminalization. Session, family, proof use and issuance
  evidence roll back together. New forward-only issuance migrations preserve
  installed history. Existing constructors remain opted out; complete bearer
  delivery, container policy, rotation and composed login remain pending.

- Add opt-in native privacy session eligibility on the original coordinator
  transaction. Checks retain original user/credential/identifier authority,
  exact owner keys, session/family locks and primary expiry without renewing
  proof metadata. Unsupported optional owners deny. Adopt the committed kernel
  invocation contract; complete privacy admission and export remain pending.

- Add explicit native identifier admission using the original coordinator
  transaction and existing kernel/authorization owners. Exact session scope,
  credential linkage and owner-derived keys are checked without rewriting
  metadata or renewing freshness; only the proven identifier successor changes
  the final comparison. Unsupported organization, factor and passkey profiles
  deny. Existing repository construction stays opted out; complete protected
  workflow activation remains pending.

- Publish framed session/family authority keys and consume the committed kernel
  admission contracts. Historical custom snapshot keys require an explicit
  migration or replacement session; they are not silently upgraded.

- Add bounded borrowed-primary `RequireSession` admission: exact immutable
  record, active session/family versions, share locks and database-time expiry.
  It supplies only session-owned checks, not full authority or authentication.

- Add native transactional family revocation through the sole identity
  coordinator, with exact owner/tenant/version checks, retained command evidence
  and mandatory audit/lifecycle declarations. Original session snapshots are
  never rewritten. Apply the additional permanently allocated
  RevocationMigrationSource migration before enabling this contributor; the
  original MigrationSource API and install remain unchanged. Issuance remains
  unsupported.

- Add forward-only complete session/family storage with digest-only unique
  lookup, tenant-bound relationships and retained revocation state. Bounded
  structural primary reads preserve all authority dimensions, original precise
  timestamps and resolved remember-policy limits. Reads do not authorize use;
  shared-coordinator issuance, rotation and recovery remain in development.
