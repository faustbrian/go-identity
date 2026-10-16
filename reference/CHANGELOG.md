# Changelog

## Unreleased

- Independently compose native pending-email OTP verification and opt-in HTTP
  routes with selected migrations, delivery, strict rate storage and current
  session/factor authority. OTP signin is no longer an incidental password/session
  bootstrap prerequisite; installed shared consuming history remains stable.
  Conflicting OTP-signin Send HTTP selection fails instead of choosing a profile.

- Compose explicit native administrative email removal and independently opt-in
  HTTP targets. Keep actor proof/session separate from target mutation, audit,
  revocation and recovery; self-only composition remains the default.

- Compose optional administrative email list/get with the existing PostgreSQL
  audit owner. Select `Email.Addresses.AdministrativeAudit` and independently
  opt into HTTP `AdministrativeTargets`; missing audit composition denies startup.
  Audit failure withholds data, without changing self reads or issuing sessions.

- Preserve explicit versioned replacement-primary removal through native and
  opt-in HTTPS composition, including rollback, contention and original recovery.

- Independently compose native safe email removal and opt-in HTTPS/OpenAPI.
  Borrow actual selected password signin/reset/proof owners, install native
  forward cascade history and retain graph shutdown/deadline custody. Native
  selection alone exposes no route; removal never silently selects a new primary.
  Independently selected keyed email HTTP installs its atomic-rate history;
  shutdown rejection preserves the operation's closed response shape.

- Run the baseline against pinned public modules with `GOWORK=off`, without
  sibling supplier archives or historical source replacements. Existing runner
  arguments remain accepted; the collection argument no longer selects code.

- Compose supported envelope v2 custody and matching public native participants.
  Callers supplying envelope/keyring services must use `/v2` types; stored
  ciphertext, original authority lifetimes and transaction ownership stay intact.

- Compose public current-major primitives and workflow adapters, including
  HTTP-client v2 for the isolated HIBP transport. Configuration and consumers
  must use matching opaque credential/proof/identifier types.

- Adopt identifier v2 input and normalization types through public source
  dependencies. Callers sharing these typed values must use `go-identifier/v2`;
  stored profile/version bindings and selected workflow behavior are unchanged.

- Adopt capability v2 public proof/grant types and explicit trusted issuer
  policy. Update capability imports and issuer-owned keys/configuration; token
  framing and native transaction/recovery ownership remain unchanged.

- Independently select keyed email add/resend and primary-change request HTTPS,
  plus change confirmation, over the native reference graph. Original signed
  password proof, cookie and CSRF custody survive exact retries without renewing
  authority. Share existing strict rate owners and graph shutdown/drain; disabled
  operations expose neither handlers nor OpenAPI metadata.

- Select keyed email management independently with `EmailManagementConfiguration.Keyed`.
  Graph-lifetime-bound calls preserve original request correlation, current
  transactional admission, cooldown and change/session/notification effects.
  Unselected or wrong-profile keyed calls deny without unkeyed fallback.

- Independently opt into native email address get/list HTTPS routes, retaining
  original session validity, current self authorization and native value/version
  disclosure. Reuse existing safe-route rate ownership or explicitly select its
  standalone profile without enabling HTTP session routes. Omitted routes remain
  absent from dispatch and OpenAPI; reads never issue or refresh credentials.

- Opt into shared signup/managed-address HTTPS confirmation with
  `HTTPRegistrationVerificationConfiguration.ManagedAddresses`. Require matching
  native issuer/replay custody, authenticate the original signed profile and
  retain one canonical route with no failed-source fallback or auto-login.

- Explicitly select native email add/resend/verification, primary-address change
  with old-address notice and session effects, and authorized address list/get.
  Reference composition supplies real proof, risk, delivery and primary owners;
  retained handles preserve initialization, tenant and shutdown admission.
  Selected native migrations extend installed histories without rewriting their
  prefixes. This selects no management HTTP routes, removal or automatic login.

- Opt into fresh password verification and keyed password change in the
  runnable PostgreSQL backend, with required HIBP/audit delivery and atomic
  revoke-all session effects. New signing/intent keys and migration requests
  are additive; original baseline/reset custody is preserved.
  Keep the bounded tenant-resolution context local to admission rather than
  truncating the configured router/workflow deadline after successful resolution.
  The combined reset/change walkthrough continues with the successfully reset
  credential and checks the next credential version.

- Add explicitly selected emailed-capability password reset to the runnable
  PostgreSQL backend: captured delivery, repeatable non-consuming inspection,
  explicit completion, required all-session revocation and replacement-password
  signin. HIBP screening and security auditing remain fail closed.
  Baseline-to-reset migration retains separate original operator requests;
  default B1 routes and private credential custody remain unchanged.
  Retain original HIBP audit records before primary append; uncertain delivery
  denies screening and survives restart for explicit native idempotent recovery
  with `reconcile-audits --password-reset` in the private local-only host.

- Explicitly select PostgreSQL-only admission without changing the existing
  Valkey recovery lane. Native bootstrap and password registration/verification/
  signin/session/logout work on a fresh primary without fabricated history.
- Add an explicitly local-only HTTPS baseline command with separate init,
  operator migration, serving and consumer-exercise operations; private stable
  keys, default Argon2id, required HIBP and captured mail remain on the path.
  The development runner uses committed supplier sources, not public-release
  installation. See BASELINE.md for the selected profile and remaining scope.

- Exercise native email secondary-OTP enrollment/confirmation through actual
  encrypted delivery and selected HTTP login with public session admission,
  credential-free replay and factor-authority invalidation. This supersedes
  selected workflow caveats below, not full reference/MFA release qualification.

- Independently select password-origin OTP sending HTTP through
  `HTTPMFAConfiguration.PasswordOTPSend` with the native read-only source and
  shared delivery quotas. Send-only selection requires no verification limiter
  and exposes no verification or enrollment operation.
- Place cross-owner password/OTP acceptance tests in reference composition,
  avoiding a reverse password-adapter dependency on its downstream consumer.

- Select password-origin secondary OTP verification transport independently.
  Native quota metadata preserves the original signed subject/child/lifetime,
  authenticates exact retained attempts before mutable factor reads and rejects
  historical input conflicts without new comparisons or consumption. Selected
  graph handles retain startup/tenant/shutdown admission. Complete selected
  enrollment-to-HTTP-login acceptance remains in development.

- Explicitly select native password-origin secondary OTP through
  `PasswordSigninConfiguration.OTP` and `FeatureSet.PasswordOTP`. Composition
  supplies the existing primary, child, session, OTP and delivery owners and
  validates shared browser-key bindings. Startup registers the native OTP
  issuer before admission; independent forward suffixes preserve optional
  TOTP/recovery/management migration allocations. This selects no HTTP route.

- Add concrete native password/secondary-OTP login sending with original signed
  child/browser custody, confirmed-factor and recipient fences, shared protected
  counters and encrypted durable delivery. Exact retry/recovery cannot generate
  another code or renew the original child. Enrollment and login share OTP's
  existing account/destination resend limits. Sending grants no session; OTP
  completion and graph/HTTP selection are still being connected.

- Compose explicitly selected pending TOTP replacement through the native
  factor-update, URI and confirmation owners, with actual session custody and
  whole-subject revocation. Append optional MFA v12/session-disposition v4 only
  when selected; preserve prior migration prefixes. Opt-in HTTP derives its
  recovery-code count from native policy. Original factor/codes stay usable
  until confirmation; confirmed successor TOTP and recovery codes support login.
  This supersedes the selected TOTP replacement caveats below, not general MFA.

- Native and HTTP one-target disable preserve and report untargeted pending
  factors; all-target disable still erases and retires their custody.

- Compose independent native disable and opt-in HTTPMFADisable with real session,
  proof, risk and complete email-reset recovery owners. Selected MFA v11 and
  session-disposition v3 migrations preserve populated prefixes. One/all native
  and HTTP consumers need no private authority-version queries. This supersedes
  the selected sole-TOTP/email-recovery disable caveat below, not general MFA.

- Compose sole-TOTP removal with the actual native emailed-reset request and
  completion owner. Explicit email recovery selection requires its HIBP and
  delivery dependencies; the graph supplies the recovery checker and optional
  forward-only MFA v10 history. Independently select removal HTTP actions and
  reset routes. Native and HTTP workflows recover password login after removal.
  This supersedes the removal caveat below, not unsupported replacement or disable.

- Independently select native TOTP label management and
  `HTTPMFAFactorUpdate` with actual session, original proof and shared limiter
  owners. Selected migrations include only the required forward-only MFA and
  session disposition suffixes. HTTP step-up can explicitly issue the selected
  management purpose without selecting regeneration routes. Unsupported native
  remove/replace actions deny rather than falling back to rename.

- Add independently selected `HTTPMFAList`, sharing the exact HTTP-session safe
  limiter or using an explicit standalone policy without selecting session
  routes. Real metadata/count journeys preserve no-store, credential-free
  responses and selected graph lifetime. Unconfigured selected listing now
  fails rather than silently disappearing in a recovery-only graph.

- Independently select native safe MFA metadata with
  `MFAEnrollmentConfiguration.Listing` and `MFAListing`. Reuse the existing real
  session and authorization owners; list confirmed TOTP metadata and remaining
  recovery counts without granting factor authority or disclosing credentials.
  This selection exposes no HTTP route or trusted-device/security-key profile.

- Connect separately selected `HTTPMFARecoveryRegeneration` to the native original
  factor-proof source and whole-set/session replacement. This supersedes the
  native-only HTTP caveat below; selection enables neither step-up nor login.
  Real HTTP rollback, contention and lost-ack recovery preserve no-redelivery.

- Independently select authenticated TOTP proof HTTP through
  `HTTPMFAActiveStepUp`, using the actual native session/factor source and shared
  verification limits. It enables neither enrollment nor login; unselected
  graphs expose no step-up variant. Recovery-regeneration HTTP remains separate.

- Compose separately selected native recovery-code replacement through
  `MFAEnrollmentConfiguration.Regeneration` and `MFARecoveryRegeneration`, with
  genuine fresh-factor proof admission, complete set replacement and session
  revocation. Selecting it appends the native session-disposition history but
  does not expose an HTTP route. Consumers must sign in again after replacement.

- Allow independently selected authenticated TOTP proof issuance through
  `MFAEnrollmentConfiguration.ActiveStepUp` and `MFAActiveStepUp`. Compose the
  real native current-session owner and append factor-verification storage only
  for selected graphs, preserving existing MFA/password migration allocations.
  This exposes a native public API, not an HTTP route or regeneration endpoint.

- Reject authenticated step-up requests in unselected login TOTP owners before
  entering login composition or disclosing rate-source metadata. Step-up cannot
  silently fall back to an anonymous continuation profile.

- Add explicit password-primary recovery-code completion and opt-in HTTP
  composition. Preserve original primary/browser scope, shared attempts,
  digest-only code burn, session provenance and credential-free replay/recovery.
  Existing preparation rate quotas remain charged after a final mutation abort;
  code, child consumption, session and lifecycle effects roll back together.

- Preserve code-free TOTP completion recovery for both selected primary profiles;
  recovery does not require verification input or regenerate credentials.

- Compose password-origin TOTP completion and opt-in HTTP challenge delivery
  without requiring magic-link login. Preserve original password/factor
  provenance through session reading and logout; replay never redelivers
  authentication credentials.

- Compose selected password-first TOTP owners with forward MFA/session migration
  histories and matching session read/signout profiles. Preserve previously
  installed prefixes and reuse native counting, encrypted output and recovery.
  Full public password-MFA journey acceptance and HTTP wiring remain outstanding.

- Add explicit password-primary TOTP completion selection, reusing the native
  counted completion pipeline without magic-link primary substitution. Preserve
  original signed credential/identifier authority and primary times. Graph
  migration selection, session read/signout and HTTP login wiring remain unfinished.

- Complete explicit enrollment-confirmation HTTP selection with native original
  custody, verification quotas and graph drain. Real registration proves HTTP
  enrollment, URI disclosure, activation and metadata-only retries without
  silently promoting the primary session. Closed-graph responses preserve the
  selected operation's wire shape. Password-first MFA login remains unfinished.

- Forward original confirmation quota custody through the native MFA graph's
  tenant/startup/shutdown admission. Confirmation HTTP selection remains
  unfinished; this read-only source neither verifies a code nor activates.

- Add explicit provisioning URI selection to MFA enrollment HTTP, preserving
  the native original-source quota/deadline and graph lifetime. The real
  registration journey now proves HTTP reveal and secret-free committed replay;
  confirmation HTTP and password-first MFA login remain unfinished.

- Add independent HTTPMFAEnrollment selection over native session,
  reauthentication, enrollment and shared-rate owners. Preserve pipeline hooks
  and graph shutdown/drain ownership. The real registration journey now proves
  cookie/CSRF enrollment, reveal-once recovery codes and metadata-only retry;
  URI/confirmation HTTP and MFA-required password login remain unfinished.

- Compose native MFA enable with retained synchronizer keys so selected cookie
  requests are fenced atomically with enrollment. The live registration-to-
  enrollment journey now uses that native cookie binding; HTTP enrollment
  handlers and MFA-required login remain separate unfinished work.

- Add explicit native MFAEnrollment composition for pending TOTP enable,
  reveal-once URI and code-confirmed activation over the graph's real password,
  primary-session and counted-risk owners. Retained handles enforce startup,
  tenant and shutdown admission. Extend the existing MFA history and reuse
  counted-preparation ownership without rewriting installed shared histories.
  Selection does not expose enrollment HTTP routes; live graph enrollment
  acceptance and that transport remain unfinished.

- Keep the selected magic-link/TOTP login owner closed to the new enrollment
  confirmation variant; do not interpret it as a login child or expose an
  unimplemented activation route. Existing login composition is unchanged.

- Compose explicitly selected signup-by-magic-link with its owned registration
  and factor-provenance histories, preserving installed prefixes and optional
  password/TOTP selection. Carry native proof limits into HTTP consumption.
  New and existing-account HTTP journeys cover delivery, supersession,
  consumption, credential-free retries and normal session logout.

- Add explicit HTTPMFA selection for native magic-link/TOTP completion with
  strict shared verification rates, original browser/device policy and concrete
  wire schemas. Unselected features expose no route or advertised operation;
  real HTTP integration remains to be verified.

- Expose an owned TOTP verification rate-source method on the selected handle.
  Authenticate original issuance and live or exact retained intent before
  returning immutable subject/challenge quota bindings; never decrypt a factor,
  charge native counters, generate a session or renew validity during this read.

- Route authenticated missing-factor TOTP attempts through the same atomic
  shared-budget, risk-counter, denial-audit and original-command history as
  wrong codes. Exact retries do not recharge; the final valid attempt completes.

- Compose selected magic-link/TOTP sessions into normal primary reads and
  cookie logout, retaining current factor fences and protected rollback/recovery.
  The public PostgreSQL journey exercises MFA login through session revocation.

- Select native magic-link TOTP completion through `MagicLink.TOTP` and
  `FeatureSet.MagicLinkTOTP`, with graph-owned issuer/browser/provider authority,
  original code/proof-free recovery and atomic shared budget, replay, child-use
  and session effects. Keep risk policy versions distinct from authorization
  revisions and preserve the original login policy identity.
- Install selected continuation/TOTP, protected preparation, counter and MFA
  session histories without rewriting existing prefixes; readiness checks the
  actual successor constraints. TOTP HTTP and mixed-session graph integration
  remain unfinished; no complete MFA enrollment or platform release is claimed.

- Bind selected magic-link HTTP continuation delivery to the native MFA
  configuration; unselected transport advertises no challenge credential arm.
  Full public TOTP completion and all-feature qualification remain unfinished.

- Compose native magic-link TOTP completion with protected provider custody,
  original-intent counter preparation and command-owned denial charging. Retain
  provider facts in encrypted output and recheck them at primary time. Graph/
  HTTP selection and positive public-path integration remain unfinished.

- Develop native TOTP completion orchestration with original-input history,
  counted denial, protected factor/session effects and reveal-once delivery.
  The feature remains unselected: anonymous protected-risk adapter charging,
  graph/HTTP selection and positive public-path integration are unfinished.

- Connect native magic-link resend and its supersession migration. The selected
  reference flow rejects an obsolete link without session credentials and logs
  in with its replacement; signup-by-link and MFA continuation remain unfinished.

- Require selected magic-link successor constraints in live readiness instead
  of their removed password/session predecessors. Keep original migration
  collision guards and checksums unchanged. Real PostgreSQL/Valkey reference
  integration now exercises public account creation and verification, encrypted
  magic-link delivery, explicit login, session reading and atomic logout/recovery.
  Scanner requests and foreign browsers cannot consume; replay cannot redeliver
  credentials. Resend and signup/MFA continuation remain unfinished.

- Use the same explicit password/OTP/selected magic-link method set for native
  session reading and transactional self-signout. Reject consuming issuers with
  incompatible deployment, namespace, audience, store, cookie or unreadable key
  material. Request-only magic-link selection grants no session authority.
  Complete reference magic-link runtime qualification remains outstanding.

- Add opt-in native magic-link request/consumption and original browser-flow
  selection to the reference graph, with guarded handles and selected HTTP
  routes. Reuse native factor, capability and session migration histories without
  rewriting existing prefixes. Selecting HTTP without its native graph now
  rejects construction rather than silently omitting the requested feature.
  Runtime reference-session and self-signout composition remain in development.

- Add explicit native password verification and keyed password-change selection
  to the reference graph. Bearer and CSRF-protected cookie ports remain distinct;
  all calls retain initialization, tenant and shutdown guards. Composition reuses
  native signing, protected counters, proof consumption, replacement and session
  disposition. New change migration suffixes retain existing installed histories
  and share the existing credential-replacement allocation with reset. Select
  verification/change HTTP independently with strict transport, origins, CSRF
  and shared native rate admission. Real durable reference composition exercises
  rollback, authorized recovery, session revocation and old/new-password login.
  Revoked cookies cannot authenticate same-key HTTP retries. Provider network
  responses remain fixtures; full release qualification remains outstanding.

- Add explicitly selected primary session reads and self-signout to the native
  reference graph. Cookie logout uses the original transaction's synchronizer
  state; bearer selection never falls back to cookies. Selected HTTP shares
  one bounded safe-rate owner, retains named browser-flow initiation, and joins
  graph shutdown cancellation/drain. Password session selection rejects lookup
  or CSRF keys that cannot verify the current issuer's exact key material.
  Selected signout appends the native single-session revocation migration;
  existing applied migration allocations and checksums remain unchanged.
  Correct the migration dependency's pseudo-version spelling without changing
  its source revision. Full session lifecycle and release qualification remain
  outstanding.

- Compose explicitly selected required-email-verification registration and
  confirmation through native signup, capability issuance, protected counters
  and encrypted delivery. Named signup initiation uses the existing secure
  browser-flow route. New accounts acquire the authorization epoch consumed by
  login atomically; unverified accounts cannot sign in. Selected native migration
  histories preserve existing reset/signin installations. HTTP remains opt-in;
  confirmation and retries do not issue sessions or reveal credentials again.
  The current profile still requires the OTP/device storage graph.

- Add explicitly selected original password-flow issuance and browser signin
  over the existing native session/password owners. Password initiation uses
  the named shared-route method without changing default OTP intent. Reset and
  signin compose as one password feature; wrong-method flows and replay cannot
  issue credentials. Native HTTP integration proves reset revocation and login
  with the replacement password without manually inserting original flows.
  The reference profile still requires the selected OTP/device storage graph.

- Compose observed HIBP screening from native reset's original command and
  authenticated issuer challenge with the durable PostgreSQL audit adapter.
  Native consumer integration checks required query/match/rejection records,
  protected attribution and unchanged-id reconciliation after a synthetic lost
  acknowledgement. Failed audit acknowledgement denies password mutation even
  when reconciliation confirms delivery. This does not qualify live provider
  interoperability or a durable audit-outage backlog.

- Exercise native reset password screening through the owned padded HIBP range
  client. Breached candidates, malformed responses, provider outages and
  redirects deny before password replacement, proof consumption or session
  revocation. Provider network responses remain synthetic test fixtures;
  observed audit integration and live interoperability remain unqualified.

- Add opt-in native password signin and recovery to the sealed graph with its
  counted risk evaluator, matching authorization and selected session storage.
  Retained handles enforce initialization, tenant isolation and closure without
  implicitly enabling HTTP. Selected native password/session migrations share
  password material with reset and preserve existing migration history. Native
  integration proves usable login before reset, revocation afterward and login
  with the replacement password. Migration discovery and readiness identify the
  signin constraint extension, not its already-owned shared session table.

- Deny readiness when a selected session store loses its credential-digest
  column, even if its native ledger and table names still match. Readiness
  observation does not repair schema or renew existing validity.

- Add selected native password-reset request, completion and recovery to the
  sealed graph and opt-in HTTP server, borrowing its counted risk, encrypted
  delivery and configured session owner. Startup, tenant and shutdown guards
  apply to every call. Selected migration discovery includes password material,
  factor authority, capability provenance, protected kernel/session reset
  effects and atomic completion rate admission without rewriting existing
  histories. Native integration exercises request, captured delivery, completion,
  revoked predecessor sessions and login with the replacement password.

- Enable bounded fresh readiness for the selected native graph after explicit
  migration deployment, initialization and covered velocity activation. Every
  observation checks selected migration compatibility and all tenants' original
  current custody. Recovery, schema loss, expiry and closure deny without
  debiting counters, renewing leases or repairing state. This does not complete
  the remaining reference-server profiles or platform journeys.

- Add opt-in email OTP Send, signin and historical recovery routes to the sole
  server graph. Selected transport requires native consuming owners, dedicated
  browser-device custody, shared strong rate admission and matching trusted
  authorization policy. Recovery returns the original outcome without issuing
  credentials again. JSON field and depth limits below the native recovery
  envelope are rejected during construction. Positive readiness and the
  remaining complete reference-server journeys are still pending.

- Add the side-effect-free sole server constructor over the sealed composition
  graph, exact complete policy callbacks, immutable transport selection and
  process probes. Opt-in original-flow HTTP initiation uses graph-owned native
  PostgreSQL rate and issuer custody. Bounded tenant resolution must match the
  trusted host before workflow admission; conflicts, cancellation and callback
  failure deny safely. Server and device configuration diagnostics are redacted.
  Complete login transport, positive native readiness and remaining deployment
  profiles are still pending; this checkpoint must not advertise ready traffic.

- Add opt-in graph-owned PostgreSQL strong HTTP rate admission and its native
  independently namespaced migration contribution. Explicit budgets and a
  public-only pool search path are required; construction performs no IO and
  graph shutdown permanently closes admission without closing the caller pool.
  Full server construction and browser integration remain pending.

- Align selected original-flow composition dependencies with the opt-in session
  HTTP feature and strict PostgreSQL rate authority. The reference server and
  production rate-migration contributor remain pending.

- Expose optional original OTP sign-in source discovery through the same selected
  native owner and sealed graph lifetime. Trusted transport obtains the original
  identifier for rate admission without an application reader or attempt debit;
  startup, tenant isolation and shutdown guards remain enforced.

- Add opt-in native original-flow initiation and outcome-only recovery to the
  OTP composition, with fixed deployment origin/action/policy, retained cookie
  key selection and graph lifetime/tenant admission. Initiation migrations use
  a selected independent native history so enabling initiation and consuming
  sign-in in either order preserves applied shared history. Multi-history owner
  checks retain every compatibility failure and plan steps bind their physical
  source rather than borrowing another history's version.

- Add opt-in single-factor OTP sign-in and code-free recovery through the sealed
  native composition. Startup, tenant selection and shutdown guard retained
  handles; new commitment reveals session/CSRF credentials once, while recovery
  preserves original history without credential redelivery. Selected consuming
  migrations retain existing Send-only allocations. MFA continuation and the
  complete reference HTTP server remain pending.

- Add opt-in operator migration Apply with complete-plan revalidation before
  writes, keyed operator-scoped retry binding and native atomic attribution.
  Original command requests resume across reconstructed owners and independent
  histories without replaying completed steps or adopting external progress.
  Dirty, incompatible, locked and unknown outcomes remain distinct; ambiguous
  commits retain their command identity for authoritative reconciliation.
  Check/Plan remain read-only. Automatic startup/server integration is pending.

- Add deterministic read-only selected-module migration planning, binding the
  complete participating native sources, ownership guards and ledger metadata.
  Pending prerequisites require explicit selection; completed prerequisites
  remain discoverable without adding unrelated work. Plans are detached
  caller-owned snapshots, not execution authority. Apply and durable command
  recovery remain pending.

- Add bounded read-only selected-module migration checks through native ledger
  discovery, retaining dirty/incompatible states and rejecting unmanaged schema
  adoption. Independent audit/outbox histories keep their original identities.
  The native migration backend pin now supports independent owner namespaces
  and atomic audit-role installation. Operational Plan/Apply and command-resume
  remain pending; this is not a complete migration service.

- Extend the selected OTP/delivery migration source with its public owners'
  kernel, OTP, session, delivery and authorization prerequisites. New permanent
  allocations follow the unchanged kernel/velocity prefix, allowing populated
  native histories to plan upgrades without renumbering applied migrations.
  Directory bootstrap tenants are explicit copied configuration, never inferred
  from users or risk scopes. Selected delivery cancellation, receipt tracking,
  authenticated receipts and reconciliation include their owned prerequisites.
  Cross-owner schema collisions are rejected before exporting history.
  Audit/outbox installation and complete operational
  Check/Plan/Apply remain pending; this is not deployment readiness.

- Add opt-in sealed OTP Send and delivery composition using the existing native
  adapters, shared risk policy and counter activation. Startup and processing
  are explicit and bounded; retained handles deny after shutdown. Selected
  delivery profiles require production policy and active-provider worker coverage.
  All selected workers share one conservative sender-capacity bound before claim.
  This partial profile still lacks selected-feature migration ownership and
  complete failure-recovery acceptance; it is not deployable reference composition.

- Retain successful native counter activation under the reference store owner.
  Internal deferred routing rejects unrecovered, foreign-policy, foreign-tenant,
  recovering and closed owners, and drains active mutations during shutdown.
  It preserves original counter outcomes without retry or freshness renewal.

- Add sealed, resource-only composition of the concrete PostgreSQL velocity
  journal and TLS Valkey recovery owner. Explicit bounded recovery restores
  original terminal history and enables counters only after covered primary
  closure and native-confirmed activation. Fresh journal coverage remains
  unavailable for a genuine full hour. Cancellation and shutdown deny admission
  without closing the caller's PostgreSQL pool.
- Export upstream-owned kernel and velocity migration contributions through
  the existing migrations source contract. The development reference allocation
  reserves versions 1000–1011 for velocity; differently allocated existing
  deployments are not automatically adopted.

This is a partial development profile, not a complete reference server or
release-ready identity platform.
