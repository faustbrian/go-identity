# Changelog

## Unreleased

- Select `SignupConfig.AuthorizationNamespace` to initialize the new user's
  authorization epoch atomically with registration, password, factor authority,
  verification grant and delivery. Use the namespace consumed by session
  admission. Neutral collisions and recovery never initialize or reset epochs.
  Empty retains legacy registration-only preparation identity; selected profiles
  have distinct custody and require the authorization owner's installed history.

- Add explicit reset screening attribution using the immutable original command
  and authenticated issuer challenge. Select `ResetConfig.CollectReset` instead
  of `Screening.Collect` for observed provider/audit composition. Foreign proof
  or scope never reaches the collector; recovery restores original output
  without recollecting. Legacy collector profiles retain their original digest;
  switching collection modes changes custody identity and cannot reuse retained
  preparations under the other mode.

- Authenticate original issued reset subject, credential and challenge lifetime
  for transport admission through the configured current query policy. Foreign
  tenant/target/action or stale policy denies without returning source metadata.
  This read grants no use; completion repeats primary authority and atomic use.

- Expose the frozen reset-request destination parser for shared HTTP rate
  admission without account, factor, issuer or delivery lookup. Invalid or
  canceled input returns no destination; native reset retains all authority.

- Compose public reset request and proof-free request recovery with keyed
  original-intent correlation, primary credential/factor admission and encrypted
  issuer/delivery checkpoints. Matching retries do not issue/send again;
  missing or factor-ineligible recipients receive the same acknowledgement
  without issuance. Select `ResetConfig.Request` and install its owner histories;
  nil preserves completion-only composition. Reset HTTP remains in development.

- Prepare reset grants into original encrypted email delivery and issuance
  custody without exposing a bearer or sending before commitment. Preserve
  recipient, callback, factor, authority and expiry bindings across restoration.
  Public request initiation/recovery and reset HTTP remain in development.

- Add native public reset completion and proof-free command recovery using
  issuer-owned provenance and current credential/factor authority. Replacement,
  session revocation, one-time use and required audit/lifecycle effects share
  the protected transaction. Original retries retain their generated verifier;
  proven rollback retains its dependency failure and terminally releases the
  original proof. Public reset request, delivery and HTTP remain unfinished.

- Retain code-free original reset predecessors inside encrypted preparation
  output so retries need not select a new aggregate version after commitment.
  Bind output to the immutable command, configuration and original generation;
  reconstruction still requires original password/proof fingerprint matching.

- Compose native reset completion with real credential replacement, required
  session revocation and atomic one-use/audit/lifecycle owners. Preserve encrypted
  preparation and original replay without hashing again. Public request,
  delivery and reset HTTP/service orchestration remain in development.

- Bind native reset verifier generation to original proof custody and signed
  credential/factor scope. Reuse counted Authentication admission and shared
  HIBP-before-hash screening without renewing original evidence. Restore the
  original verifier and signed admission from encrypted preparation output
  without regeneration or resurrection of terminal proof custody. Public reset
  orchestration and HTTP exposure remain in development.

- Extend the existing original-command material CAS and hash-free effect history
  to the distinct native reset-complete operation. Preserve password-change
  behavior and installed migration bytes; forward migration 6 admits reset
  receipts without adding another intent journal. No hash-only reset endpoint is
  registered. Full native/public reset composition remains in development.

- Initialize authoritative known-empty MFA state atomically with genuine new
  password accounts. Neutral signup and rollback do not create factor state;
  existing accounts remain unknown. Install the MFA authority migration before
  native signup. Password-reset orchestration remains in development.

- Adopt opt-in keyed browser signup HTTP composition with native required-email
  verification and strict PostgreSQL admission. Preserve original retry-key,
  flow/device and schema-field custody; do not manufacture sessions or disclose
  existing accounts. Immediate-session/MFA signup remains unsupported.

- Expose native signup address normalization for split rate admission without
  account lookup, password work or live-flow requirements. Original keyed
  retries remain usable after flow consumption or deletion.

- Adopt opt-in browser password signin HTTP composition with the native service
  and strict PostgreSQL admission. Preserve original remember/callback custody,
  fresh-only cookie/CSRF delivery and credential-free restart recovery.

- Expose original-flow-authenticated signin identifier normalization for split
  IP/identifier rate admission without account lookup, password comparison,
  risk charging, pre-auth consumption or session issuance.

- Adopt selected original-signup email confirmation HTTP composition with the
  native service and strict PostgreSQL rate owner. Preserve fresh address
  disclosure, metadata-only replay and proof-free original-command recovery.

- Expose authenticated original signup-link subject, signed grant ID and
  immutable lifetime for verification-rate composition. Preserve current query
  policy and callback binding, returning no mailbox or partial metadata on
  failure. Historical consumed provenance grants no permission to reuse a proof;
  confirmation remains the owner of current checks and atomic effects.

- Bind typed email confirmation/recovery to the existing native coordinator.
  Fresh successful confirmation returns an exact-version verified address after
  current disclosure policy and a primary read. Replay/recovery stay metadata-
  only; later disclosure failure preserves known commitment without payload.
  Existing receipt APIs remain compatible and this profile issues no session.

- Confirm original signup email links explicitly through native proof-bound
  counters and atomic capability, address, audit and lifecycle participants.
  Scanner validation remains read-only; same-command replay preserves the
  original receipt, and proof-free recovery uses current disclosure policy.
  Select `SignupVerificationConfig.Counters` and install the forward kernel
  email-verification and risk verification-counter migrations. This initial
  require-verified profile creates no session or additional delivery.

- Inspect delivered signup verification links through scanner-safe public
  validation. Require an issued unused proof, original callback and current
  active account/pending identifier without consuming, renewing, mutating or
  issuing a session. Return only boolean eligibility; later confirmation must
  repeat admission and commit atomically. Historical origin reads stay separate.

- Authenticate original registration email-verification intent through the
  native signup owner under current confirmation caller policy. Preserve signed
  issuance, encrypted input, original expiry and retained replay-key provenance
  without requiring the original cookie/password or a live pre-auth flow. Reads
  neither mutate nor consume; the complete confirmation workflow remains pending.

- Fix interrupted-signup password reconciliation through the bounded kernel
  row API. Preserve nullable credential evidence and deny contradictory
  material; missing issuance evidence still leaves the whole command pending.

- Add native public required-verification signup and password-free original
  recovery. Keep account, password material, flow consumption, verification
  issuance and encrypted delivery atomic; matching retries do not regenerate.
  Suppress occupied identifiers without exposing accounts or issuing grants.
  Recovery authenticates retained input and original cookie after flow deletion
  and never redelivers credentials. Immediate-session/MFA signup remains pending.

- Keep original signup password and cookie custody distinct from the generated
  verifier. Native preparation uses the kernel's existing journal before hash
  generation and restores the original encrypted risk, verification issuance
  and delivery for atomic account/material/flow effects. Complete public signup
  orchestration and password-free recovery remain in development.

- Recheck original signin risk admission at the same authoritative observation
  as the session and credential bounds, without invoking configured risk clocks
  under SQL locks. A frozen evaluator clock cannot admit expired original facts
  after audit/outbox waits; stale admission rolls back issuance.

- Add original-command password material persistence for native registration.
  Require the exact active transaction and newly created account, identifier
  and password reference; preserve the prepared verifier unchanged and roll
  back material with the account on failure. Public signup orchestration and
  password-free signup recovery remain in development.

- Upgrade successfully compared obsolete password hashes inside the original
  backend signin transaction. Bind salted replacement material to the keyed
  command, atomically advance credential material/reference and independent
  authority versions, and issue only a successor-bound session. Preserve original
  remember/risk/policy/expiry and password-free historical recovery; failures
  roll back hash and session effects together. MFA continuation remains pending.

- Add native backend password-signin orchestration through exported Go APIs,
  including canonical email discovery, enumeration-neutral verification,
  original cookie/intent admission and atomic proof/session/audit effects.
  Preserve browser or persistent cookie policy and deliver bearer/CSRF once
  after commit. Password-free restart recovery discloses only authorized
  original history, including after session payload cleanup. This development
  profile requires verified email and current-policy single-factor material;
  atomic rehash, MFA continuation and remaining lifecycle profiles are pending.

- Add immutable native password-signin signing-key custody without exposing a
  public signing operation or private material. Keys copy consistent Ed25519
  input and reject unsupported authentication profiles. Native transaction
  execution now persists original authentication, pre-auth consumption, session
  and synchronizer with required audit/outbox, and gates reveal-once delivery
  on a new successful commit. Expired delivery preserves committed history
  without revealing credentials. This does not yet
  supply a complete login service or atomic hash-upgrade workflow.

- Add bounded primary reading of immutable committed original password-signin
  records through Authentication's existing SignInSource contract. The additive
  migration preserves existing password material and reauthentication history;
  closed decoding retains original signatures, versions and times. This source
  does not sign, authenticate, issue sessions or supply a public record setter.

- Qualify protected cookie verification through selected HTTP and real primary,
  password, rate and proof owners. Return the stored signed original without
  renewing session or synchronizer state; reject invalid custody/password
  without success effects. Cookie password change consumes the signed proof
  located by the verification response. Browser and full release remain pending.

- Add explicit native cookie password verification with frozen dedicated
  synchronizer keys and exact primary session/family admission in the existing
  atomic proof/audit/outbox transaction. Rotation after lookup denies, including
  unchanged session versions; concurrent proofs preserve the synchronizer.
  Bearer APIs remain unchanged, and recovery remains proof-free. HTTP pending.

- Qualify selected bearer password verification with original signed browser
  correlation through real PostgreSQL primary, atomic rate and proof owners.
  Missing device custody denies before rate admission; committed HTTP results
  preserve the original signed proof while session and atomic effects retain
  native lifecycle behavior. Cookie verification and full release remain pending.

- Bind existing native password reauthentication to the portable verification
  port without changing direct service signatures. Forward original bearer,
  password and target once; reject incomplete or foreign recovery scope instead
  of discarding it. Original outcomes and proof-free recovery are preserved.
  Cookie-protected verification and optional verification HTTP remain pending.

- Qualify cookie password change through the optional Feature and selected
  router with native PostgreSQL owners. Validate original committed/replayed
  outcomes, pre-command conflict and missing-CSRF denial against the selected
  OpenAPI responses without introducing consumer transaction or handler glue.

- Document optional cookie password-change HTTP composition using native
  primary session/proof and atomic rate owners. Preserve the same protected
  journal, original retry key, replay and pre-command conflict semantics;
  HTTP feature selection and full lifecycle/release remain in development.

- Bind the strict native cookie password-change profile to the portable cookie
  Change/Recover port. Forward the original nested retry key and opaque CSRF
  token without selecting bearer fallback or transferring secret custody.
  Existing direct signatures remain supported; optional HTTP remains pending.

- Clarify native cookie-change restart and recovery: retain original eligible
  CSRF keys for receipt replay, while retired keys deny replay and changed
  token intent conflicts under the original retry key. Session continuation
  preserves historical authentication, lifetime and synchronizer state;
  disclosure of a committed receipt after source revocation renews no authority.

- Add an explicit keyed cookie password-change profile with required opaque
  session CSRF custody. Validate exact synchronizer state under the existing
  primary fences before preparation admission and mutation; rotation between
  observation and execution denies without consuming the proof. Cookie and
  bearer request intents are separated, and CSRF bytes are never persisted.
  Existing bearer/unkeyed APIs remain unchanged. Portable cookie/HTTP wiring
  and full lifecycle/release qualification remain in development.

- Bind the native keyed password-change workflow to the portable password
  Change/Recover port without changing existing direct service signatures.
  The request's required retry key reaches the original journal unchanged;
  keyless input cannot select an unkeyed fallback. Original unknown, committed
  and recovered outcomes retain their native meanings. Optional HTTP can now
  consume the core contract without importing this adapter.

- Add opt-in keyed authenticated password change on the existing kernel journal.
  Matching retries retain the original encrypted preparation and credential
  outcome; changed password, proof or network intent conflicts without repeating
  screening or charging counters. Original risk/proof expiry bounds blocked
  work, and ambiguous commits use code-free recovery. Retain namespace/HMAC
  configuration and decrypting local keyring keys; install kernel request-key,
  preparation, admission-preparation and counter-preparation histories. The
  existing unkeyed service remains supported; HTTP and full password lifecycle
  and release qualification remain in development.

- Compose native password-change session preservation, revoke-other and
  revoke-all in the original protected transaction. Freeze trusted choice and
  whole-set cap in each command; zero configuration retains strict revoke-all.
  Continued bearers use current credential versions for fresh reauthentication
  without rewriting historical login, freshness, lifetime or CSRF custody.
  Reconcile retained session effects alongside password/proof recovery. Install
  the session CSRF/OTP/credential-continuation/password-change histories before
  enabling this service. Other-factor preservation and full lifecycle/release
  qualification remain in development.

- Add native authenticated password change with original signed-proof validation,
  HIBP screening, current-password reuse denial and protected counter admission.
  Consume the proof with password material, credential authority, audit and
  lifecycle effects in one transaction; rollback preserves proof availability.
  The initial strict profile invalidates all prior credential authority, including
  the source session. Code-free original-outcome recovery does not repeat
  provider work or password submission. Install additive password migration 4
  and the selected native risk counter histories. Selective session preservation,
  reset/administrative flows and full lifecycle/release qualification remain
  in development.

- Add native single-factor password reauthentication using the original bearer,
  counted/audited abuse admission and current locked primary owners. Commit the
  original signed proof, required audit and lifecycle event together without
  creating or extending sessions. Exact configured targets and capped original
  lifetime deny scope expansion. Code-free outcome recovery never redelivers a
  proof; unknown outcomes must not be automatically retried. Install password
  migration 3 and the selected kernel/session/authorization/audit/outbox histories.
  Protected atomic consumption, other factor profiles and complete password
  lifecycle/release qualification remain in development.

- Add bounded primary retrieval of original signed password reauthentication
  records through authentication's public source contract. Pending, aborted,
  absent, foreign and malformed records expose no partial proof or renewed
  freshness. Install additive password migration 3; native issuance, current
  authority checks, atomic consumption and retention remain in development.

- Add native existing-password material replacement through the original
  coordinator transaction. Require exact current issuance parameters, lock and
  CAS the owned predecessor, and retain hash-free original-command evidence.
  Legacy material remains readable and may be replaced without changing its
  encoding first. Install additive password migration 2 and kernel replacement
  history. Reauthentication/HIBP/session and complete lifecycle workflows remain
  under development; no independent setter or authenticated endpoint is added.

- Add forward-only password material storage and bounded canonical-account
  primary reads that preserve exact hash encoding and full credential versions.
  Consistent kernel eligibility and material/version checks prevent partial
  positive results; the public core can compare real stored credentials.
  Coordinated mutations, complete lifecycle and release qualification remain
  in development. No independent setter or consumer workflow is provided.
