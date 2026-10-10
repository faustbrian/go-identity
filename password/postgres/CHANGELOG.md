# Changelog

## Unreleased

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
