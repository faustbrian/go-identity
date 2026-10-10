# Changelog

## Unreleased

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
