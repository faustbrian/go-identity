# Changelog

## Unreleased

- Add bounded, redacted signup input retaining the original raw password,
  generic address, pre-auth cookie, remember choice and opaque retry key.
  Requested attributes have bounded tagged shapes but require independent
  schema/policy admission. Structural validation grants no creation or session
  authority; complete native registration remains in development.

- Add a native sign-in/recovery port, immutable password-free original attempt
  correlation, and structurally checked session-owned results. Historical
  recovery preserves deleted-session identity without credential redelivery;
  unknown outcomes never imply rollback. Native login orchestration and genuine
  MFA continuation remain in development; existing workflow APIs are unchanged.

- Add bounded, redacted password sign-in input preserving actual pre-auth cookie
  custody, raw identifier/password bytes and the resolved remember choice.
  Attempt identity remains server-owned; structural validation grants no flow,
  authentication or session authority. Native orchestration and endpoint remain
  in development. Existing password verification/change APIs are unchanged.

- Add a distinct portable cookie-verification input and native workflow port.
  Original session-owned synchronizer custody is required without revealing or
  checking it during intrinsic validation. Native atomic CSRF/proof admission
  and origin/channel transport remain separate requirements; bearer APIs and
  original authentication proof ownership are unchanged. Native binding pending.

- Add adapter-neutral non-keyed password verification request, target, result
  and native workflow port. Preserve original authentication proof ownership,
  borrowed raw credential custody and scoped code-free outcome recovery;
  intrinsic validation grants no issuance authority or request-selected expiry.
  Native portable binding and optional verification HTTP remain in development.

- Add a separate adapter-neutral cookie password-change input and workflow port
  using the session-owned opaque synchronizer token and the original nested retry
  key. Structural validation grants no CSRF authority; native transaction checks
  and exact-origin transport admission remain required. Bearer APIs are unchanged.
  Cookie native binding and HTTP endpoint composition remain pending.

- Add adapter-neutral keyed password-change request/result and workflow ports.
  Require the original retry key, bounded trusted caller/tenant scope and live
  borrowed password custody without inventing a second proof type or default
  mutation policy. Implicit input serialization denies. Native adapter binding
  and HTTP composition are subsequent development work, not completed endpoints.

- Expose the shared pre-transaction hash preparer through explicit bounded
  composition. HIBP must be enabled for each supported creating operation;
  incomplete, unavailable, breached, foreign or stale facts disclose no hash.
  Original screening facts are not renewed after crypto. This grants no
  credential authority and does not replace atomic risk/proof consumption.

- Add bounded canonical-account password comparison with current-policy dummy
  work and a primary authority/material recheck before returning a match.
  Account blocking, credential changes, expiry and stale versions deny neutrally.
  This result does not issue a session/proof or replace the required transactional
  signin, risk, MFA and upgrade workflow; the durable adapter remains pending.

- Gate password hash creation through the existing risk policy's mandatory
  HIBP assessment for every selected creating operation, including recovery and
  administrative paths. Recheck unchanged facts after hashing; stale, foreign,
  unavailable and non-allow results cannot produce a usable hash.

- Add the private shared credential execution path for upcoming workflows:
  require completed screening before hashing, perform real dummy verification
  for unknown accounts, and discard output on cancellation or custody loss.
  Durable registration/signin and provider composition remain unimplemented.

- Add explicit registration enablement and inclusive raw password-byte limits
  over primitive-owned ephemeral secrets, without normalizing or consuming
  them. Generic signup-address validation preserves owner interpretation and
  denies implicit serialization. Complete identity password workflows remain
  in development; these checks do not authorize a credential mutation.
