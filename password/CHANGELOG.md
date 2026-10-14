# Changelog

## Unreleased

- Add a separate borrowed-proof reset inspection port returning only advisory
  valid/invalid state. Inspection grants no reservation or future completion
  permission and preserves the existing reset service interface.

- Add a closed password-first MFA challenge result, separate from authenticated
  session results. Challenge history cannot carry session cookies or CSRF, and
  replay cannot redeliver the challenge proof. Native login wiring is ongoing.

- Add explicit protected hash preparation that checks HIBP and required
  providers while deferring only transaction-owned velocity. Original provider
  freshness is rechecked after hashing; ordinary complete preparation remains
  unchanged. Native mutations must still reserve/recheck counters atomically.

- Add borrowed-secret, original-proof reset request/completion contracts and
  scoped proof-free recovery ports. Structural validation performs no IO or
  authority checks; request acceptance reveals no account/delivery state, and
  completion reports successors only with committed session revocation.
  The native public reset workflow remains in development.

- Bind original MFA generations in emailed-reset capabilities and reconstruct
  them unchanged. Historical unbound payloads retain their original bytes and
  do not fabricate factor authority; factor-fenced native completion denies them.

- Recover original emailed-reset scope from genuinely verified grants and the
  trusted callback allowlist without renewing versions or timestamps. Retained
  keys support unchanged original intent; retired keys/callbacks and malformed
  scope deny. Durable provenance and current recovery admission remain separate.

- Add immutable emailed-reset capability scope policy binding original account,
  credential and identifier versions, tenant, issuance command, recovery path,
  callback and lifetime. Retained callback-binding keys permit rotation without
  renewing issuance or expiry. Signature verification and transactional one-use
  consumption remain with capability; complete native reset remains in progress.

- Add signup and password-free original recovery ports with immutable anonymous
  attempt correlation. Closed result validation separates enumeration-safe
  verification acknowledgement from optional native session issuance and
  forbids credential redelivery on replay. Existing password APIs are unchanged;
  the complete native signup workflow remains in development.

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
