# Changelog

## Unreleased

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
