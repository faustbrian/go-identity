# Changelog

## Unreleased

- Add independently selected cookie-only MFA listing with closed safe metadata
  output, shared safe-route admission and unchanged original session validity.
  Reads reject body/query/target/Authorization/idempotency overrides, send no
  credentials and remain no-store through middleware and final delivery. HTTP
  reference composition remains in development.

- Connect that listing profile through explicit reference selection and real
  HTTP enrollment/recovery-count journeys. This supersedes the reference-
  composition caveat above; full MFA transport qualification remains pending.

- Add independent recovery-regeneration HTTP with original signed factor-proof
  lookup, cookie/Origin/CSRF, stable original-command quotas and reveal-once
  modern-code delivery. Native replacement owns atomic proof/set/session effects;
  replay, uncertainty and failed/expired delivery expose no codes.

- Add opt-in authenticated TOTP step-up on the explicit `X-MFA-Variant: step-up`
  arm. Require current cookie/Origin/CSRF and native original quota/deadline
  custody. Only a fresh known commit reveals a regeneration proof ID; no session,
  enrollment, replay, uncertain or expired proof output is delivered.

- Connect recovery-code transport to the explicitly selected native reference
  password-primary profile. This supersedes the earlier transport-only
  orchestration caveat below; standalone handlers still require a native service.

- Return a redacted HTTP 409 for classified completion conflicts instead of
  reporting them as provider unavailability, without delivering credentials.

- Add opt-in recovery-code completion transport with closed original-continuation
  input and no TOTP fallback. Retain shared browser/rate admission and deliver
  credentials only for fresh, matching recovery-session provenance. Native
  recovery orchestration and reference-server selection are not yet connected.

- Withhold provisioning URI and recovery codes when final-response middleware
  delays, cancels or fails delivery. Preserve committed command metadata without
  extending the original session or disclosure deadline.

- Add explicitly selected password-primary TOTP completion alongside magic-link
  completion. Deliver only credentials with matching original password/factor
  provenance and unexpired authority; reject cross-profile results without
  credential delivery. Password-only selection does not require magic-link login.

- Add a cookie-only enrollment confirmation handler using native original
  custody/deadline reads, verification quotas and atomic activation. Require
  the explicit enrollment discriminator and closed factor/code input; return
  activation metadata without session issuance. Select confirmation alone or
  alongside login behind one route with disjoint wire contracts. Reference
  selection and the live HTTP activation journey remain unfinished.

- Reserve an explicit singleton enrollment discriminator on the shared TOTP
  verification route. Absent-header login stays unchanged; invalid, duplicate
  or unselected variants fail before authentication without fallback. Preserve
  real pipeline hook binding; enrollment confirmation HTTP remains unfinished.

- Add explicit cookie-only provisioning URI transport, native original-custody
  quota/deadline reads and shared one-time-command admission. Reveal only after
  a fresh known commit; replay and expired delivery return no URI or successor.

- Add an explicitly configured cookie-only TOTP enrollment handler. Retain the
  original session and action-specific verification proof, enforce Origin and
  CSRF, and deliver recovery codes only on a fresh known commit. Enrollment
  remains pending until separate code confirmation; it creates no session.

- Add opt-in native magic-link/TOTP completion transport and closed OpenAPI
  contract. Bind original browser/device and authenticated subject/challenge
  quotas; deliver session/CSRF credentials only on fresh matching commitment.
  Replay, error, expiry and changed final status withhold credentials.
  Reference HTTP integration and full MFA transport remain in development.
