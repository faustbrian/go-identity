# Changelog

## Unreleased

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
