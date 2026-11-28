# Changelog

## Unreleased

- Add explicit configurable-quorum HTTPS selectors that check the native
  lifecycle versions for Start, Deny, and Stop, and expose bounded distinct
  approvals in the quorum view. Keep the fixed-one selectors unchanged.

- Add an opt-in HTTPS quorum read for the native single-approval profile.
  Require the original administrator cookie and shared audited admin quota.

- Add opt-in HTTPS pending denial using the original ordinary session,
  the shared audited admin quota, and a metadata-only terminal response.

- Add opt-in approved-grant keyed Start and combined Start/Stop selection.
  Only the original committed native call sets the paired child cookies;
  receipt-only retries leave transport untouched.

- Add an opt-in HTTPS cookie self-stop route with separate child CSRF and
  exact commit-gated child-cookie deletion. Leave the ordinary session
  untouched.
