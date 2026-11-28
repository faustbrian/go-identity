# Changelog

## Unreleased

- Add opt-in HTTPS pending denial using the original ordinary session,
  the shared audited admin quota, and a metadata-only terminal response.

- Add opt-in approved-grant keyed Start and combined Start/Stop selection.
  Only the original committed native call sets the paired child cookies;
  receipt-only retries leave transport untouched.

- Add an opt-in HTTPS cookie self-stop route with separate child CSRF and
  exact commit-gated child-cookie deletion. Leave the ordinary session
  untouched.
