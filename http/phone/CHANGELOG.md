# Changelog

## Unreleased

- Add independently selected cookie-only phone self-removal with a closed,
  versioned request, original signed proof/CSRF custody and shared keyed rate
  admission. Return only original command and pending cascade status; never
  issue credentials or claim that queued notification/cleanup is complete.

- Preserve counted wrong-code denials and original verification/recovery
  responses by explicitly projecting code-free attempt correlation to JSON.

- Add explicit cookie-only existing-account phone enrollment, SMS verification
  and code-free original recovery handlers with closed JSON/OpenAPI, original
  session/CSRF/device/proof custody and canonical shared rate admission. No
  route, session, public signup/signin, replacement or reset is implicit.
