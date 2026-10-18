# Changelog

## Unreleased

- Preserve counted wrong-code denials and original verification/recovery
  responses by explicitly projecting code-free attempt correlation to JSON.

- Add explicit cookie-only existing-account phone enrollment, SMS verification
  and code-free original recovery handlers with closed JSON/OpenAPI, original
  session/CSRF/device/proof custody and canonical shared rate admission. No
  route, session, public signup/signin, replacement or reset is implicit.
