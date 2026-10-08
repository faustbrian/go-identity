# Changelog

## Unreleased

- Add opt-in `GET /v1/session/get` with explicit cookie/bearer selection,
  trusted HTTPS tenant mapping, strict credentials, canonical safe-route rates,
  and credential-free original session/expiry/refresh metadata. Reading never
  changes session or transport state. Full feature/router/OpenAPI composition,
  signout and release qualification remain in development.
