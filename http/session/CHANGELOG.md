# Changelog

## Unreleased

- Add opt-in `POST /v1/session/signout` with explicit cookie/bearer selection,
  exact trusted origin, bounded canonical token channels, primary transactional
  CSRF and safe-route admission before mutation. Clear only the selected
  transport on confirmed success; retain original command/outcome/recovery
  on ambiguity, cancellation and delivery error without automatic retries.

- Add opt-in `GET /v1/session/get` with explicit cookie/bearer selection,
  trusted HTTPS tenant mapping, strict credentials, canonical safe-route rates,
  and credential-free original session/expiry/refresh metadata. Reading never
  changes session or transport state. Full feature/router/OpenAPI composition,
  signout and release qualification remain in development.
