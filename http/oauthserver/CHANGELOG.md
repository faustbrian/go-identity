# Changelog

## Unreleased

- Opt into device authorization, session-bound consent, and the device grant
  on the single shared token route. Keep device and workload IP budgets
  separate and document only the selected grant and cookie contracts.

- Add independently selected confidential-workload token, owning-client
  introspection and revocation HTTP features with strict Basic/form custody,
  canonical shared rate admission, typed router/OpenAPI composition and
  no-store protocol responses. Final current authority and durable effects
  remain with the native OAuth owner. Other grants and discovery are not
  selected. The selected native PostgreSQL/HTTPS lifecycle and required-effect
  rollback are exercised; Reference integration remains in development.
