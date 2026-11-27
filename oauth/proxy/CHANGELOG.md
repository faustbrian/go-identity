# Changelog

## Unreleased

- Validate callback tenant bindings as exact Directory IDs, preserving uppercase
  canonical IDs while rejecting malformed values without provider work or a
  handoff. Deployment, recipient and claims-profile slug rules are unchanged.

- Add a command-owned callback mode so the native coordinator can already
  own reservation, preparation and atomic settlement. The provider step is
  invocation-local and cannot disclose a handoff on replay or without an
  acknowledged commit. The existing reserve/finalize mode remains available.

- Add the production OIDC preview callback coordinator. It binds provider
  exchange to acknowledged original state and PKCE, then requires acknowledged
  settlement before returning encrypted evidence to an exact registered preview
  endpoint. Unknown outcomes do not release a handoff or trigger an exchange retry.
