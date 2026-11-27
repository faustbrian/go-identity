# Changelog

## Unreleased

- Expose a no-I/O production callback selector for transport admission and
  the original preview flow and immutable cutoff after acknowledged settlement.

- Authenticate a preview handoff against the independently loaded original
  browser flow, exact preview registration and original cookie before opening
  encrypted provider evidence. Return its unchanged observation and earliest
  original deadline without consuming a grant or creating a session.

- Add trusted preview initiation admission with one configured HTTPS registration
  and bounded bearer authentication. Exact subject, issuer, sole audience and
  proxy-start scope are required before returning unchanged command, transaction,
  request fingerprint and resolved remember bindings. Cancellation, panic and
  authentication failures return only redacted typed errors; admission has no
  provider, persistence, issuance or HTTP effects.

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
