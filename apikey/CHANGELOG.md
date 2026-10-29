# Changelog

## Unreleased

- Add optional safe metadata Get/List contracts without expanding the existing
  Service interface. Explicit self/organization ownership, selected configuration
  filters and bounded live-view pagination grant no credential or mutation
  authority and never expose secrets or digests.

- Add explicitly selected no-expiry legacy import and verification contracts,
  preserving an absent historical expiry without inventing a deadline. Default
  legacy and all modern profiles still require expiry; current owner eligibility
  and the original bounded authority evidence remain mandatory.

- Add an explicit organization creation extension that cannot be ignored by
  an older self-owned service. Organization create/rotate results retain the
  real human manager separately from their owner, require exact selected
  schemas, and preserve reveal-once and uncertain/status-only recovery custody.

- Represent known organization-key verification and same-tenant digest-import
  snapshots without fabricating a human owner. Organization credential epochs
  must match exactly, preventing a later owner epoch from reviving old keys;
  user-key policy epoch and unknown-key denial behavior remain unchanged.
- Keep legacy credential and verifier custody redacted inside private diagnostic
  wrappers as well as direct formatting, without changing digest bytes or APIs.
- Add explicit verify-only bare SHA-256 credential and digest-only import
  contracts, preserving stable typed metadata and source versions without
  changing modern parsing, HMAC digests or retained configuration bytes.
- Add modern tenant/configuration-bound HMAC API-key secret custody with
  reveal-once delivery and status-only unknown-outcome recovery contracts.
- Add explicit self-owned management, current-authority grant intersection,
  version-fenced Narrow/Revoke decisions, and exact atomic verification attempt
  contracts for the uncached unlimited-quota profile. Unsupported profiles deny.
- Keep shared tenant/configuration authority distinct from each key's credential
  root, with scoped verification evidence and independently fenced permission
  reduction outcomes.
