# Changelog

## Unreleased

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
