# Changelog

## Unreleased

- Add complete immutable session authority vectors with exact scope/version
  comparisons and explicit organization, factor and passkey applicability.
  Missing dimensions and changed authority deny without silently renewing
  stale sessions. Primary reads, activity/freshness proof and persistence remain
  in development.

- Add opaque canonical 32..64-byte token custody, one-winner explicit delivery
  across copies, automatic formatting/serialization protection and versioned
  tenant-bound HMAC lookup digests. These are credential primitives, not durable
  session issuance or authentication.

- Add one explicit remember-policy choice shared across authentication
  continuations, with a browser-session lifetime cap, idle/absolute/freshness
  checks and secure host-cookie lifetime/deletion attributes. Session issuance,
  persistence, rotation and revocation are not yet available.
