# Changelog

## Unreleased

- Add immutable complete session records and closed, exact-bound native issue
  commands carrying resolved remember policy, full authority vector, digest-only
  lookup and original proof/credential metadata. Anonymous records have a
  separate zero-assurance variant and cannot carry verified or factor metadata.
  These are structural preparation, not authenticated or committed issuance;
  authority-issued proof validation and durable effects remain unfinished.

- Preserve authentication completed before session issuance when calculating
  freshness, rather than requiring its timestamp to be reset to issuance.
  Pre-issuance activity and future authentication still fail closed. Existing
  in-family timestamps retain their prior behavior.

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
