# Changelog

## Unreleased

- Add the bounded self-rename request, service and transport rate-source
  contracts with exact original proof/session, comparison intent and version
  predecessors. Implicit serialization omits the candidate and credentials.

- Add the advisory availability service/request contract with explicit trusted
  tenant/network scope, redacted input and stable denied/throttled/unavailable
  errors. A positive observation grants no reservation or authentication.

- Add fixed Unicode 15.1 Latin-v1 username canonicalization with separate
  original display, explicit profile-bound persistence, before/after length
  limits, and versioned reserved/custom enrollment validation. Lookup and
  restoration do not reapply enrollment restrictions to existing names.
- Keep canonical identity within opaque name custody and provide profile-aware,
  display-independent equality; canonical bytes are available only through the
  explicit sensitive persistence projection.
