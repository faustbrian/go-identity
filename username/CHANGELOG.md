# Changelog

## Unreleased

- Add fixed Unicode 15.1 Latin-v1 username canonicalization with separate
  original display, explicit profile-bound persistence, before/after length
  limits, and versioned reserved/custom enrollment validation. Lookup and
  restoration do not reapply enrollment restrictions to existing names.
- Keep canonical identity within opaque name custody and provide profile-aware,
  display-independent equality; canonical bytes are available only through the
  explicit sensitive persistence projection.
