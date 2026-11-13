# Changelog

## Unreleased

### Added

- Side-effect-free `Config.Validate` for rejecting malformed selected cache
  configuration during composition. It shares the constructor's validation;
  `New` still performs its original strict TLS/server probe at initialization.
- Explicit standalone TLS 1.3 session positive caching using the existing
  authenticated encrypted-cache codec. Restored hits, promotion and retries
  retain the original authoritative deadline of at most 20 seconds.
- Bounded exact-session and family invalidation generations fence stale fills.
  Marker loss, persisted-server restart, flush, capacity exhaustion and cache
  outage discard cache eligibility or use the existing primary reader. No
  cache-only authentication, session authority or cluster profile is added.

No existing APIs or stored primary records change. This is a new optional module.
