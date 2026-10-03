# Changelog

## Unreleased

- Add owned checker-to-risk composition with full attribution validation,
  neutral breach facts and safe classified failures. Preserve original provider
  expiry independently of local assessment freshness; reject incompatible
  cache policy at construction. Password workflow integration remains pending.

- Add scoped fixed-endpoint HTTPS checking with padding, redirect refusal,
  bounded private LRU caching, independent same-prefix waiters, bounded outbound
  and caller admission, explicit shutdown and typed redacted failures. Risk
  signals and password acceptance remain owned by unfinished composition.

- Begin HIBP support with bounded complete-range validation, private full-scan
  suffix matching and exact-byte candidate derivation from borrowed password
  secrets. HTTP checking, caching and risk integration are not available yet.
