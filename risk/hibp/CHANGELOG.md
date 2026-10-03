# Changelog

## Unreleased

- Add scoped fixed-endpoint HTTPS checking with padding, redirect refusal,
  bounded private LRU caching, independent same-prefix waiters, bounded outbound
  and caller admission, explicit shutdown and typed redacted failures. Risk
  signals and password acceptance remain owned by unfinished composition.

- Begin HIBP support with bounded complete-range validation, private full-scan
  suffix matching and exact-byte candidate derivation from borrowed password
  secrets. HTTP checking, caching and risk integration are not available yet.
