# Changelog

## Unreleased

- Retain successful native counter activation under the reference store owner.
  Internal deferred routing rejects unrecovered, foreign-policy, foreign-tenant,
  recovering and closed owners, and drains active mutations during shutdown.
  It preserves original counter outcomes without retry or freshness renewal.

- Add sealed, resource-only composition of the concrete PostgreSQL velocity
  journal and TLS Valkey recovery owner. Explicit bounded recovery restores
  original terminal history and enables counters only after covered primary
  closure and native-confirmed activation. Fresh journal coverage remains
  unavailable for a genuine full hour. Cancellation and shutdown deny admission
  without closing the caller's PostgreSQL pool.
- Export upstream-owned kernel and velocity migration contributions through
  the existing migrations source contract. The development reference allocation
  reserves versions 1000–1011 for velocity; differently allocated existing
  deployments are not automatically adopted.

This is a partial development profile, not a complete reference server or
release-ready identity platform.
