# Changelog

## Unreleased

- Extend the selected OTP/delivery migration source with its public owners'
  kernel, OTP, session, delivery and authorization prerequisites. New permanent
  allocations follow the unchanged kernel/velocity prefix, allowing populated
  native histories to plan upgrades without renumbering applied migrations.
  Directory bootstrap tenants are explicit copied configuration, never inferred
  from users or risk scopes. Selected delivery cancellation, receipt tracking,
  authenticated receipts and reconciliation include their owned prerequisites.
  Cross-owner schema collisions are rejected before exporting history.
  Audit/outbox installation and complete operational
  Check/Plan/Apply remain pending; this is not deployment readiness.

- Add opt-in sealed OTP Send and delivery composition using the existing native
  adapters, shared risk policy and counter activation. Startup and processing
  are explicit and bounded; retained handles deny after shutdown. Selected
  delivery profiles require production policy and active-provider worker coverage.
  All selected workers share one conservative sender-capacity bound before claim.
  This partial profile still lacks selected-feature migration ownership and
  complete failure-recovery acceptance; it is not deployable reference composition.

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
