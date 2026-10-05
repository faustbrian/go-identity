# Changelog

## Unreleased

- Add explicit native identifier admission using the original coordinator
  transaction and existing kernel/authorization owners. Exact session scope,
  credential linkage and owner-derived keys are checked without rewriting
  metadata or renewing freshness; only the proven identifier successor changes
  the final comparison. Unsupported organization, factor and passkey profiles
  deny. Existing repository construction stays opted out; complete protected
  workflow activation remains pending.

- Publish framed session/family authority keys and consume the committed kernel
  admission contracts. Historical custom snapshot keys require an explicit
  migration or replacement session; they are not silently upgraded.

- Add bounded borrowed-primary `RequireSession` admission: exact immutable
  record, active session/family versions, share locks and database-time expiry.
  It supplies only session-owned checks, not full authority or authentication.

- Add native transactional family revocation through the sole identity
  coordinator, with exact owner/tenant/version checks, retained command evidence
  and mandatory audit/lifecycle declarations. Original session snapshots are
  never rewritten. Apply the additional permanently allocated
  RevocationMigrationSource migration before enabling this contributor; the
  original MigrationSource API and install remain unchanged. Issuance remains
  unsupported.

- Add forward-only complete session/family storage with digest-only unique
  lookup, tenant-bound relationships and retained revocation state. Bounded
  structural primary reads preserve all authority dimensions, original precise
  timestamps and resolved remember-policy limits. Reads do not authorize use;
  shared-coordinator issuance, rotation and recovery remain in development.
