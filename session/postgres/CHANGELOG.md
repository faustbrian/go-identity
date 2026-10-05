# Changelog

## Unreleased

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
