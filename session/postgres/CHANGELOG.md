# Changelog

## Unreleased

- Add explicitly configured authenticated session issuance through the existing
  protected coordinator. Preserve the complete original record, remember policy,
  proof/credential linkage and authority vector; compare native current owners
  before effects and terminalization. Session, family, proof use and issuance
  evidence roll back together. New forward-only issuance migrations preserve
  installed history. Existing constructors remain opted out; complete bearer
  delivery, container policy, rotation and composed login remain pending.

- Add opt-in native privacy session eligibility on the original coordinator
  transaction. Checks retain original user/credential/identifier authority,
  exact owner keys, session/family locks and primary expiry without renewing
  proof metadata. Unsupported optional owners deny. Adopt the committed kernel
  invocation contract; complete privacy admission and export remain pending.

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
