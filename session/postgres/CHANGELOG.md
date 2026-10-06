# Changelog

## Unreleased

- Compose public credential-based bulk session revocation through the owned
  primary reader, native command executor and core service. Original admission
  bounds final commit; retained counts/disposition replay without new mutations.
  Restart recovery uses current result-access policy, survives payload pruning
  and rejects corrupt native metadata without erasing a known command outcome.
  Install the bulk migration before use; no application domain stores or final
  signin-proof issuer are required. Full session lifecycle remains unfinished.

- Add bounded transactional revoke-other/revoke-all effects to the configured
  native contributor. Select the complete tenant/user set across audiences,
  reject over-limit sets without partial changes, and retain counts and source
  disposition with command recovery evidence. Preserve surviving source bearer,
  lifetime and authentication while advancing its session version; never bump
  user-wide authority. Install `RevokeSetMigrationSource` after the base history.
  Owned bulk execution/public factory composition remains under development.

- Add owned authenticated session listing with an indexed, bounded primary
  tenant/user/audience keyset query and safe active/inactive device projections.
  Apply `ListMigrationSource` after the base session install at a permanent
  history slot; it adds an index without rewriting session records or earlier
  migrations. Construction needs no application store or command journal.
  Device labels, remaining session profiles and complete lifecycle remain pending.

- Compose public idempotent self-logout through `NewSignOutService` with the
  owned primary reader and native transactional executor. One execution profile
  selects schema, authority, clock and policy; no application stores or fresh
  login are required. Clear only the selected transport after committed or
  already-inactive success; operational failure never becomes cookie deletion.
  Historical recovery remains on the native executor. Full session lifecycle
  and release verification remain unfinished.

- Add owned single-session execution using original opaque caller admission,
  current policy and same-transaction source/target owner checks. Freeze both
  records and original validity in command intent, order session locks to avoid
  cross-revocation deadlocks, and bound commit by primary-observed remaining
  admission time even with application-clock skew or slow audit/outbox work.
  Replays and scoped restart recovery retain historical outcomes without a new
  transition. Revocation does not require final-signin proof composition;
  public idempotent signout and absent/expired target handling remain pending.

- Add exact single-session revocation through the existing coordinator with
  complete original-record mapping, locked directory/credential/policy/session
  admission, target-only CAS and retained terminal successor evidence. Sibling
  records, family authority and original snapshots remain unchanged. Install
  `RevokeOneMigrationSource` alongside the selected issuance history before
  using this configured native operation. Caller authentication and public
  idempotent logout orchestration remain unfinished.
- Permit later independently issued sessions in an existing active family
  while retaining its original creation timestamp. A session cannot predate
  its family; corrupt or future family timestamps still fail closed.

- Add owned single-factor stateful session validation using the committed core
  service and native primary directory, user, identifier, exact credential,
  authorization and session/family owners. Deny ambiguous retained-key lookup,
  revoked or stale authority and unsupported dimensions without cache fallback.
  Preserve original read-start freshness and exclusive credential/session
  expiry. Construction borrows the primary pool and requires existing migrations;
  remaining profiles, rotation and complete login remain under development.

- Add restart-safe issuance reconciliation from exact historical scope and
  trusted current caller, without retaining original authentication proof or
  bearer custody. Return only command metadata under current policy; preserve
  live leases and reconcile expired intent through the existing kernel owner.
  Missing or conflicting participant evidence cannot prove rollback or success.

- Add owned authenticated cookie-issuance execution and original-request
  recovery using the kernel command owner and production audit/outbox adapters.
  Bind current self-service access and atomically persist the original session,
  proof use and mandatory effects; core token custody reveals only after a new
  committed result. Historical replay/recovery never reveals a credential.
  Consume the committed core issuer and exact-input recovery contracts.
  Process-restart recovery, browser-container policy, rotation and complete
  login/session authentication remain unfinished.

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
