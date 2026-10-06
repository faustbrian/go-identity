# Changelog

## Unreleased

- Add storage-neutral session rotation with exact original caller and transport
  custody, retained-key compatibility, immutable successor preparation and
  commit-gated reveal-once delivery. Preserve absolute and authentication lifetime,
  family and unrelated authority; replay, recovery, error and ambiguity deliver
  no credential. Native atomic rotation and reuse-family revocation remain pending.

- Preserve exact known bulk-revocation commitment when ancillary retained
  metadata cannot be read. Return a redacted error and no count/version/source
  disposition; malformed receipts or partial metadata still fail closed.

- Add fresh authenticated revoke-other/all orchestration with explicit source
  preservation, bounded whole-set commands and opaque original caller custody.
  Receipt versions and recovery bind the authenticating session; the user CAS
  remains unchanged so preserving that session does not invalidate its owner.
  Original authority and authentication freshness deadlines cannot be renewed.
  Denial, cancellation and ambiguous outcomes expose no successful count.
  Atomic PostgreSQL set mutation and recovery remain pending adapter work.

- Add bounded authenticated self-session listing with current authorization,
  safe device projections and optional inactive records. Scope-bound keyset
  cursors traverse at most 100 raw rows per call without exposing credentials,
  digests or proof linkage; expiry and cancellation deny partial disclosure.
  The owned PostgreSQL page-reader composition remains a separate pending step.

- Add bounded public self-signout through the configured primary reader and
  owned revocation executor. Absent or primary-denied credentials succeed
  without a new mutation; active callers target only their original session.
  Cookie and bearer removal remain separate. Preserve durable outcomes and
  exact recovery scope while withholding successful logout/deletion on policy
  denial, outages, cancellation or ambiguity. Ordinary logout needs no fresh
  login. Real PostgreSQL composition and complete session services remain
  separate pending integration work.

- Add one-session request preparation bound to the configured authenticated
  reader's opaque caller custody and original exclusive validity. Retain the
  independent complete target while rejecting fabricated callers, foreign
  composition, cross-owner targets and same-ID record substitution. This does
  not require fresh login, execute revocation or replace transactional policy
  and current-owner checks; public idempotent logout remains in development.

- Add an immutable exact-target one-session revocation command preserving the
  original authority snapshot and checked version successor. It cannot project
  as issuance or family revocation. Execution and idempotent logout remain
  pending; construction alone does not authenticate or authorize a caller.

- Add explicit stateful opaque credential validation with bounded retained-key
  lookup, exact active authority-vector and lifetime admission. Preserve original
  source freshness within 20 seconds, deduct clock uncertainty, reject stale
  fallback and retain cancellation/error classification. Positive result copies
  cannot renew validity or authenticate through public-field reconstruction.
  Cookie/bearer transport uses one token profile without OAuth token semantics.
  The owned primary reader and other storage profiles remain required work.

- Add owned authenticated cookie issuance orchestration with private original
  token preparation, exact durable receipt/record matching, unchanged remember
  policy and commit-gated reveal-once delivery. Replays, recovery, unknown
  outcomes and failed delivery never return a bearer. The storage-neutral
  executor's public owned PostgreSQL composition remains in development.
  Add access to the original opaque request proof for protected native adapter
  admission without admitting structural metadata as authentication.

- Add a closed exact-scope native family-revocation command with checked
  full-width versions. It remains distinct from issuance and user-wide logout;
  preparation alone grants no authorization or durable outcome.

- Preserve all resolved remember-policy limits through trusted persistence
  projections and exact reconstruction. Invalid or unresolved stored values
  fail rather than applying new defaults or silently clamping lifetime limits.

- Add immutable authenticated issue requests retaining the upstream opaque
  final proof with its exact native command. Expected-authority validation
  rejects foreign proof provenance and metadata/credential substitutions;
  copying preserves original proof expiry and resolved session lifetime.
  This admission does not issue, persist, consume or reveal a session.

- Add immutable complete session records and closed, exact-bound native issue
  commands carrying resolved remember policy, full authority vector, digest-only
  lookup and original proof/credential metadata. Anonymous records have a
  separate zero-assurance variant and cannot carry verified or factor metadata.
  These are structural preparation, not authenticated or committed issuance;
  authority-issued proof validation and durable effects remain unfinished.

- Preserve authentication completed before session issuance when calculating
  freshness, rather than requiring its timestamp to be reset to issuance.
  Pre-issuance activity and future authentication still fail closed. Existing
  in-family timestamps retain their prior behavior.

- Add complete immutable session authority vectors with exact scope/version
  comparisons and explicit organization, factor and passkey applicability.
  Missing dimensions and changed authority deny without silently renewing
  stale sessions. Primary reads, activity/freshness proof and persistence remain
  in development.

- Add opaque canonical 32..64-byte token custody, one-winner explicit delivery
  across copies, automatic formatting/serialization protection and versioned
  tenant-bound HMAC lookup digests. These are credential primitives, not durable
  session issuance or authentication.

- Add one explicit remember-policy choice shared across authentication
  continuations, with a browser-session lifetime cap, idle/absolute/freshness
  checks and secure host-cookie lifetime/deletion attributes. Session issuance,
  persistence, rotation and revocation are not yet available.
