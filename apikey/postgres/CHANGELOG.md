# Changelog

## Unreleased

- Add current-human safe metadata Get/List for exact self or explicit
  organization ownership across selected modern/legacy profiles, including
  revoked, expired and no-expiry records. Reads expose neither credentials nor
  digests and do not verify, debit or mutate keys. Pagination survives native
  reconstruction and repeats current authorization on every live-view page.
- Add independent opt-in user/organization metadata paging indexes and
  per-configuration result limits. Access paths remain optimizer-dependent;
  native/caller deadlines bound the complete read. Apply the selected migration before
  using List; old issuance, verification and exact-key Get remain compatible.
  Ordinary transactional index builds require bounded deployment/lock deadlines
  and temporarily block key writers. Uninstalled selected indexes fail closed.

- Support digest-only legacy imports with an absent expiry under an explicitly
  selected `AllowLegacyNoExpiry` configuration. Preserve canonical source
  metadata and original bounded authority evidence through verification and
  recovery; rotation creates a finite modern successor and revocation remains
  terminal. Default legacy and modern expiry requirements are unchanged.

- Add explicitly selected organization-owned creation, digest-only import,
  verification, rotation, revocation and original status recovery through the
  existing native coordinator. Creator membership removal denies that person's
  management without revoking the organization's independent key; owner archive
  and restore cannot revive its previous credential epoch. Required effects,
  reveal-once custody and original non-renewable validity remain atomic.
- Add optional populated-state organization-owner migration without rewriting
  user records or historical checksums. Existing user management and canonical
  bytes retain their shape; ordinary unselected services deny organization paths.

- Add an explicit user-owned verify-only SHA-256 import profile through the
  existing native authority/coordinator, preserving canonical IDs, distinct
  source/record versions, original absolute times, restrictions and tombstones.
  Imports accept no plaintext and produce no issuance/reveal event.
- Add additive populated-state migration and exact legacy configuration checks.
  Bare verification uses server-selected bounded digest lookup; rotation makes
  a modern successor with a non-expanding expiry and no old-root authority.
  Source retries recover original outcomes; stale/conflicting updates fail
  explicitly rather than resurrecting credentials.
- Add a bounded read-only deployment configuration check for exact existing
  active profiles. It neither provisions nor resets disabled authority;
  first-install initialization retains its existing conflict semantics.

- Add native modern human-owned API-key issuance, reveal-once recovery,
  zero-overlap rotation and revocation using actual password bearer authority,
  protected admission and the existing identity coordinator.
- Implement unlimited-quota verification and secret-free original-attempt
  reconciliation with current authority, bounded non-renewable validity,
  atomic permission narrowing and separate authentication/update effects.
  Exact retries retain their original identity after subsequent key changes.
- Preserve the full supported 64-permission, 128-byte ceiling through
  verification and recovery, including JSON-escaped permissions. Snapshot,
  effect and storage bounds account for encoded records without weakening
  individual key-record limits.
- Require the original primary authentication to remain within the
  15-minute sensitive-operation window for create, rotate and revoke,
  including protected execution. Session refresh or a recent read cannot
  extend it. Fractional clock budgets conservatively floor verification
  deadlines to PostgreSQL precision rather than strand retained attempts.
- Reject Revoke reduction at native construction. This selected Narrow-only
  profile cannot represent a terminal revocation as a permissions-change event.
- Preserve identical failed-attempt replay after independent key transitions
  using the coordinator's existing authenticated preparation, including when
  protected effects rolled back. Complete incoming intent is still compared
  before returning original results; no second attempt journal is introduced.
