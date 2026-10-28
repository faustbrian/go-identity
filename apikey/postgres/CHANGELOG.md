# Changelog

## Unreleased

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
