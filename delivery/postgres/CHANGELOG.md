# Changelog

## Unreleased

- Add owned prepared-enqueue orchestration through the original coordinator.
  Current exact-scope policy applies before reservation and on committed replay;
  denied callers create no command claim or delivery effect. Policy failures
  are redacted and fail closed. Complete public Queue admission, including
  pre-encryption authorization and scoped keyed dedupe, remains unfinished.

- Add native enqueue command preparation and an exact enlisted execution phase.
  Commands freeze every prepared effect under the original coordinator; absent
  or failed ciphertext persistence rolls back delivery and lifecycle effects,
  retaining only classified failure evidence. Authenticated Queue admission
  and complete public worker orchestration remain unfinished.

- Add private database-time worker heartbeat and conservative release.
  Renewal preserves the original credential expiry and attempt lifetime,
  rejects lost/foreign ownership and stops on cancellation. Release retains
  unknown provider effects for reconciliation without blind retry. Public
  Queue composition and authenticated lifecycle APIs remain unfinished.

- Add opt-in forward worker schema and private durable delivery processing.
  Claims record a tenant-bound generation before plaintext handoff; completion
  rejects stale workers and replays exact evidence. Lost leases reconcile rather
  than resubmit, bounded retries preserve original payload/identity, and expiry
  erases custody without inventing provider failure. Public Queue integration,
  heartbeat, receipts and authenticated cancellation remain unfinished.

- Recover the exact original encrypted-intent binding after process restart
  using the installed canonical profile and retained keys. Malformed or changed
  scope fails closed before decryption; recovery cannot renew credential expiry.
  Durable Queue leasing and provider processing remain unfinished.

- Expose immutable encrypted preparation and original-command staging through
  the public enlisted contributor, plus a migration source that extends kernel
  history without rewriting installed SQL. Foreign owners and original bindings
  cannot stage preparations; no-op admission retains no sendable custody.
  Complete Queue processing and authenticated feature workflows remain unfinished.

- Add original-command encrypted intent and safe-handle outbox admission under
  the enlisted kernel transaction. Concurrent matching inputs retain one effect;
  randomized encryption cannot duplicate admission, and terminal effects cannot
  regain custody. Expired ambiguous effects erase payloads without fabricating
  provider outcomes. Public Queue processing and migration installation remain
  unfinished.

- Freeze encrypted message custody under the original command and complete
  effect scope. Confidential logical identity survives randomized encryption;
  local attestation validation requires no key-provider call under transaction
  locks. Preparation and decryption cannot extend the original expiry.
  The production PostgreSQL Queue and processing lifecycle remain unfinished.
