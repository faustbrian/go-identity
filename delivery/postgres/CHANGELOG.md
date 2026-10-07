# Changelog

## Unreleased

- Owned workflows can checkpoint and restore original encrypted delivery
  preparation across process restart. Authenticated original-generation custody
  preserves effect identity, expiry, retained keys and recipient fences without
  regenerating secrets or renewing authority. Automatic serialization remains
  forbidden; checkpoints grant no queue or execution authority.

- Native workflow delivery can bind an explicit anonymous flow without a
  fabricated user. A separate authenticated custody profile preserves the
  original flow through restart and worker execution; existing user custody
  bytes remain unchanged. User-only management rejects anonymous effects even
  when the flow and user IDs have identical text.

- Public `Worker` and full `Queue` now expose scoped `RenewLease` and
  `ReleaseLease` for explicitly scheduled workers. Renewal retains the original
  attempt lifetime and enforces provider identity even when profiles share retry
  policy. Release atomically records audited outcome-unknown, preserves custody
  for reconciliation and denies blind resubmission; exact replay is unchanged.
  Existing core interfaces and synchronous processing remain unchanged.

- `EnqueueService.NewQueue` composes every public delivery Queue operation with
  the existing command, policy, custody and worker owners. Full composition
  explicitly selects status tracking, cancellation, signed receipts and provider
  reconciliation; legacy admission and worker profiles remain available. Core
  service configuration must match the retained worker profile. Normalized
  receipts cannot substitute authenticated callback fields; mutation replay
  retains original command and fences without requerying or resending.

- Public workers require status tracking and atomically stage protected audit
  for claims, completion, no-invocation release, lease-loss uncertainty and
  expiry/erasure. Audit failure rolls back state, custody and history; exact
  completion replay retains its event. Cleanup respects the selected provider.
  Worker actor, tenant, correlation and policy attribution now require 1–64
  ASCII letters, digits, underscores or hyphens and fail at construction rather
  than after leasing. Local exhaustion does not assert provider unavailability.

- Owned public worker composition from an existing admission service, with
  current service-account policy before leasing, after custody opening and
  before completion. Exact retained provider and policy versions govern sends,
  retries and completion replay, including providers sharing a retry policy.
  Sender runs after committed lease acquisition, outside SQL ownership; unknown
  sends remain unretryable. Full Queue facade and release verification remain
  in development.

- Enable opt-in public original-key reconciliation with current service-actor
  policy, bounded lookup outside transactions/reservations, encrypted scoped
  restartable cursors and atomic original-command progress/status/audit/lifecycle.
  Historical replay never queries or resubmits. Terminal observations and other
  settlement paths erase cursor custody. Add a forward optional query migration
  without changing installed checksums; transient query failure grants no retry.
  Recover pending query commands through the original coordinator's current
  policy and unanimous retained evidence without provider lookup or replay.

- Add optional original-command reconciliation results and a protected local
  participant under the identity coordinator. Commit keyed progress, provider
  evidence, erasure, audit and lifecycle together; preserve historical replay
  and recover abandoned commands without a second journal. Existing migration
  checksums are unchanged. Public query admission and cursor custody remain
  unfinished.

- Add optional forward reconciliation checkpoint storage and private borrowed
  effect application. Fence original generation and keyed cursor progress,
  commit provider evidence and terminal erasure together, and preserve original
  query results on replay. Public query/cursor custody and retry admission remain
  unfinished; installed migration histories remain unchanged. Cursor exhaustion
  permits later polling of unresolved effects only at the latest checkpoint step.

- Project authenticated acceptance and bounce evidence in public status,
  subsequent receipt settlement and cancellation without rewriting original
  worker results. Add opt-in metadata-only receipt tracking after callback
  credentials are retired; legacy compositions remain unchanged.

- Enable opt-in authenticated provider receipts through owned key configuration
  and the original kernel coordinator. Enforce current provider actor/tenant/
  version policy before reservation and disclosure; commit event, erasure, audit
  and lifecycle atomically. Exact retries recover immutable original results
  without renewed fences. Requires both receipt migrations and state tracking;
  disabled configuration preserves installed enqueue plans. Complete Queue and
  provider-specific interoperability remain unfinished.

- Add the private owned signed-receipt authentication foundation: bounded
  deployment/tenant/provider/version-scoped HMAC-SHA256 envelopes, explicit key
  validity/rotation, fresh signatures for delayed observations and strict closed
  JSON decoding. This does not yet enable public callbacks or claim vendor
  signature interoperability; protected admission remains unfinished.

- Add forward receipt-command results and a private native receipt participant
  under the original kernel coordinator. Bind redacted keyed evidence and exact
  version/generation fences; commit event result, custody erasure, protected
  audit and lifecycle together. Exact replay preserves the original result;
  downstream failure restores all effects. Public callback authentication and
  current-policy admission remain unfinished.

- Forward optional provider-receipt schema and borrowed receipt effect phase:
  scoped keyed event dedupe, immutable evidence/results, generation fencing,
  monotonic provider observations and atomic terminal ciphertext erasure.
  Unknown observations preserve the original live worker's completion fence;
  definitive provider evidence fences late competing completion. Public callback
  authentication/coordinator composition and reconciliation remain unfinished.

- Add opt-in authenticated local cancellation through the original kernel
  command authority. Freeze version/generation, retain keyed confidential reason
  identity, and atomically persist protected audit, lifecycle and exact replay
  outcomes. Target-retained policy fences survive configuration rotation;
  submitted sends remain unknown and keep attributable worker completion.
  Requires status and cancellation migrations; full Queue remains unfinished.

- Expose current-policy-authorized versioned delivery snapshots in the selected
  status-tracking profile. Read intent version and attempt metadata together
  without consumer-written SQL, payload access or mutation; legacy profiles
  reject versioned reads rather than fabricate a fence. Public authenticated
  cancellation remains unfinished.

- Add a forward original-command cancellation result migration and private
  native coordinator phase. Atomically retain redacted stop outcomes with
  status/generation fences, protected audit and lifecycle; downstream failure
  restores custody, and original replay does not renew status. Public
  authenticated cancellation and complete Queue composition remain unfinished.

- Stage cancellation through borrowed transaction access so the owning command
  can roll back custody, scheduling and status together. Private standalone
  cancellation retains its existing commit and unknown-outcome semantics;
  authenticated public cancellation remains unfinished.

- Add an opt-in forward status-tracking profile without rewriting installed
  migration history or queued custody. Preserve old-writer monotonic versions
  and immutable no-op local-stop metadata across expiry; legacy status remains
  supported, and selecting absent tracking schema fails closed.

- Preserve live, attributable worker completion across local cancellation
  fences while preventing lease renewal and retry. Add the private atomic
  cancellation foundation; authenticated public cancellation remains unfinished.

- Add current-policy-authorized primary delivery status with exact tenant and
  target-user isolation. Preserve attempting, accepted and unknown distinctions
  without exposing payloads or provider references. No-op intents retain the
  same queued/expired status shape; reads never mutate or retry delivery.

- Add owned public message admission with authorization before primary recipient
  discovery and versioned rendering. Compose atomic custody, audit and lifecycle
  persistence without consumer-written stores; preserve scoped duplicate intent
  identities and classify changed-input conflicts and ambiguous outcomes.
  Exact retries after expiry preserve authoritative historical outcomes without
  renewing expiry or admitting new delivery effects.
  This admission service does not yet implement the complete Queue lifecycle.

- Select delivery recipients from the owned primary identifier directory after
  exact-scope authorization. Freeze and transactionally fence record versions
  so an intervening address or owner change cannot commit stale delivery custody.
  Pending addresses are restricted to address-verification purposes.

- Add scoped request-key allocation to the original enqueue command. Matching
  requests with different candidate command IDs retain one intent and receipt;
  changed confidential input conflicts. Allocation grants no execution outcome.
  Install the additive keyed migration after retained policy history.
  Preserve the original custody fingerprint key across rotation and fail closed
  when its retained key is unavailable, without duplicating committed effects.

- Require current delivery-scope authorization before enqueue encryption and
  again before reservation. Bind original recipient scopes, template versions
  and retained provider policies; reject caller overrides and unavailable
  history without claiming a command. Public Queue composition remains pending.

- Add immutable retained delivery-policy registration and version-isolated
  worker selection. Restart configuration changes cannot reinterpret an
  installed policy; rotation retains original retry and lease settings.
  Select the new forward policy migration after the worker extension.
  Complete authenticated Queue admission remains under development.

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
