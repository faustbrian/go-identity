# Changelog

## Unreleased

- Add identity-owned account linking with explicit, opt-in verified implicit
  and opt-in administrative paths. Bind signed one-use evidence to exact actor,
  provider subject, command, continuation and authority/record choices; preserve
  collisions, tombstones, independent access and known/unknown commit outcomes.
  Add canonical proof-payload construction without treating it as authority.
  Authorize exact account IDs before link/unlink recovery receipt reads,
  overriding caller metadata and preserving account-specific policy denial.
  Provider ceremonies, durable proof/risk/token-vault atomicity, SQL and public
  feature/transport composition remain required integration work.
- Add bounded identity-owned identifier and verification records, and copied
  attach/verify/primary/replace/remove transitions with explicit authority and
  record fences. Replacement clears verification and primary selection; removal
  retains versioned retirement data for scoped reuse tombstones. Canonical
  normalization, fresh proof consumption, tenant-wide uniqueness, final access,
  durable commands and feature/transport composition remain pending.
- Add current-subject account unlink command admission and scoped recovery.
  Verify exact issuer/audience/session/command/version/provider-choice bindings
  using signed one-use capabilities; preserve unknown or known committed
  outcomes without claiming provider revocation success. Durable proof/risk
  consumption, SQL and full public transport composition remain pending.
- Add the identity-owned unlink state transition with aggregate, account,
  social-link and credential fences. Recheck final usable access against locked
  primary eligibility; produce copied next state and a tombstone version without
  claiming a durable commit or provider cleanup. Data-only unlink preserves the
  credential authority dimension.
- Target Go 1.27, matching the current Golib module baseline.
- Add tenant-bound account and non-secret credential metadata, current-subject
  account reads with per-row policy/redaction and a shared final-access decision.
  Preserve imported canonical IDs and federation URNs. Refuse removal when no
  independent usable human login method remains; API keys and expired/disabled
  methods do not qualify. Transactional link/unlink, pagination, fresh proofs
  and provider cleanup remain unfinished integration work.

- Add explicit versioned suspend/ban and restore/unban commands with registered
  reasons, bounded absolute expiry, scoped recovery and distinct user authority
  versions. Preserve historical replay and known commitment after output failure;
  reject future versions and purpose substitution. Owner admission reports every
  required consumer pending, never asynchronous revocation completion. Durable
  SQL, consumer acknowledgements, audited expiry and keyed transport are pending.

- Add self-service profile reads, versioned explicit-command updates and scoped
  recovery with a distinct email/status/role-excluding projection. Require the
  current human subject, current operation/field policy, bounded allowlisted
  HTTPS images, privately copied output and replay-before-active/version CAS.
  Preserve known commits after disclosure failure. Session/keyed transport,
  durable adapters and full catalog/composition integration remain pending.

- Add explicit-ID administrative typed-field updates and scoped recovery.
  Preserve same-command replay before stale-version checks, retain original
  known outcomes after output failure, and bind new writes to field policy and
  a single aggregate-version advance. Creation/update recovery reject wrong
  purposes. Reject future expected versions before mutation so authorization
  cannot cross into a newer account state. Durable adapters, keyed admission
  and self-service profile remain
  unfinished integration work.

- Add the five-member PolicySet and bounded typed risk, claims, retention and
  redaction evaluation. Copy policy inputs/results, enforce current versions and
  registered reasons, reject destructive legal-hold allows and incomplete field
  partitions, and omit every failed decision. Existing upstream authorization
  and read/create APIs remain unchanged; full workflow integration is pending.

- Add authorized explicit-ID user creation and scoped command recovery through
  storage-neutral UnitOfWork execute/recover contracts. Freeze typed command
  payloads, reuse field enforcement and sample trusted time once. Preserve
  committed/conflict/in-progress/unknown outcomes; withhold output after current
  redaction failure or cancellation without inventing rollback. Durable adapters,
  keyed transport admission and remaining lifecycle operations are still pending.

- Add versioned typed additional-field schemas and bounded command preparation.
  Preserve false, zero, empty strings/lists and full int64 values; normalize
  through explicit versioned composition, enforce field permissions through the
  existing authorization service and reject the whole request on invalid or
  denied fields. Creation defaults and returned lists are privately copied.
  This prepares values only; durable create/update commands remain in development.

- Add tenant-scoped bounded user listing with stable-snapshot continuations,
  confidential signed cursors and fresh collection/row authorization. Bind each
  continuation to its viewer, filters, limit and policy; retain its original
  expiry and withhold all partial output on cancellation or malformed pages.
  The existing get-only constructor remains valid; directory composition adds
  listing explicitly and requires an owned snapshot repository.

- Add bounded user lookup through the upstream revision-fenced authorization
  service, injected canonical-ID validation and typed redaction. Reject scope
  mismatches before storage and never disclose users after cancellation,
  policy failure or malformed repository output. A read-only constructor does
  not require mutation/capability dependencies. Redaction decisions must carry
  an explicitly registered reason; missing or unknown reasons deny disclosure.

- Add tenant-bound user projections and closed lifecycle statuses, preserving
  canonical directory IDs unchanged. Add bounded explicit status-policy
  validation that denies terminal resurrection, unlisted edges and invalid
  restriction durations without performing or authorizing a mutation.

### Added

- Distinct subject and pre-authentication transaction ID contracts with
  cryptographic 128-bit generation, strict canonical reconstruction, decoded
  byte ordering and stable redacted invalid-input/entropy errors.
