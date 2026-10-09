# Changelog

## Unreleased

- Preserve password credential continuation through durable reconstruction,
  native command mappings, rotation and revoking other sessions. Current
  admission uses the effective credential version without rewriting original
  authentication or advancing unrelated authority. Install the additive
  credential-continuation migration after OTP history and upgrade relevant
  readers/writers before selecting the new stored profile.
  Fresh credential-proof issuance rejects continuation rather than allowing
  historical proof linkage to substitute for the current credential version.

- Add closed original-session admission mapping for native cross-module
  workflows. Preserve credential or OTP authentication, complete authority,
  remember and CSRF state without copying the session codec into other owners.
  Malformed or incomplete fields deny; mapping grants no authentication.

- Add bounded primary inspection of the retained OTP sign-in user/session/family
  identity, including after live session payload deletion. Validate the original
  command and record commitment without reconstructing a session or credential;
  historical inspection remains separate from disclosure authorization.

- Add the native consuming OTP session effect within the original coordinator
  transaction, preserving verified recipient, authority, remember and CSRF state
  and denying stale owners or expired authentication. Retained recovery binds
  actual user/session/family and record identity after live-payload cleanup.
  Install `OTPIssueMigrationSource` after existing issuance/OTP record history;
  old proof-based evidence remains unchanged. Public OTP sign-in and recovery
  composition remain under development.

- Add closed scalar OTP sign-in session mapping, preserving anonymous command
  scope separately from the selected user and retaining exact authentication,
  remember policy, authority and optional CSRF state before reservation.
  Existing proof-based mappings remain unchanged. Mapping is structural only;
  consuming session effects and public sign-in remain under development.

- Add an explicit owned OTP session reader using the exact verified identifier
  and current primary authority without requiring a persistent credential.
  Preserve original authentication and bounded evidence deadlines; historical
  OTP expiry does not expire an issued live session. Existing proof-only
  composition stays unchanged. Apply the OTP record migration before selecting
  this profile; native consuming signin and restart recovery remain pending.

- Preserve original OTP authentication provenance in durable session schemas
  3/4, including optional synchronizer state, without changing historical
  schemas 1/2 or renewing authentication time. Apply `OTPMigrationSource` after
  the CSRF migration and upgrade readers/writers before OTP writes. Native OTP
  authentication and atomic sign-in composition remain under development.

- Add an explicit owned cookie-logout executor with named-key selection and
  CSRF checks inside the original primary mutation transaction. Keep raw tokens
  ephemeral, retain a strict-profile command discriminator, and reject legacy
  dispatch rather than downgrade protection. Existing direct execution remains
  compatible for requests without CSRF custody. Apply the existing CSRF migration
  before selecting this profile; HTTP/browser enforcement remains pending.

- Add borrowed-transaction synchronizer-token admission against the exact
  primary session and active family, retaining invalidation fences through
  protected work. Callers must abort on denial and preserve other authority
  and terminal-time checks. Native workflow and HTTP wiring remain pending.

- Preserve session synchronizer CSRF state in stored records, native command
  projections and rotation recovery. Keep tokenless historical bytes unchanged.
  Add a forward-only CSRF record migration; apply it and upgrade relevant
  readers/writers before enabling the new profile. Old binaries fail closed on
  CSRF-bearing records. HTTP token/origin enforcement remains in development.

- Add identifier-admission profile validation and original-session authority
  derivation for native participants. Preserve exact owner expectations without
  IO, refreshing epochs, authenticating a bearer or granting permission.

- Compose the public owned pre-auth issuer with native atomic initiation and
  restart-safe outcome recovery. Persist the unchanged server-generated cookie
  commitment and remember choice; only fresh commitment permits core delivery.
  Use the core canonical operation descriptor without changing stored command
  shapes or migration history. Native OTP continuation remains under development.

- Add pre-auth issuance results distinguishing sole-reservation execution from
  replay, pending observation and conflict. Concurrent identical commands grant
  fresh-execution eligibility to only the committing owner; historical receipts
  never permit cookie delivery. Existing receipt-only calls remain compatible.

- Add owned pre-auth initiation execution and restart-safe receipt recovery
  with exact service policy, original flow, audit and lifecycle in the sole
  kernel transaction. Preserve original metadata on replay and deny retired
  flow-ID resurrection under new commands. Install forward
  `PreAuthIssueMigrationSource` after the kernel/pre-auth histories; retained
  issuance evidence survives live-payload retirement. Flow generation, cookie
  delivery and OTP continuation composition remain under development.

- Freeze complete original pre-auth initiation state in a closed native command
  vocabulary, with separate anonymous-flow target and service actor. Reject
  substituted scope, incomplete fields, narrowed versions and noncanonical
  timelines without changing remember policy or cookie commitment. Public
  issuance and command-recovery composition remain under development.

- Add terminal pre-auth release through the exact owner's sealed coordinator
  noncommit callback, including expired reservations. Preserve original flow
  intent and cookie while fencing rollback/recovery generations and terminal
  replay. Install forward `PreAuthReleaseMigrationSource` after the initial
  pre-auth migration during a bounded constraint-update window; existing rows
  and applied migration checksums are unchanged.

- Add structural primary pre-auth loading, exact reserved-owner admission and
  predecessor-only generation transfer. Preserve the original cookie, intent,
  remember policy and expiry across takeover; stale owners and terminal flows
  cannot transfer or finalize. Transfer requires live coordinator authority,
  not elapsed time or a caller-supplied generation.

- Add canonical pre-auth primary storage and exact locked admission, one-winner
  reservation and same-transaction consumption. Preserve original intent,
  remember policy, nanosecond expiry and named cookie digest; fence exact
  command/fingerprint/generation and deny terminal replay without renewing or
  automatically releasing state. Install additive `PreAuthMigrationSource`
  after the base session schema. Public initiation/recovery and native workflow
  registration remain under development.

- Add native self-session device-label CAS with unchanged bearer, activity,
  authentication, remember choice and unrelated authority. Commit metadata,
  version, audit/lifecycle and receipt atomically; retain exact replay and
  bounded outcome-only restart recovery. Install `UpdateMigrationSource` for
  both update and list paths. The additive tables preserve older session row
  writes/codec; current labels cascade with payload deletion and historical
  evidence stores label digests rather than duplicating plaintext. Browser
  transport and complete privacy/release verification remain pending.

- Add bounded, owner-scoped database-time expiry cleanup with current service
  authorization, locked refresh-safe selection, terminal digest retirement and
  same-commit audit/lifecycle effects. Preserve natural-expiry authority versions
  and retained command/rotation/revocation evidence. Exact retries and restart
  recovery return historical deletion count/lag rather than selecting another
  batch. Install `CleanupMigrationSource` after the base/rotation history; its
  transactional owner/expiry index installation requires a bounded write window.
  Scheduling and general privacy erasure remain separate platform work.

- Add explicit protective retired-token replay checking with current trusted
  service policy and primary lineage-derived ownership. Commit one exact family
  revocation with protected audit/lifecycle effects, preserve exact retry
  receipts, and recover historical outcomes after restart without a bearer.
  Active, absent, foreign and expired tokens reserve no command. Ordinary
  session reads remain read-only; transports must explicitly enable the guard
  and enforce origin/CSRF policy. Reuse the existing rotation/family migrations.

- Add restart-safe rotation receipt recovery using the original safe command
  scope and current access policy. Preserve historical version/audit metadata
  without original authentication admission or live session payloads; never
  return a session or credential, renew live leases or reserve missing commands.

- Add owned source-bound session rotation with atomic digest retirement,
  successor persistence and audit/lifecycle effects. Preserve absolute lifetime,
  original authentication and every non-session authority. Reveal credentials
  only through the core rotator after a new successful commit; replay/recovery
  never redeliver them. Install `RotationMigrationSource` after existing history;
  its populated-row backfill and digest guards cover old/direct session writers.
  Retained exact-intent evidence supports historical recovery without live
  session payloads. Retired-token family-replay revocation and other remaining
  session profiles still require implementation before full lifecycle completion.

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
