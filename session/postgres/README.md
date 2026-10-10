# PostgreSQL session storage

## Original-signin hash upgrades

`PasswordSigninEffect.PrepareHashUpgrade` admits the frozen prospective
session's directory before reserving exclusive predecessor user/credential
locks through the kernel. Call it in the registered password owner's original
Apply invocation, before shared recipient/credential or password-material
locks. Freeze the kernel-owned predecessor fields and successor-bound signed
proof/session into that same original paired command before fingerprinting.
Native password comparison, original cookie/risk/policy verification and
bounded replacement generation happen before opening Work.

After preparation, the native owner performs material CAS and the kernel's
`ApplyPasswordHashUpgrade` in that Work. `ApplyHashUpgrade` obtains the actual
successor directly from Work and compares the prospective credential reference
and independent security epochs before staging the unchanged session/pre-auth
effects. Both `ApplyHashUpgrade` and direct `Apply` enforce exact original
command custody through the kernel before reading the session payload. A
reconstructed or substituted command poisons Work, even if its binding and
successor epochs match; ignoring that denial cannot commit an earlier upgrade.
It accepts no caller-created successor recipient. Original observation
and authentication times are not renewed; previous credential-bound sessions
are not silently preserved. Propagate every error to coordinator abort.

These are provisional transactional effects, not a credential verifier,
token delivery path or separate password-change command. The native owner must
use its exact original command and repeat final temporal/risk admission.
Recovery keeps its original retained-command semantics without recreating a
bearer. Existing original-command non-upgrade behavior, `Recover`, mapping and
migration history remain unchanged. Full native signin hash-upgrade composition is a
separate consuming implementation, not provided by this seam alone.

## Password-signin session mapping

`PasswordSigninSessionFields(record)` freezes the complete prospective session
into the closed `session.result.*` vocabulary. Include these fields in the
password owner's native command before fingerprinting and reservation, then
bind that exact paired command to the prepared password issuer.
`PasswordSigninSession(command)` restores only that paired profile, including
the actual selected tenant/user without changing anonymous command scope.

The initial profile supports single-factor password authentication, initial
session version one, original remember policy and optional synchronizer state.
Organization, factor, passkey, OTP and credential-continuation profiles deny.
Missing, unknown, wrongly typed or noncanonical owned fields deny. Returned
fields are caller-owned copies; raw password, pre-auth cookie and session bearer
are not scalar fields. Other command fields remain the password owner's duty.

This is structural mapping, not proof of successful password comparison,
pre-auth possession, current owner state or commitment. The native password
owner must compare the selected credential and enforce current policy in the
same transaction as pre-auth/risk consumption, signed original authentication,
session/family issuance and audit/outbox. That atomic consuming composition is
still under development; this mapping alone does not enable login or recovery.

## Continued password-session records

Install `CredentialContinuationMigrationSource{Schema: "session_store",
Version: allocatedVersion}` after `OTPMigrationSource`, using the same migration
runner and a permanent version. It validates populated rows transactionally and
changes no existing payload, receipt or applied migration. Upgrade all relevant
readers and writers before enabling continuation: older binaries reject the new
schemas 5/6, while schemas 1–4 retain their original representation.

Durable records and native command mappings preserve the original password
authentication independently of `EffectiveCredentialVersion()`. Current admission
uses that effective credential reference and the continued credential-authority
epoch; it does not advance user authority or refresh login time, lifetime,
remember policy or freshness. Rotation, metadata updates and revoking other
sessions preserve this linkage. Neither stored metadata nor reconstruction
certifies that a password change committed or substitutes for current owner checks.
Fresh credential-proof issuance rejects continuation, including direct scalar
commands: an old unused login proof cannot select a newer effective credential
version by supplying continuation metadata.

The native session effect below stages selective continuation in the original
password transaction. Its consuming public password service is not yet wired.
Do not implement this with a separate application transaction or refresh a stale
session from current authority.

`PasswordChangeSessionFields(original, disposition, maximum)` freezes that
selection alongside `CredentialReplacementFields` before command reservation.
Choose `PasswordChangePreserveSessions`, `PasswordChangeRevokeOtherSessions`,
or `PasswordChangeRevokeAllSessions` explicitly; zero is invalid. The whole-set
bound is 1–100000 active-state rows, including stale/expired rows, not a page size.
This initial profile admits only single-factor password sources without selected
organization, factor or passkey dimensions. Mapping owns its returned fields and
preserves historical authentication, effective credential linkage, remember and
CSRF custody. It performs no SQL and cannot authorize or complete session effects.
The consuming password-service integration is still pending.

## Native password-change session effect

Install `PasswordChangeMigrationSource` at a permanently allocated version after
the credential-continuation and kernel credential-replacement histories. It adds
command-linked retained session evidence without changing prior migration bytes
or live records. Retain this evidence with command tombstones; session payload
cleanup must not delete it. The existing owner-order index supports the bounded
selection; no new coordinator, journal, background worker or index is introduced.

Construct `NewPasswordChangeEffect(sessionConfig, passwordAdmissionProfile)` at
trusted composition. The exact registered password contributor calls
`effect.Apply(ctx, originalWork, itself, originalCommand)` during its native
feature invocation, before the kernel advances credential epochs. Its constructor
accepts no pool, coordinator or application-written store. The password owner must
verify bearer possession, fresh credential-specific reauthentication, HIBP/reuse
and one-use proof consumption in this same transaction. Propagate every error so
the coordinator aborts; the returned receipt is provisional, not commit evidence.

The effect compares current directory, user, identifier, credential and policy
authority, locks the source/family, and selects all active-state rows for the exact
tenant/user in bytewise keyset pages of 16. The original whole-set cap includes
expired and stale rows; exceeding it rolls back all staged changes. Preservation
continues supported current password rows without changing their session version,
historical authentication, lifetime, activity, remember, lookup or CSRF state.
Stale/expired/family-denied supported rows are revoked, never promoted. Already
revoked rows remain unchanged. Preservation of a different credential or optional
organization/factor/passkey profile denies until those real owners are composed;
revoke-other/all may terminally revoke them without granting authority.

The password owner's `RecoverParticipant` calls
`effect.Recover(ctx, originalRecoveryWork, itself)` and reconciles that result with
its other retained effects. Only the original coordinator can conclude the whole
command outcome. Recovery uses original binding, selection, predecessor, source
and ordered-result commitments rather than live payloads or present authority.
Absent effects support negative recovery only through that coordinator; corrupt
evidence or missing infrastructure remains unknown. It neither authenticates
current access nor reveals a replacement session or bearer.

## Original-session admission mapping

Native feature adapters use `OriginalSessionFields(original)` to bind the
complete original session into their command's `source-session.*` fields.
Select only that namespace and pass it to
`OriginalSessionFromFields(tenant, user, fields)` during execution. Each native
feature must exhaustively validate its other fields; this mapper does not
validate an entire foreign command. Field order is irrelevant, but missing,
duplicate, unknown and noncanonical tagged-union values deny.

Credential and OTP authentication retain distinct complete historical
metadata. Remember policy, exact times/versions, lookup commitment, every
authority dimension and optional CSRF state round-trip through the existing
session-owned codec. Anonymous sessions use a different admission profile and
are rejected. Returned slices are owned copies; these correlated projections
must not be logged or exposed as transport credentials.

Mapping is not authentication or authorization. Native workflows must prove
the separate submitted bearer, compare every current authority under the
original coordinator transaction, and call `RequireSession` with the same
frozen record. Do not replace the record with a newer observation, refresh its
timestamps or accept its metadata as a reauthentication proof.

## Retained sign-in identity

`Repository.ReadPasswordSigninIdentity(ctx, originalBinding)` provides trusted
primary inspection of the original password-signin user/session/family IDs.
It validates the complete original binding and password-specific commitment;
it does not depend on a live session payload. Anonymous commands retain their
original anonymous scope, with the selected user returned separately. Missing
evidence returns `ErrRecordAbsent`; corrupt evidence returns `ErrInvalidRecord`.
The native password workflow must authenticate original cookie possession,
authorize historical disclosure and obtain the sole coordinator's outcome
before exposing these IDs. Inspection alone cannot authenticate, recover a
command, recreate a session or issue credentials. Earlier deadlines win, and
errors and implicit formatting/serialization reveal no retained identity.

`Repository.ReadOTPSigninIdentity(ctx, originalBinding)` reads the original
user/session/family tuple from existing retained issuance evidence. It works
after live payload cleanup, including anonymous flows whose command user is
empty. Every binding field and the original record commitment must match.
Missing evidence returns `ErrRecordAbsent`; corrupt evidence returns
`ErrInvalidRecord`; operational failures are redacted typed identity errors.

This is trusted structural inspection like `Get`, not a public endpoint or
authentication/recovery authority. The native OTP service must first authenticate
original possession, authorize historical disclosure and reconcile the original
consuming command. The tuple contains no bearer, digest or partial session and
cannot enable credential redelivery. Formatting is redacted; implicit JSON/text
export is refused. No new schema or recovery journal is introduced.

## OTP sign-in command mapping

The native OTP owner includes `OTPSigninSessionFields(originalSession)` alongside
its own closed fields before fingerprinting and reserving the consuming command.
`OTPSigninSession(command)` decodes the session-owned `session.result.*` fields
for the exact record-free v1 `identity.otp.signin` operation. Unknown, missing,
wrong-kind or noncanonical owned scalars deny. Other fields must be exhaustively
validated by the OTP owner; this decoder does not validate its entire command.

The mapping retains the selected user independently of an anonymous command's
flow scope, exact nanosecond times and uint64 versions, original remember policy,
the full authority vector and optional synchronizer digest. It contains no raw
code or bearer and grants no authentication, consumption or issuance authority.
Existing proof-based issue/revocation command mappings remain unchanged. Public
sign-in/recovery is still being implemented;
applications must not bridge them with separate transactions or custom stores.

## Native consuming OTP session effect

`NewOTPSigninEffect(Config{...}, OTPAdmissionConfig{...})` creates the immutable
session-owned effect used by the native OTP feature. It performs no IO and owns
no pool or coordinator. Install `OTPIssueMigrationSource{Schema: "session_store",
Version: allocatedVersion}` after the existing issuance and OTP record histories
before enabling this profile. The forward migration extends the purpose
constraint under the migration runner's table lock; old rows and digests remain
unchanged. Allocate a permanent version; do not rewrite applied history.

The registered OTP feature must lend its exact consuming `Work`, original
command and original verified recipient to `Apply`. The OTP owner exhaustively
validates Send/pre-auth/remember custody and finalizes those owners in the same
transaction. The effect checks the checked consuming scope, original authority,
current directory/recipient/authorization, session/family state and database-time
expiry after downstream waits. The complete session, family and issuance
evidence are provisional until the sole coordinator commits; propagate every
error so it aborts. Never register another session command or independently
commit a session. Unsupported organization/factor/passkey profiles deny.

`Recover` accepts only the owning feature's original sealed `RecoveryWork`.
It verifies retained command and selected user/session/family/record commitments
even after live session payload deletion. It returns participant evidence only,
not a session, bearer, current authentication or disclosure permission. Missing
evidence is not a public rollback decision: the coordinator must reconcile all
participants. The native public OTP service remains responsible for code-free,
currently authorized outcome/session-identity recovery; that composition is not
yet available. Applications must not supply that orchestration themselves.

## Explicit OTP session authentication

`NewOTPSessionService(pool, OTPSessionServiceConfig{...})` selects the owned
primary reader for single-factor email/phone OTP sessions. Configure the trusted
deployment, authorization namespace and audience through `OTPAdmissionConfig`;
repository and validation budgets/keys retain `NewSessionService` semantics.
Apply directory, user security, identifier, authorization and OTP-capable session
migrations first, including `OTPMigrationSource` after the installed CSRF history.
The borrowed primary pool remains caller-owned. Construction performs no IO.

The reader checks the exact original verified identifier and verification
versions, active user/directory, all three user security epochs, authorization
epoch and session/family state. It reuses the identity owner's bounded identifier
and recipient queries, requiring the session's actual user, not an address-only
lookup or fabricated password credential. Removing/reassigning the identifier,
blocking the user, changing any authority or revoking the session denies use.
The 128-identifier limit fails closed on incomplete projections. Database failures
never become positive fallback or suppressed successful authentication.

Positive evidence expires within20 seconds of the original read beginning;
later owner reads and response delay cannot restart it. Original OTP continuation
expiry is historical provenance: it does not expire an already issued live
session or renew its authentication time. Organization, MFA and passkey profiles
remain explicitly unsupported. The existing factory stays proof-only; selecting
the OTP factory does not implicitly enable proof credentials or a combined
multi-method deployment profile.

This is authoritative reader composition, not OTP issuance. Public atomic
consumption/Signin and code-free recovery of
original outcome/session identity remain pending. Applications must not fill
those gaps with their own stores or separate transactions.

## Owned cookie logout

Use `NewCookieRevokeOneExecutor(pool, configuration, eligibleCSRFKeys)` with
the exact owned primary `SessionService`. Pass that executor to the existing
`session.NewSignOutService`, then select `session.NewCookieSignOutService`
with the same eligible dedicated keys. Construction performs no IO, copies
mutable configuration and accepts no application store or transaction callback.
Apply the existing kernel/authorization/session/revocation/audit/outbox histories,
including `CSRFMigrationSource`, before selecting this profile.

The strict executor checks original opaque caller custody and selects only the
state-named trusted key. It carries the token in an invocation-private native
participant, never a shared request map, context payload or durable command
field. The command retains only a strict-profile discriminator and the existing
digest-only session projection. Within the original coordinator invocation,
ordered source/target write fences precede `RequireCSRF`, then mutation, audit
and lifecycle commit atomically. Failure audits are retained on denied commands;
successful revocation/lifecycle effects roll back. Original primary deadlines
are not refreshed. Concurrent calls do not share ephemeral token custody.

`ExecuteRevokeOneWithCSRF` is the explicit strict dispatch. Direct
`ExecuteRevokeOne` on this strict executor always denies. The existing
`NewRevokeOneExecutor` remains available for trusted direct calls and rejects
CSRF-bearing requests before reservation rather than silently downgrading them.
Historical recovery returns only the original outcome under current access
policy; it cannot issue a credential, renew authority or authorize execution.

HTTP must still enforce trusted origin, canonical cookie extraction and one
CSRF channel before invoking the strict service. These endpoint/browser
boundaries and full release qualification remain unfinished.

## Transactional synchronizer-token admission

`RequireCSRF` composes the core token/key check with `RequireSession` on the
borrowed original primary transaction. It compares the complete frozen record,
locks the active session/family until transaction closure, and checks database
time after locking. Legacy tokenless state cannot bypass token protection.
The helper creates no transaction, validity lease or authorization decision.

Trusted native participants must abort or poison the owner transaction on every
error, preserve directory/credential/policy checks, and recheck temporal validity
at their existing terminal boundary. Acquire any session write fence before
admission; do not upgrade shared locks afterwards. Never call through a replica,
cache or autocommit pool. HTTP token-channel/origin checks, pre-auth one-time
state and integration into protected native executors remain required separately.

## OTP authentication storage

Apply `OTPMigrationSource{Schema: "session_store", Version: allocatedVersion}`
after `CSRFMigrationSource`, in the same owned migration history, before writing
OTP sessions. Upgrade all relevant readers and writers first: older binaries
fail closed on the new schema-3 (OTP) and schema-4 (OTP plus CSRF) records.
The migration validates populated rows transactionally without rewriting
historical schema-1/2 payloads or recovery hashes. It has no destructive down SQL.
Constraint replacement takes an exclusive table lock and validates all stored
rows. Use the migration runner's bounded context and an appropriate maintenance
window for a large installation; local fixture success is not production-scale
lock-duration evidence. A failed or canceled migration rolls back both changes.

Durable reconstruction retains the original Send/sign-in, challenge/attempt,
identifier/verification versions, authentication time and continuation expiry.
It also preserves Remember, the complete authority vector and any synchronizer
binding. The continuation expiry is historical, not the session expiry or a
renewable authoritative validity lease. Reconstruction cannot authenticate an
OTP, manufacture a proof or grant permission. Native OTP session issuance and
the opt-in primary authentication reader remain separate implementation work;
installing this migration does not enable them.

## Synchronizer CSRF storage

Apply `CSRFMigrationSource{Schema: "session_store", Version: allocatedVersion}`
after the base session migration through the existing migrations Runner. It
extends the record constraint in place without changing historical migration
checksums, tokenless record bytes or retained command identities. Upgrade all
relevant readers/writers before opting into native CSRF issuance: old binaries
can still handle tokenless schema-1 records but reject CSRF-bearing schema-2
records. Rollback requires disabling new issuance, not dropping state.

Stored records and closed native command projections preserve the separate
`Session.CSRFState()` alongside the original `Session.Bindings()`. Rotation
preserves exact source/successor state; bearer rotation and version-changing
metadata invalidation clear it according to the core lifecycle. Retained
digest-only history is not current authorization. `RequireSession` fences and
compares the complete active primary record, including this state; it does not
validate a browser CSRF token or its Origin. Protected-work token enforcement,
OTP custody and HTTP composition remain in development. Do not substitute a
cached structural token check for those missing boundaries.

## Original-session admission expectations

`IdentifierAdmissionConfig.Validate` checks the configured owner profile.
`OriginalSessionAdmission` derives exact directory, credential and user
authorization expectations from a frozen session and command binding. It
preserves original keys and epochs, rejects unsupported optional authority
dimensions and performs no IO. It neither authenticates a bearer nor grants
permission. Native participants must separately authenticate possession, use
primary `RequireSession` checks, and recheck original freshness after waits.

### Canonical pre-auth state

Install `PreAuthMigrationSource` after the base session schema in the single
migration history. It adds a separate canonical private `bytea` record and
digest index, retaining the complete original flow binding and nanosecond UTC
timeline. No raw cookie or credential proof is stored. Existing session rows,
positional inserts and migration checksums are unchanged.

`InsertPreAuth`, `RequirePreAuth`, `ReservePreAuth` and `FinalizePreAuth` are
bounded native participant operations on the **original primary transaction**,
not public endpoints or a new command engine. The owning platform participant
must derive `PreAuthUse` from its live sealed coordinator handle, fence current
policy/scope and abort or poison the unit on every error. Never pass autocommit
pools, replicas, client-supplied custody or consumer-written workflow callbacks.
The borrowed query/write shape also accepts generation-bound `WorkRows`.

Admission locks and compares the exact private record, indexed scope/version,
cookie commitment and original exclusive expiry; primary time is sampled after
locking. Reservation has one winner and binds exact command/fingerprint/
generation. Finalization checks that owner and original deadline again, then
consumes in the same transaction as protected session/link effects. Rollback
leaves both effects uncommitted. Terminal replay denies; receipt replay belongs
to the sole kernel journal, not these operations. No path automatically releases
reserved state or renews its validity after timeout, retry or connection loss.

`ReadPreAuth` restores the exact original record and checks its physical indexes;
it does not authenticate a flow or admit expired, reserved or terminal state.
`RequireReservedPreAuth` locks and checks the exact reserved owner for apply.
`RebindPreAuth` changes only the generation from an exact predecessor to its
immediate successor, using the coordinator's live sealed takeover invocation.
Neither elapsed time nor connection failure authorizes transfer. The original
deadline still applies, and rollback restores predecessor ownership. These
operations must use the same borrowed primary transaction as other participants.

These native operations do not authenticate a user, expose a cookie or constitute
complete usable initiation. Owned issuance/recovery, proven-noncommit reservation
coordination and OTP/other workflow registration remain under development.
The internal initiation command vocabulary freezes every original record field
as closed typed scalars, including nanosecond UTC times and resolved remember
policy. It binds the anonymous-flow namespace separately from the service actor
and rejects inconsistent command/record scope. Structural decoding does not
authenticate the actor, authorize initiation or persist/recover a command.

Compose `NewPreAuthIssueExecutor` with a borrowed PRIMARY pool, current service
authorization, bounded clock/coordinator configuration and one exact trusted
action/origin/callback/policy profile. Empty callback explicitly disables
redirection. Actor identity is fixed at configuration, not selected by a request.
`session.PreAuthIssueCommand` carries the server-prepared original flow and stable
command identity; the adapter alias retains the same storage-neutral value.
Never decode it directly from HTTP input or provide a consumer-written store.

Install `PreAuthIssueMigrationSource` at a later permanent history slot after
the kernel and initial pre-auth migration. It creates retained native effect
evidence, not another journal; it has no live-flow FK and a permanent per-tenant
flow-ID uniqueness fence. Retain that evidence with the original command
history. Payload retirement cannot prove rollback or permit ID resurrection.
Existing rows and applied migration checksums stay unchanged; no down migration
or automatic evidence pruning is provided.

`ExecutePreAuthIssue` applies current configured service policy before reserving
the exact original command. Original flow, native evidence, audit, lifecycle and
receipt commit together. Primary locked time rejects expired originals. Exact
replay returns historical metadata without reissuing; changed intent conflicts.
`ExecutePreAuthIssuance` runs that same owned path and additionally returns
`session.PreAuthIssueExecution`: only the acquired coordinator reservation
clears `Replayed`. Pending observations, conflict, terminal replay and
pre-reservation failure cannot claim original execution. Concurrent identical
commands have one newly committed result, even when other callers observe the
same historical committed receipt. This metadata contains no cookie and alone
is not delivery authority; core issuance must validate the exact receipt,
original expiry and error/cancellation before revealing a credential.
`RecoverPreAuthIssue` observes/reconciles complete original anonymous-flow scope
under current configured service policy, without a cookie, new reservation or
lease renewal. Unknown requires recovery, not a new command. Detached kernel
cleanup retains its own bounded budget and may outlive the caller deadline.
These native methods do not generate entropy or deliver cookies. Compose them
with `session.NewPreAuthIssuer` to own original ID/nonce/cookie preparation and
commit-gated reveal-once delivery metadata. Use matching trusted profile and a
dedicated retained flow key; pass the resolved final-session remember choice
unchanged. Core cookies stay within original 1..10-minute flow TTL for both
choices. Restart recovery returns only exact command outcome, never a credential
or caller-reconstructed flow payload. Native OTP continuation registration and
complete browser login remain pending.
Retain original digest keys and terminal records until the owned retention and
recovery policies authorize retirement; no cleanup/down migration is provided.

Install `PreAuthReleaseMigrationSource` in a later allocated history slot after
`PreAuthMigrationSource`. This forward transactional constraint replacement adds
distinct `released` terminal state, scans existing rows and requires a bounded
maintenance window. Existing issued, reserved and consumed rows stay unchanged.
Never rewrite the applied initial migration or renumber either history slot.

`ReleasePreAuth` accepts only the registered owner's live sealed
`identitypostgres.OTPReleaseWork`. The existing coordinator supplies rollback
or unanimous primary noncommit authority; neither scalar custody nor timeout
does. Release preserves the original record and terminalizes the exact previous
reservation, even after original flow expiry. It permits the unchanged rollback
generation or coordinator's immediate recovery successor only. It does not
reissue/reactivate a flow, reveal a cookie, authenticate a user or register a
native OTP workflow. The callback must abort on any error and cannot retain its
handle. Receipt replay and ambiguity remain the sole coordinator's responsibility.

### Owned self-session device labels

Install `UpdateMigrationSource{Schema: "session_store", Version: allocatedSlot}`
after the existing kernel/session migrations, through the single migration
runner. This additive install creates separate metadata/evidence tables;
existing positional session inserts and the closed session codec stay unchanged.
Listing also requires this migration. The transactional install needs an
explicit deployment window; never renumber an applied migration.

Compose `NewUpdateExecutor(pool, UpdateExecutorConfig{Execution: nativeConfig,
Sessions: authenticatingReader})` with `session.NewSessionUpdater`. The exact
reader must have authenticated the original cookie/bearer. Prepare selects
that session's exact current version and a label of at most128 UTF-8 bytes
without control runes; empty clears it. A label is untrusted display text,
not device trust, a credential, a factor or authorization. Escape it at rendering.

Native execution checks current policy and every supported primary owner,
locks the source, and commits label plus session/vector version, audit,
lifecycle and receipt in the existing kernel transaction. It preserves bearer,
activity, authentication, remember choice and all other authority. Exact retry
observes the historical successor without applying again; changed intent
conflicts. Original admission's exclusive deadline bounds the entire mutation.
Errors never return apparent successful display metadata; commit ambiguity
requires recovery rather than guessing rollback or issuing a different command.

`RecoverUpdate` retains original request custody; `RecoverUpdateCommand`
supports process restart with the complete safe original scope and a trusted
current caller. Both observe historical outcomes under current access policy,
never return a label/session, renew authentication, mutate metadata or reserve
missing commands. Terminal evidence survives payload deletion and retains only
the label digest; current label plaintext cascades with session deletion.
Retained session records share the existing command-evidence retention policy;
they are not a current authorization source or a second journal. General
privacy retention/anonymization and remaining session profiles are still pending.

Pool, reader, authorization and clock dependencies are borrowed, immutable and
must remain alive until calls finish. Use PRIMARY only. Calls are concurrency
safe, use bounded contexts and start no goroutines; detached kernel cleanup
retains its documented independent bounded budget. HTTP routing, origin/CSRF
policy and request key parsing belong to the explicit HTTP composition.

### Owned source-bound rotation

Compose `NewRotationExecutor(pool, RotationExecutorConfig{Execution: nativeConfig,
Sessions: authenticatingReader})` with the core `session.NewSessionRotator`.
The reader must be the exact trusted service that authenticated the original
cookie/bearer. Core preparation privately generates the successor; native
execution compares current primary owners, locks the original source and commits
its one-version successor, old-digest retirement, required audit/lifecycle and
command receipt together. The absolute caller deadline also bounds commit.
Rotation preserves original issuance/authentication/remember policy, family and
every non-session authority. It cannot repair or renew a stale authority vector.

Install `RotationMigrationSource{Schema: schema, Version: permanentVersion}`
after the existing base/issuance/revocation history, through the sole migration
runner. Its transaction takes a session-table write lock, backfills one token
claim per populated session and installs invoker-only writer guards. Budget the
complete populated installation in a reviewed maintenance window; this is not
an online chunked backfill. Existing session payloads and older checksums remain
unchanged. Guards prevent digest reassignment and irreversible retired-digest
resurrection even through older binaries/direct writers. Deleting a payload also
terminally retires its digest. Runtime
writer roles must not have `TRUNCATE`, trigger-disable or schema-alter privileges;
these guards are not a security boundary against a privileged database owner.
No destructive downgrade
or retirement/evidence deletion is supported. Terminal claims and retained
rotation metadata outlive prunable live payloads; privacy retention obligations
remain part of the unfinished full lifecycle implementation.

`ExecuteRotation` accepts only the original opaque request. `MapRotationRequest`
is an exact structural projection, not substitute authentication; raw
`MapCommand`/`Apply` rotation remains forbidden because it lacks that admission.
`RecoverRotation` uses current result-access policy and exact retained complete
intent, including original deadline and transport. It works without a live old
session/admission, never reserves a missing command or replays effects, and
returns historical receipt/session metadata only. Corrupt or missing ancillary
evidence fails closed without erasing known commitment. Core replay/recovery
never deliver a token/cookie; only a new error-free commit can reveal once.

After process restart, `RecoverRotationCommand(ctx, exactRecoveryQuery,
trustedCurrentCaller)` returns the exact historical command/version/audit
receipt without the original request, admission, reader instance or bearer.
Reconstruct the public reader/executor configuration; do not manufacture a new
rotation request. Supply every original safe query scope field and an
independently authenticated current caller. Current policy governs disclosure.
Missing/denied queries return no history and never reserve a command. Live
pending does not renew its lease; expired pending reconciles through the sole
kernel owner and frozen participants. Missing/conflicting evidence cannot prove
rollback. Pruning live payloads does not erase committed receipts. No session,
credential, current authority or permission to retry is returned.

Retired-token denial and explicitly composed family-replay revocation are
implemented. Selected organization/factor/passkey
profiles, complete cleanup/privacy handling and whole-unit release gates remain
unfinished; ordinary rotation is not a claim of full session lifecycle parity.

### Protective retired-token replay checking

Explicitly compose `NewFamilyReplayGuard(pool, FamilyReplayGuardConfig{Execution:
nativeConfig, LookupKeys: retainedValidationKeys, ActorID: trustedServiceActor})`.
Use the same one to four retained HMAC keys as the primary reader and a configured
service-account actor whose current policy permits protective family revocation.
Install the existing family, rotation, kernel, audit and lifecycle migrations;
the guard adds no tables or journal. Configuration borrows the primary pool and
policy dependencies and starts no goroutines.

`CheckReplay(ctx, FamilyReplayInput{TenantID: tenant, Token: parsedToken,
CommandID: stableID, CorrelationID: correlation})` derives the owner and family
only from exact primary retired-token lineage. The caller cannot choose them.
It authenticates nobody: the operation is a denial-only protective mutation.
Current service policy, original absolute expiry, locked family-version CAS,
protected service audit and lifecycle effects govern the sole transaction.
Concurrent distinct commands have one winner; exact retries preserve the
original receipt and changed intent cannot borrow a previous success. Blocking
the human owner does not disable this protective action. All retained keys,
input tokens and guard configuration deny JSON export and diagnostic traversal.

A zero result with nil error means no eligible replay was observed. Active,
absent, foreign-tenant and absolutely expired tokens reserve no command. This
does **not** authenticate a token or prove that an earlier command rolled back.
Original idle expiry is not the retention cutoff: rotation extends idle activity
while preserving absolute lifetime. Application-clock/policy latency cannot
extend the primary expiry or final commit budget.

Keep the returned safe binding whenever the outcome is uncertain. After restart
or absolute token expiry, `RecoverReplayCommand(ctx, exactRecoveryQuery,
trustedCurrentServiceCaller)` returns only historical command/version/audit
metadata under current access policy, without needing the token. Live pending
does not renew its lease; expired pending uses existing participant recovery.
Missing or inconsistent evidence remains uncertain and never authorizes retry.

Ordinary `SessionService.Get` remains read-only and still denies retired tokens.
The explicitly enabled transport owner must invoke this guard on presented
credentials and enforce origin/CSRF and source/transport policy before mutation.
This is not automatic HTTP wiring, an authentication endpoint or a new authority
cache; these transport/composition requirements remain separate platform work.

### Bounded expiry cleanup

Install `CleanupMigrationSource{Schema: schema, Version: permanentVersion}` after
the complete base/rotation history. It adds an owner/expiry index and retained
result evidence without changing populated records or earlier checksums. The
transactional index build can block writes; budget its installation explicitly.
Do not give runtime roles trigger-disable, schema-alter or `TRUNCATE` privileges.
The existing rotation deletion trigger is required to terminally retire digests.

`NewCleanupService(pool, CleanupServiceConfig{Execution: nativeConfig,
ActorID: trustedServiceActor, MaximumBatch: batchLimit})` enables maintenance
under the configured current service policy. `MaximumBatch` is 1..10000; the
service borrows the existing primary/kernel/audit/lifecycle dependencies and
starts no goroutine. Default repositories/readers expose no cleanup operation.

Call `CleanupExpired(ctx, CleanupCommand{TenantID: tenant, UserID: owner,
CommandID: stableID, CorrelationID: correlation, Limit: limit})` for an explicit
owner partition. Current policy must permit that configured service actor to
maintain the selected owner; input cannot select the actor or clock. A limit
above the configured maximum or any invalid scope fails before reservation.
This is maintenance, not an authentication endpoint or a global scheduler.
Reference-server scheduling and broader privacy erasure remain separate work.

One existing-kernel transaction selects at most `Limit` indexed expired
candidates using database time, locks and rechecks their current expiry, skips
busy rows, and prunes live payloads with terminal digest retirement. It does
not scan past locked candidates to fill a deletion quota. A concurrent refresh
survives; other tenants/users and active payloads are untouched. Natural expiry
does not increment session/family/user authority. Retained issuance, rotation,
revocation, proof-use and command records are never removed by this operation.

The same transaction records historical count/lag evidence, service audit
`identity.session.expire` with reason `completed`, and `session.expired.v1`
maintenance lifecycle metadata. The record-free receipt has zero before/after
versions: it is not a new session authority. Audit failure rolls back deletion,
tombstone changes and all effects. A zero-row pass is a committed observation,
not proof that no locked or subsequently expired rows exist.

`CleanupResult` includes the command outcome and, only after verified success,
`Deleted`, `ObservedAt` and `RemainingLag` for that partition. Lag includes
locked expired rows, saturates at 8760 hours, and describes the database-time
observation—not the live backlog at the time a caller reads a historical result.
Exact retries return the original count/lag without deleting another batch;
changed scope/correlation/limit under the same ID conflicts. New batches need
new IDs. Retain safe command scope for `RecoverCleanupCommand` after restart or
uncertain acknowledgement. Current trusted service access policy governs
disclosure; live leases are not renewed and expired pending uses existing
frozen-participant recovery. Missing/corrupt evidence never proves rollback or
authorizes retry. An ancillary evidence error preserves known commitment but
returns no invented counts or timestamps.

### Owned session listing

`NewListService(pool, ListServiceConfig{Sessions: primaryConfig,
Listing: session.ListConfig{Authorization: policy, PolicyRevision: revision,
MaximumDuration: budget}})` composes the real primary authentication reader,
existing authorization service and one bounded joined page query. No application
domain store is required. Its explicit repository budget cannot exceed the
whole listing budget. Native authentication retains its single-factor profile;
unsupported authority dimensions deny rather than being ignored.

Apply `ListMigrationSource{Schema: schema, Version: permanentVersion}` after
the base session migration in the sole composition history. The new
tenant/user/audience/session index supports bytewise exclusive keyset traversal.
Its transactional build can block writes: size and schedule populated installs
explicitly. It neither rewrites records nor changes historical SQL/checksums.

Pass tenant, actual cookie/bearer credential, safe correlation, `Limit` 1..100
and optional cursor/`IncludeInactive` to `List`. Current user/audience scope is
derived from authentication, not request identifiers. The primary reader scans
at most `Limit+1` raw rows in one statement; the service returns at most `Limit`
safe device projections. Filtering can yield an empty page with a continuation.
Labels remain empty until the owned metadata writer is implemented. Revoked
family/session and exact expiry metadata are not live authentication authority.
Cancellation, corrupt records, current-policy denial and primary outage return
no partial page or stale fallback. The pool is borrowed until calls finish.

### Owned self-logout

`NewSignOutService(pool, SignOutServiceConfig{Execution: execution,
Validation: validation, Cookie: cookie, MaximumDuration: budget})` composes
the primary reader, native executor and core service without application stores.
Set `validation.Clock` to nil: `execution.Clock` owns both phases. Its schema,
authority profile and policy are shared; existing validation key/audience and
read-budget rules still apply. Install the selected kernel, authorization,
session/issuance, revocation, audit and outbox migrations before calls. Final
signin proof issuance is not a mandatory dependency of ordinary logout.

Pass a canonical host-generated command ID, correlation, tenant and explicit
cookie/bearer transport to `SignOut`; the credential may be absent. Successful
cookie results provide secure deletion metadata, not another token. Never clear
transport state on an error or unknown outcome. Retain the returned recovery
scope and use `RevokeOneExecutor.RecoverRevokeOneCommand` with current result
access policy before attempting a replacement for an ambiguous command.
The native executor can be reconstructed with the same pool/execution profile
and an owned `NewSessionService` reader; historical recovery never requires
the revoked credential or its expired private admission. The HTTP owner must
still enforce canonical parsing, mixed-source rejection and origin/CSRF policy.
Full session lifecycle and release verification remain pending.

Experimental Go 1.27 durable adapter. Forward-only migrations and bounded
primary `Get`/digest `Lookup` reads preserve complete native session records,
resolved lifetime limits, original nanosecond timelines, full uint64 authority
versions and revocation tombstones. Native family revocation now participates
in the sole identity PostgreSQL coordinator. Explicitly configured native
authenticated issuance now checks current owners and atomically stages records
and original proof use. Owned authenticated cookie issuance now composes real
audit/outbox effects with the core's commit-gated token custody.
**General bearer issuance, browser-container policy,
privacy cleanup, devices and complete session profiles remain unfinished.
Single-factor stateful opaque validation now has owned primary composition;
this is not yet a complete login service.**

## Bulk native revocation

The configured `NewRepositoryWithIssueAdmission` contributor registers
revoke-other and revoke-all. Install `RevokeSetMigrationSource{Schema: schema,
Version: permanentVersion}` after the base history, alongside the kernel,
issuance and selected audit/outbox migrations. This forward migration retains
command result counts and adds an active-owner selection index. Existing
records and historical checksums are unchanged; the transactional index build
can block writes and requires explicit populated-deployment scheduling.

`NewSetRevocationService(pool, SetRevocationServiceConfig{Execution: execution,
Validation: validation, MaximumSessions: maximum, MaximumDuration: budget})`
composes credential authentication, current policy and native atomic mutation.
Set `validation.Clock` to nil: `execution.Clock` owns both phases. It starts no
goroutines and accepts no application domain stores or transaction callbacks.
Use `RevokeOther`/`RevokeAll` with actual tenant-bound cookie/bearer credentials,
host command/correlation IDs and, for all, explicit source disposition and exact
positive user-authority CAS. Final-signin issuance is not a bootstrap dependency.

`MapRevokeSetRequest` structurally maps an original opaque core request; it
does not authenticate or authorize execution. Raw `MapCommand` cannot supply
the source-admission deadline. `NewRevokeSetExecutor` accepts the exact trusted
reader that prepared requests and the same execution profile. Native deadline
conversion uses primary time and cannot extend admission during audit/outbox
persistence. Do not substitute an application transaction or caller-ID workflow.

`RecoverRevokeSetCommand` on a reconstructed executor takes the exact original
safe recovery scope plus currently trusted result-access policy context. It
returns historical command metadata and retained count/version/disposition,
never a bearer or permission to execute. Missing/foreign scope cannot reserve
a command. Missing/corrupt retained metadata produces an error and zero success
metadata, preserving a command commitment already proven by the journal.
Payload pruning does not remove native evidence. Recover the original command
rather than minting another ID after an unknown outcome or failed disclosure.

The native effect selects all active-state sessions for the authenticated user
within the tenant, across audiences, in bounded bytewise keyset chunks. The
configured maximum counts target rows, not pages: an excess row denies the
entire mutation rather than truncating it. Expired/family-denied active-state
records are also tombstoned. Corrupt records or current-owner denial abort the
complete set. The kernel's existing tenant transaction mutex serializes owned
issuance and mutation; there is no second lock or invalidation authority.

Revoke-other always preserves the source. Revoke-all has explicit source
disposition. A preserved source retains bearer, lifetime, authentication and
user authority, advancing only its session/snapshot version. Included sources
and targets retain their original immutable payload behind terminal tombstones.
Required audit, lifecycle and retained count/disposition evidence share the
coordinator's sole transaction and rollback. Original admission remains bounded
by the earlier freshness/expiry deadline; native checks cannot renew it.
Retained scoped recovery evidence survives session payload cleanup, but corrupt
or conflicting evidence never proves success or authorizes a new mutation.

## Single-session native revocation

The explicitly configured `NewRepositoryWithIssueAdmission` contributor also
supports the closed `session.NewRevokeOneCommand` variant. Install the additive
`RevokeOneMigrationSource` at a permanent version after the family history,
merging it with issuance and kernel migrations in the existing single history.
It does not rewrite historical SQL or populated session records.

Mapping retains the complete original record, policy and authority vector.
The sole coordinator checks the exact registered invocation; the adapter locks
current directory, credential, authorization, target and family state before
mutating only the target. The physical record/version remains its original
snapshot; `session_revocations` retains the terminal version successor and
command binding independently of payload cleanup. Audit and lifecycle effects
share that transaction. Missing infrastructure and ambiguous/corrupt recovery
evidence never prove noncommit or authorize another transition.

This currently supports active single-factor self-service targets with the
configured owner profile, not anonymous/factor/passkey or administrative
variants. Construction and structural mapping do not authenticate a caller:
the owned execution service supplies opaque current caller admission and policy
before reservation. Public idempotent signout and revoked
or expired-target management remain required work. No bearer is issued here.

`NewRevokeOneExecutor(pool, RevokeOneExecutorConfig{Execution: ..., Sessions:
reader})` owns the kernel/native/audit/outbox composition. `reader` is the exact
trusted service that returned the positive caller result. The existing execution
configuration supplies deployment profile, bounded clock, policy revisions and
coordinator keys; final-signin proof composition is not required for revocation.
Use `reader.PrepareRevokeOne(caller, command)` and pass that original opaque
request to `ExecuteRevokeOne`. Structural `MapRevokeOneRequest` is not admission.

The mapped intent retains both complete caller and target records and the
unchanged original deadline. The executor checks original custody/current
policy before reservation, locks current source/target owners on the primary,
orders both session locks deterministically, and checks original admission
before commit. The transaction/commit budget cannot outlive the remaining
original validity. Primary database time caps a monotonic deadline anchored
before the clock query, so application-clock skew and slow audit/outbox work
cannot extend that validity. Copies and retries do not restart that window. Exact replay
returns the original retained receipt without another mutation or effect.
`RecoverRevokeOneCommand` observes historical scoped metadata under current
result-access policy, including after reconstructed executor composition; it
does not reconstruct a bearer, authenticate the caller or authorize execution.
Absent, expired and already-revoked public logout semantics remain unfinished.

## Owned stateful authentication

`NewSessionService(pool, SessionServiceConfig{Repository: ..., Profile: ...,
Validation: ...})` returns the core service with the owned primary reader.
Select `session.StorageStatefulOpaque`, audience, retained digest keys, trusted
clock and explicit bounded read/clock budgets. The profile is the same trusted
single-factor deployment/method/credential-owner profile as native admission.
Repository's budget cannot exceed validation's. Construction has no IO.

`Get` performs exact tenant/digest lookup across at most four retained key
versions and denies ambiguity. It checks live session/family tombstones, exact
owner-derived scope keys, directory status/epochs, user security and identifier
epochs, exact credential ID/kind/owner/version/expiry and current authorization
epoch through public owner APIs. It never substitutes aggregate CAS versions,
original authentication metadata or a stored record for current authority.
Identifier projection uses its owner's finite 128-record bound; incomplete or
corrupt owner state denies rather than becoming a partial positive result.

The earliest read-start sample precedes token lookup. Evidence lasts at most
20 seconds from that sample, capped by credential and session expiry and the
core uncertainty deduction. Copies and delayed responses do not renew it.
Missing infrastructure fails closed; there is no stale cache fallback.
Authentication does not grant authorization, update activity, refresh a token,
consume a proof or perform any durable mutation. Reuse requires the core
result's private-custody `ValidateAt` with trusted current time.

Apply kernel directory/status/identifier/credential, authorization-authority
and session migrations first; this constructor does not bootstrap them.
Borrow the primary pool until all calls finish. The service starts no
goroutines and supports concurrent calls. Organization, factor, passkey and
anonymous profiles explicitly deny until their separate owners compose.
Browser credential extraction, CSRF and container policy remain HTTP/core
responsibilities. Automatic transport replay-guard wiring, remaining profiles and release gates
remain pending.

## Adoption and API

`NewRepository(pool, Config{Schema: "identity_session", MaximumDuration:
time.Second})` accepts the caller-owned `go-postgres` PRIMARY pool. It performs
no IO. Apply migrations first and close the pool only after all calls finish.

`MigrationSource{Schema: "identity_session", Version: 10}` returns one atomic,
forward-only install. The version is an example: the platform composition owns
its permanent allocation in the single `go-migrations` history. Compose this
source with the installed kernel history and run the owned migrations Runner
and PostgreSQL backend. The kernel's `identity.users` table is a prerequisite.
Never use independent competing ledgers, renumber applied versions or silently
adopt an occupied schema. `public`, `identity`, `information_schema`, `pg_*`
and noncanonical schema names are rejected. There is no destructive down SQL.

To enable native revocation, use
`RevocationMigrationSource{Base: MigrationSource{Schema: "identity_session", Version: 10}, Version: 11}`
with an additional permanent version greater than the base in the same history. This
forward-only migration adds retained mutation bindings without changing the
original session install or live records. The original two-field
`MigrationSource` remains unchanged and returns only the read-only install.
Register the repository alongside the owned kernel, audit and outbox
contributors. Its descriptor is `identity.session.store` version 1 and it
declares `identity.session.revoke-family`; the default constructor does not
register issuance.

## Protected native issuance

`NewRepositoryWithIssueAdmission(pool, config, IssueAdmissionConfig{...})`
freezes a trusted single-factor self-service profile: deployment authority,
authorization namespace, audience, authentication method and credential
kind/owner. Configure the coordinator's trusted final-authentication authority
and namespace separately. Neither profile comes from request input.
Organization, factor and passkey profiles deny until their native owners are
composed; no applicable authority is dropped from the original record.

Compose `IssueMigrationSource{Base: RevocationMigrationSource{...}, Version: ...}`
with kernel proof-use, directory, status/credential and authorization-authority
migrations in one ordered permanent history. Issuance evidence survives session
payload cleanup and cannot be silently pruned during command reconciliation.

Map the closed `session.SessionCommand` with `MapCommand`, then use the
coordinator's `PrepareAuthenticatedCommandPlan`/`ReserveAuthenticatedCommand`
with the same original opaque final-authentication proof. Ordinary reservation
rejects issuance even when its structural command is valid. The adapter compares
every original proof field and complete snapshot, locks current native owners,
preserves original family issuance time and denies absent/stale/revoked families.
A genuinely new family requires version1; concurrent uniqueness waits cannot
overwrite a retained family or reset its authority. The same Work persists
family, session, proof use, native issuance evidence, audit and lifecycle.
Final comparison includes the complete stored session and primary expiry.

No raw bearer is generated, stored or returned by these adapter methods.
Replay returns retained command metadata, not another credential. This native
path is a prerequisite for the core issuer's reveal-once bearer custody and
container policy, not a replacement for that unfinished service. Integration
checks use the production session repository and real PostgreSQL; test-owned
audit/outbox contributors prove transaction atomicity, not complete production
delivery composition. Full coverage, mutation and release gates remain pending.

### Owned authenticated cookie issuance

`NewIssueExecutor(pool, IssueExecutorConfig{...})` owns composition of the native
repository, kernel coordinator and production audit/outbox contributors. Supply
the primary pool, `Repository` configuration, trusted `Profile`, retained
`Coordinator` keys/final-authentication namespace, existing `Authorization`
service, trusted `Clock`, `PolicyID`, positive `PolicyVersion` and
`AuditRetentionVersion`. Execution work uses the coordinator's 1ms..30s
maximum duration or any earlier caller deadline. Synchronous detached kernel
cleanup may outlive that deadline; each cleanup phase has its own bounded
coordinator budget, rather than one whole-call return deadline. Dependencies are
borrowed, immutable and concurrency-safe; construction performs no IO and
never runs migrations. Apply the kernel proof-use, directory/status/credential,
authorization-authority, native session/issuance, audit and generic/identity
outbox migrations first. Missing storage fails closed.

Pass this executor to `session.NewSessionIssuer` with the **same** trusted
authenticator, independent session digest key, explicit cookie policy, token
size and duration. The core generates and privately retains the original token
in `Prepare`; the adapter receives only its opaque `IssueRequest` and exact
digest-bound native record. Applications supply neither stores, transactions,
registries nor workflow orchestration. Current self-service identity and policy
are derived from the original authenticated command, not request-selected
decision attributes. Issuance currently supports the configured single-factor
profile; organization, factor, passkey and anonymous variants remain unavailable.

The executor checks current access before reservation. The native participant
checks all selected authority dimensions under the protected transaction before
effects and again before commit. Session, family, proof consumption, retained
issuance evidence, audit and lifecycle notification commit together. Core
delivery reveals the token only after a new exact committed result; cookie
attributes have an empty value until an explicitly authorized transport combines
them with that token. `ExecuteIssue` historical replay and `RecoverIssue` never
deliver credentials. Recovery compares complete original input and current
access, uses only the existing primary journal/recovery owner and cannot reserve
missing input, renew live leases or refresh original proof authority.

Retain the original safe request/proof for exact-input recovery and fingerprint
keys/policy versions while an outcome may require reconciliation. Never prepare
a new token to retry an uncertain command. After a process restart,
`RecoverIssueCommand(ctx, exactRecoveryQuery, trustedCurrentCaller)` returns
historical command metadata without original proof or token custody. Supply all
original safe scope fields and the independently authenticated current caller,
not request-selected actor/tenant overrides. Current policy governs disclosure.
Missing/denied commands are indistinguishable; recovery never reserves them.
Live pending remains observational; expired pending uses the kernel's frozen
participant reconciliation, and missing/conflicting evidence remains unresolved.
Successful reconciliation does not return a session or any bearer/cookie and
does not authorize retrying issuance. Structural
historical sessions are not current authentication evidence. Browser maximum
session/container policy, automatic transport replay-guard wiring and complete login
composition remain required future work. Real PostgreSQL integration covers the
owned executor and production audit/outbox path, unlike the contributor-only
transaction fixture above. Full release coverage/mutation gates remain pending.

`MapCommand(session.NewRevokeFamilyCommand(...))` maps the closed native
command's complete expected-version intent. Prepare a native feature plan with
subject `session_family`, security action `identity.session.revoke`, lifecycle
`session_family.revoked.v1`, exact expected/successor versions and selected
standard (or privileged protected) retention. The coordinator checks registry,
budgets, digests and the native owner's mandatory declarations before reserving.
Only its `ApplyFeature` invokes the registered repository. Direct `Apply` on a
borrowed, foreign or returned Work fails; the constructor accepts no coordinator,
transaction or registry. Authorization belongs to the owning service, before
reservation. This trusted adapter is not a public revocation endpoint.

Revocation changes exactly one owned active family's tombstone and version,
never its sessions' original snapshots. Missing, stale, already-revoked and
foreign-owner targets return redacted conflict without disclosing foreign
existence. Exact same-command replay is handled before mutation by the sole
coordinator. Required audit/lifecycle effects and retained mutation evidence
commit with the transition. Errors require coordinator Abort; a failed commit
stays Unknown until primary recovery proves its original result. Recovery reads
retained exact command bindings, never infers success from current family state.
No adapter cleanup prunes those bindings; their journal FK prevents premature
command retirement. Retention/privacy retirement remains a later owned policy
boundary, not permission to treat pruned evidence as noncommit.

`Get(ctx, tenant, sessionID)` and `Lookup(ctx, tenant, session.TokenDigest)`
return a structural `StoredSession`. Both use one joined primary query and a
finite read budget. Earlier deadlines win; cancellation, deadline, absence and
unavailability are redacted. No SQL diagnostic or partial record escapes.

`RequireSession(ctx, work, Config{Schema: "identity_session", MaximumDuration:
time.Second}, frozenSession)` borrows the owning transaction's query cursor
(`identitypostgres.Work` or a trusted primary `pgx.Tx`). Freeze the exact original
session in the owning command before reservation. The native query compares
physical indexes, complete stored snapshot, authentication linkage and lifetime
without replacing any field. It requires active session/family state and exact
versions, takes share locks on both, and checks database time **after** acquiring
those locks. Earlier caller/Work deadlines win; rows close before return and
locks remain until the original coordinator commits or aborts.

This is only session-owned admission, not full session authentication. Native
participants must still check current global/tenant/user/identifier/credential,
authorization and every applicable organization/factor/passkey authority, plus
authentic proof and final temporal validity. Passing a pool/autocommit queryer
cannot prove protected admission. The owning native participant must fence
scope/lifetime and poison/abort Work on every failure, including ignored denial.
No bearer, authority lease, policy decision, refresh or new session is returned.
Missing/revoked/expired/unequal rows deny uniformly with `identity.ForbiddenError`;
invalid inputs and storage/corrupt rows retain redacted typed classifications.

## Native password-signin session effects

`NewPasswordSigninEffect(Config, IdentifierAdmissionConfig)` freezes the bounded
single-factor password admission profile without IO. Install
`PasswordSigninMigrationSource` after `OTPIssueMigrationSource`, using a permanent
unused migration version in the existing single history. The forward constraint
extension preserves populated session and retained issuance records.

The registered `identity/password/postgres` participant calls `Apply` only in
its original coordinator `Work`, with the original paired password/pre-auth
command, selected verified recipient and pre-auth snapshot. It must first
verify actual password and cookie possession, authentic proof provenance,
complete request intent and risk/policy admission. Structural session mapping
is not authentication. The effect fences current directory, selected credential
and authorization without retargeting anonymous command scope; it stages
pre-auth consumption, family/session and retained issuance in that same Work.
Original expiry is checked after waits. Every error must reach coordinator Abort;
provisional success must not disclose a bearer before a known original commit.

`Recover` runs only during that participant's sealed recovery invocation. It
checks retained original issuance commitments, including after session payload
cleanup, but returns neither a credential nor current access authority. The
coordinator reconciles all participants. This seam does not implement password
comparison, public login orchestration or an HTTP endpoint.

## Security and tradeoffs

- These are trusted storage APIs, not unauthenticated public endpoints.
- A found record is **not** authentication, authorization or current-validity
  evidence. Deny revoked records/families and compare every applicable current
  authority before accepting a credential. Neither timestamp nor construction
  proves a source read or renews the original freshness bound.
- The returned native session retains its original family version. The current
  family's version/status are separate facts; they never replace the snapshot.
- Only tenant/version-bound digests are indexed. Raw bearer tokens and opaque
  authenticated proofs are never stored or reconstructed. All returned digest
  bytes are compared in constant work; database lookup is not constant latency.
- Schema-versioned bounded JSONB stores one complete explicit native projection.
  Missing, null, unknown and malformed fields fail closed on reconstruction.
  JSON numbers are decoded directly into integers, never through float64.
- UTC, fixed-width nanosecond text preserves exact timeline precision and
  bytewise expiry ordering. Standard PostgreSQL timestamptz would round these
  native timestamps. Expiry indexes are preparation, not an implemented cleanup.
- Protect database access, backups and retention: non-bearer authentication
  metadata and authority scope keys still correlate users. Do not log records,
  digests, query arguments or driver diagnostics.
- PostgreSQL uniqueness/FKs enforce exact tenant/session/digest and parent
  relationships. Cross-tenant absence does not disclose a foreign record.

## Operations, verification and FAQ

Use the `integration` build tag and an explicit task-owned loopback
`IDENTITY_SESSION_POSTGRES_TEST_DSN` for tests. Missing selected infrastructure
fails, never skips. Unit and fuzz tests cover reconstruction; integration tests
use the real owned migration runner and PostgreSQL. Their parent-table fixture
does not replace eventual full-kernel/reference composition evidence.
Native revocation tests additionally compose the actual full kernel migrations,
populated session upgrade and real contributor/coordinator. Audit/outbox SQL
seams prove atomic rollback and visibility, not production adapter interoperability.

**Can this adapter issue or authenticate sessions?** The configured owned issuer
and primary reader support the documented single-factor profile. Raw repository
reads reconstruct structural data only. Final proof consumption and effects use
the sole identity PostgreSQL coordinator, never a private issuance transaction.

**Can a revoked session become active on reload?** No: retained record and family
tombstones are returned explicitly. Reading them never alters state or authority.

**Can a deployment change remember-me defaults for existing sessions?** No:
reconstruction retains all resolved durations and rejects values needing new
defaults or clamping.

See `CHANGELOG.md`. Complete mutation, coverage, API/catalog, clean-consumer,
kernel/reference composition and release gates remain pending.
## Native privacy eligibility

`NewRepositoryWithPrivacyExportAdmission(pool, config, profile)` explicitly
opts the same store into `identitypostgres.PrivacyExportAdmissionContributor`.
Use trusted deployment, policy namespace, audience and method/kind/owner fields
as for identifier eligibility below. Existing constructors remain opted out of
privacy; this constructor does not enable identifier admission.

`CheckPrivacyExport` reads only the exact selected live invocation. It derives
all applicable primary owner keys from the original session and compares the
request's expected **user security authority version**, not the identifier or
aggregate identity version. Initial and final checks keep the same original
session, credential linkage and authority versions; privacy allocation cannot
refresh them. Directory, user/credential and authorization checks precede the
complete session/family share locks and primary-time expiry check. There is no
pool fallback, independent transaction, write, bearer issuance or policy engine.

The current native profile denies organization, factor and passkey applicability
rather than omit their owners. Complete multi-owner platform support is still
required. Eligibility alone is not fresh reauthentication, one-time proof
consumption or queued export admission. Public privacy execution remains closed
until native proof, all contributor cuts, effects and recovery are composed.

# Native identifier eligibility

`NewRepositoryWithIdentifierAdmission` explicitly enables the same repository
as `identitypostgres.IdentifierAdmissionContributor`. Existing `NewRepository`
remains opted out. Register the same instance for the store descriptor and the
plan's separate read-only role; do not register a second duplicate store owner.
The constructor accepts only the primary pool, existing schema/read budget and
trusted deployment/authorization/audience/credential profile, never Work,
coordinator, registry, callbacks or an application-written domain store.

`Repository.CheckIdentifier` can run only under the selected live coordinator
invocation. It reads the exact command-bound session ID/version, checks every
required scope key, then uses the existing global/tenant, user/credential and
authorization owners before locking and rechecking the exact session/family
record and primary-clock expiry. Owner locks remain until the original Work
closes. Session projection reads acquire no locks before those owners; the
complete post-lock comparison rejects intervening changes. No replica,
autocommit fallback, independent transaction or network callback is used.

Initial comparison uses the original snapshot. Final comparison changes only
the identifier epoch supplied by the kernel's exact Work-owned mutation receipt;
the stored snapshot, credential ID/version, original proof metadata, issued time
and accepted activity stay unchanged. Reading a record does not authenticate its
bearer or manufacture fresh reauthentication. This eligibility check is not a
policy Allow, one-time proof consumption or complete workflow authorization.
Public protected identifier execution remains disabled pending those phases and
durable recovery composition.

`SessionAuthorityKeys` uses visible-ASCII canonical IDs under the session
owner's existing profile. Family keys bind tenant/user/family; session keys add
session ID. Versioned, length-framed SHA-256/base64url avoids delimiter aliases.
Compare these keys together with `identitypostgres.KernelAuthorityKeys` and
authorization's `AuthorityScope.Key`. Keys contain no versions or positive
validity evidence and must not be logged. Historical custom keys are rejected
by this profile, never silently transformed or adopted from a newer epoch.

Configure the exact authentication method and credential kind/owner used by the
issuer. Currently only single-factor sessions without organization/factor/
passkey applicability are eligible. Anonymous, multifactor and passkey-owned
sessions deny even if optional dimensions were omitted. Present unsupported
dimensions also deny; they are not skipped. Full support remains required in
the platform and needs the actual corresponding owners, not a configuration
override. Zero/malformed profile and missing pool/configuration are InvalidInput;
foreign, stale, revoked and unsupported sessions deny uniformly as Forbidden;
corrupt storage and unavailable primary reads are redacted Unavailable. Earlier
caller/Work deadlines win, and cancellation/deadline classifications remain.
