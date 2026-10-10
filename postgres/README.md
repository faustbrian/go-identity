# Identity PostgreSQL

## Native registration domain

`NewPasswordRegistrationDomain(repository, config)` constructs the kernel
participant used by the native password-registration workflow. It does no IO,
starts no goroutines and borrows the exact repository/pool enlisted with the
sole coordinator. Configure the exact versioned identifier comparison profile
and the retained reuse keys used by identifier removal; missing keys fail
closed while live retirement history references them.

`PasswordRegistrationFields(intent)` binds prepared permitted attributes,
their schema, the created user, canonical identifier, initial credential and
comparison profile into the original signup command. Include every returned
field unchanged before admission. Attributes are committed without putting a
serialized attribute blob into feature metadata. Neither helper authenticates,
canonicalizes input, approves fields or grants registration policy.

The native password owner calls `domain.Apply(ctx, work, participant, command,
intent)` only during its original protected Apply invocation, after HIBP/risk,
pre-auth and password preparation. The kernel creates user/attributes, an
unverified non-primary identifier and an enabled version-one password reference;
the native owner must insert its material through the same Work. Provisional
results are not authentication or durable success. The coordinator refuses a
signup receipt without its actual kernel creation and commits required
audit/outbox/native effects together. Never chain `UserCreate`, identifier
attachment and password persistence as separate registration commits.

Append `PasswordRegistrationMigrationSource` at an explicitly allocated version
after the complete credential-reference and identifier-retirement history.
Existing history and populated accounts are not rewritten or inferred to be
signups. `identity.registration_bindings` is retained original domain evidence,
not another journal: it links the signup command to its created record IDs and
survives pruned account payloads. Primary recovery keeps the original command
namespace and cannot regenerate an account or infer rollback from cancellation.

This kernel operation is a development prerequisite. The complete native signup
service, verification delivery, optional session issuance and release
qualification remain pending; applications should not implement their own
workflow around this low-level seam.

Construct the original native `password-signup` v1 command with
`identity.NewFeaturePasswordSignupCommand(spec, preparedHash, originalCookie)`.
The coordinator fingerprints the exact hash and cookie in distinct retained-key
domains, with no raw material in the journal or safe collision scope. Scalar
and cookie-only commands cannot impersonate this profile. Changing either input
changes command intent; recovery must keep the original command, not regenerate
its hash or submit a replacement cookie. Other independently registered signup
schemas are unaffected. This identity binding neither admits the cookie nor
proves password policy; the native workflow owns those checks.

## Exact native command custody

Adapters staging a native feature command must call `Work.RequireFeatureCommand`
with the supplied command before using its payload. It admits only an unchanged
copy of the original command in that registered owner's active Apply invocation.
Reconstruction, even from equal-looking fields and the same secrets, denies and
poisons Work: ignoring the error cannot commit earlier provisional writes.
`FeatureCommandIdentity` only returns correlation metadata; it does not validate
a candidate command. Existing metadata and successor accessors remain unchanged.

## Original-signin hash upgrades

The registered `identity/password/postgres` owner can compose a hash-only
upgrade inside the original paired password-signin command. Freeze independent
predecessor versions with `PasswordHashUpgradeFields` before fingerprinting.
After directory admission, call `Work.PreparePasswordHashUpgrade` before any
shared user/credential admission. This exclusively locks current predecessor
authority and admits the unchanged selected recipient without a lock upgrade.

The native owner compares the original password and prepares bounded replacement
material before opening Work. It performs its material CAS in that Work, calls
`ApplyPasswordHashUpgrade`, and binds `PasswordHashUpgradeSuccessor` into its
own proof/session effects. Every failure must abort. Credential record,
credential-authority and user aggregate versions advance independently; user
and identifier authority and the original observation time do not change.
Advancing credential authority invalidates predecessor-bound sessions: any
continuation must follow an explicit session-owner policy, not this receipt.

The lifecycle participant can read `StagedPasswordHashUpgrade` after staging.
Receipts remain provisional until the sole original command commits. A final
kernel fence rejects missing application, expiry or changed successor authority,
rolling back material and all effects. Only the exact original native Apply
invocation can mutate or obtain successor admission; scalar fields grant no
authentication. This API neither adds a password-change journal nor delivers
tokens. Existing admission and replacement contracts are unchanged. Public
signin composition with this seam remains required separately.

## Final native feature admission

A native feature owner may implement `FeatureCommitContributor` in addition to
the unchanged execution contract. The coordinator invokes `CheckFeatureCommit`
with the original command after required audit/outbox, journal writes and other
final checks, immediately before SQL commit. Use original expiry/admission
facts and bounded primary reads; never renew facts, mutate, stage effects,
perform network IO or retain Work. Existing owners without this optional
contract keep their behavior.

Only the exact selected owner's synchronous check can use `FeatureScope`.
Apply-only `FeatureCommandIdentity` remains unavailable. Callback failures,
panics or unfinished rows roll back all provisional effects; SQL commit
ambiguity keeps its existing unknown classification. This seam grants neither
password authentication nor token delivery and creates no additional journal.

## Original password-signin intent

The coordinator explicitly selects `identity.NewFeaturePasswordSigninCommand`
for `identity.password.signin`, `password-signin` v1, record-free user or
anonymous-flow scope. The original primitive-owned password and pre-auth cookie
are borrowed together, fingerprinted in distinct `password-signin-password` and
`password-signin-cookie` domains under the retained command key, and never
persisted as raw bytes. Changed password or cookie is conflicting intent even
after key rotation. Busy or destroyed password owners fail closed; callers must
destroy the original owner after bounded execution. Plain scalar metadata cannot
impersonate this exact profile. Other independently registered signin schemas,
including existing CAPTCHA-protected commands, retain their historical mapping.

Native preparation and final-plan attachment preserve the disjoint command and
its complete scope rather than using legacy accessors that omit its secrets.
This structural transport grants no password authentication, cookie possession
or session authority. Execution still requires an exact registered native owner
to compare the password, enforce current policy and pre-auth state, and commit
all session and security effects together. The complete native signin workflow
remains under development. Recovery uses secret-free command correlation, not
resubmission of destroyed secrets or reconstruction from a persisted digest.

## Authenticated password-change intent

The coordinator explicitly selects `identity.NewFeaturePasswordChangeCommand`
and fingerprints its original encoded hash, source bearer and complete upstream
reauthentication proof under separate retained-key domains. Seconds and
nanoseconds remain separate: timestamp rounding cannot make two proofs the same
intent. Original versions retain all 64 bits. Equivalent time zones encode the
same instant. Neither journal intent nor safe collision metadata retains raw
verifier, bearer or proof values, and key rotation rebinds the original custody
under the claim's retained key. Existing hash-only command encodings are unchanged.

This is structural mapping, not authentication or proof consumption. Execution
still requires the exact registered native replacement participant, complete
policy checks and the existing protected effect plan. The existing hash-only
password repository rejects the authenticated variant. Native signed-proof and
current-source validation, atomic consumption and the public password-change
workflow remain under development; adding custody alone does not enable them.

## Exact consuming OTP recovery

`RecoverOTPFeatureCommand` is the native consuming counterpart to metered-check
and counted-denial recovery. Supply the exact original code-free `OTPAttemptPlan`
and historical query scope under current `QueryPolicy`. It matches every attempt,
fingerprint, scope, challenge and version field before disclosure and under the
existing command locks before pending reconciliation. It does not compare a
code, charge again, require the consumed pre-auth to remain executable, or return
a session/bearer. Native orchestration must separately authenticate original
possession and current disclosure scope. Historical outcomes grant no authority
or credential redelivery; unavailable reconciliation preserves Unknown rather
than inferring rollback. Existing recovery profiles remain separate.

## Request-key correlation before command preparation

Native feature adapters can use `QueryPreparedFeature` to restore an existing
committed workflow by its server-issued command ID without a new initiating key
or caller-written store. The exact registered request/preparation owner and
current `CommandQueryPolicy` must authorize the complete historical scope.
The result contains independently owned encrypted input/output and their
original binding/generation. Both envelopes still require native authentication,
separate bearer possession and current authority checks; historical custody is
not renewed authority. Missing, retired, pending, aborted or legacy incomplete
history returns no custody. Lookup never recovers, generates, mutates or charges
anything. Install the existing request-key and feature-preparation migrations;
no additional schema is required. Generic `QueryCommand` remains metadata-only.

Native generated workflows can opt into `ResolvePreparedRequestKey` after
installing `RequestKeyPreparationMigrationSource{Base, Version}` over the
original request-key history. The exact registered feature owner prepares
bounded authenticated **code-free** input outside SQL. The allocated command ID
and ciphertext commit together in the existing immutable mapping; matching
retries recover the original input without reselecting recipients or renewing
times. Race losers recover the winner, and legacy mappings cannot be backfilled.
Preparation may perform bounded reads/encryption, not risk charges, domain
writes, delivery or OTP generation. Those follow acknowledged custody through
the existing journal. Authenticate the complete returned binding and immutable
configuration; include configuration in the initiating intent. Restore original
input without treating it as current authority, and verify bearer possession
separately. Unknown acknowledgement returns no usable input. This kernel seam
does not itself implement the public OTP Send service.

Compose `RequestKeyMigrationSource{Base, Version}` after kernel history and use
`NewCoordinatorWithRequestKeys` with a separate `RequestKeyConfig`. Existing
`CoordinatorConfig` and `NewCoordinator` remain unchanged; the ordinary
constructor leaves request correlation disabled. Construction performs no SQL.
Use `NewRequestKeyConfig(namespace, lookupKey, policy)` to copy the nonzero
32-byte key into opaque custody; there is no raw key projection and nested
configuration diagnostics cannot traverse its bytes.
The first authorized resolve pins the configured random lookup key to its
trusted deployment namespace; changing that key fails closed. Keep it secret
and stable. Command-fingerprint keys rotate separately; retain every version
referenced by a mapping. Stage new keys in both old/new processes before changing
the current issuance version, so overlapping processes can verify the winner.

`ResolveRequestKey` accepts `identity.IdempotencyKey`, a trusted canonical
`RequestKeyScope` and a complete immutable `identity.RequestIntent`. The lookup
is namespace plus tenant, actual actor (ID/kind), method, canonical route ID and
keyed client-key digest. Body, target user, purpose and options are **not** lookup
dimensions: they belong in the independently keyed intent. Feature owners map
every behavior-affecting field, including policy/schema and expected versions;
applications do not supply private fingerprints, SQL or workflow callbacks.

The separate configured policy must authorize the current actor/tenant,
route-ID action and resource `identity.request-admission` with that route ID.
Owned resource attributes `identity.request.admission`, `.method` and
`.namespace` replace caller overrides. Earlier cancellation/deadlines win.
Policy decisions run outside transactions; database errors and panic are redacted.

Matching retries return the original random command and stored fingerprint-key
version; different intent returns conflict without an ID. A lost commit
acknowledgement returns unknown with no usable admission: retry the same key and
intent, not a new key or namespace. Mapping never grants execution or a result.
Recover the original command journal/native prepared state **before** generating
another credential or provider effect. OTP Send composition is still pending.

Rows retain correlation indefinitely, including absent/pending/unknown journal
state and retired command tombstones; there is no 24-hour reassignment. Immutable
database fences reject updates, deletes and truncation. Operational storage
retention is therefore an explicit tradeoff, not an implicit cleanup policy.
Existing immutable migrations and default-disabled coordinator behavior remain
unchanged; unsupported destructive downgrade must not remove retry identity.

### Pre-generation journal custody

`PreparationMigrationSource{Base, Version}` adds optional columns to the same
`identity.commands` journal; it does not create another workflow authority or
enroll historical commands. The private preparation phases match the original
immutable claim, acquire its journal lease, and commit a generation-start marker
before any entropy, rendering or sealing outside the transaction. A competing
caller cannot generate. An abandoned lease without a start marker can transfer;
a start marker with missing ciphertext remains uncertain and cannot regenerate.

The original live generation can retain one bounded encrypted output. Exact
byte retries are idempotent, replacement and erasure are fenced, and takeover
receives the original ciphertext with its original generation—not permission to
generate a new code. Lease checks use primary time after acquiring the row lock.
The native feature codec must authenticate and bind that encrypted output;
the journal does not interpret or decrypt it. A lost start-commit acknowledgement
cannot authorize entropy. No SQL transaction is held across generation callbacks.

Installing these columns alone enables no public workflow. An opt-in stable
native `FeaturePreparationContributor` can use `ExecutePreparedFeature` to
consume the journal preparation and final execution path. Its original request
is schema-validated and primary-admitted before committing the start marker.
The owner generates bounded authenticated ciphertext outside SQL, then restores
the exact original generated command and plan from retained output. The final
plan preserves the initial feature, subject, mandatory audits and lifecycle;
only original encrypted delivery may be added. The coordinator preserves the
caller-request fingerprint, separately binds reconstructed execution fields,
and executes through its existing atomic Begin/Apply/Commit owner.

Generated password hash/authenticated-change commands retain their disjoint
native custody variant when the coordinator attaches the final plan. The
legacy `Feature` accessor stays closed to those variants; native selection and
the existing complete keyed hash/bearer/proof intent remain mandatory. The
registered password owner still authenticates retained output and the original
proof, checks current source authority, and owns atomic proof consumption.
This is not a public password endpoint or a substitute for its native policy.

An optional `FeatureAdmissionPreparationContributor` can assess external facts
before generation. Install `AdmissionPreparationMigrationSource` after the
existing preparation source, with a later explicit version, before selecting
this owner. The coordinator acknowledges its existing lease reservation and
closes SQL before `PrepareFeatureAdmission`. It then reacquires that same
generation/owner, repeats current primary admission, checks original local
facts and commits the start marker. Admission is checked again after that
acknowledgement before calling its invocation-local `Generate`.

`FeaturePreparationAdmission.Check` is strictly bounded and IO-free. The
returned invocation captures the original request and admission, not shared
request state. Its generated authenticated ciphertext must retain original
admission custody; `RestoreFeatureAdmission` reconstructs a local check from
that unchanged output/generation without provider, counter or generation IO.
The coordinator checks local admission again after final Begin waits and just
before commit. Current account/flow authority remains the native owner's job;
this seam does not supply risk facts, authentication or a one-use artifact.

Busy, terminal and started-without-output replay never assesses externally.
Retained output calls only IO-free restoration. Failed external admission
leaves its acknowledged pending lease but no generation marker; retry remains
under the existing journal and native risk owner's original-attempt replay
rules. Nil/failed admission denies; provider diagnostics are redacted and
cancellation/deadlines remain attributable. Unknown start acknowledgements
cannot generate. Immutable profile 2 rejects legacy/profile-1 takeover rather
than silently bypassing admission; historical profile 1 is not enrolled or
reinterpreted. This is native composition support, not public OTP Send or
proof of real risk/provider integration.

During final `ApplyFeature`, that exact registered preparation owner can read
`Work.FeaturePreparationOutput` to restore invocation-local custody. It returns
an owned ciphertext copy and the original output generation, even after a later
lease generation takes over. Admission, ordinary execution, recovery, foreign
instances and returned/closed handles have no access. This avoids shared
per-request state and does not expand generic command-field size limits. The
adapter must still authenticate its existing envelope, separately verify bearer
possession and recheck current authority and expiry before staging effects.

Use one immutable comparable native owner across all phases, with per-invocation
state; never replace the registry after generation or share mutable prepared
delivery between requests. `AdmitFeaturePreparation` borrows Work only for
current checks, not generation, effect staging or domain mutation. It can reuse
existing exact-owner directory/user/credential/authorization helpers. Every
final execution must recheck current admission after waits. Restore authenticates
the complete original request/generation and separately submitted bearer; it
cannot remap output, manufacture authority or renew expiry.

Terminal matching replay returns the original receipt without another native
generation/restore invocation. Started-but-unretained output stays in progress
after lease expiry. Lost start acknowledgement runs no generation; lost retained
output acknowledgement returns unknown and retry can recover the original bytes.
One-use preparation profiles remain rejected, not skipped. Protected counters
are an explicit opt-in: install `CounterPreparationMigrationSource` after
admission preparation history, with a later version, and register the exact
native `CommandCounterAdmissionContributor`. Profiles 3/4 freeze the complete
code-free declaration in the existing journal before charging. The charge and
generation-start marker commit before generation; externally admitted profile 4
charges before external admission and commits its start marker afterwards.
Denied charges retain their audit and original terminal receipt without output.
Final restoration must preserve the exact counter scope, and final Apply/Commit
still recheck current counter authority; an allowed reservation is not permission
to mutate. Lease takeover transfers the original charge without recounting or
renewing its observation. Lost start acknowledgements cannot generate, and lost
retention acknowledgements resume the original output. A changed declaration
conflicts, including after fingerprint-key rotation. Old readers reject the new
profiles rather than bypass their charge; legacy profile 1/2 history is unchanged.
These are trusted compile-time adapter phases, not consumer workflow callbacks
or a public authentication endpoint. Public OTP Send and its real native
composition remain unfinished. Ordinary command and migration bytes are unchanged.

Code-free `identity.NewFeaturePreAuthCommand` and
`identity.NewFeatureSessionCommand` use these same private fingerprint domains,
without an OTP entry. Identical scalar scope with changed bearer bytes or a
different custody variant cannot reuse the original command intent. Retained-key
replay retains original custody. This does not bypass native authorization or
enable OTP comparison/reservation without a code. The owned issuance workflow
must still authenticate the actual submitted bearer and original primary state.

Separate opaque pre-auth cookies use the existing `identity-command-secret-v1`
framing under the exact field path `pre-auth-cookie`; its HMAC enters private
canonical intent as `pre_auth_cookie`. Different submitted cookies cannot reuse
the same command fingerprint. Safe collision fields contain no bearer or cookie
digest. Cookie-free and code-only commands retain their exact historical bytes.
Fingerprinting is not active-flow admission. Generic execution still rejects
all opaque OTP submissions; native counted and consuming phases must own their
primary checks. No storage or migration change is introduced by this framing.

## Workflow recipient selection

`Repository.ResolveRecipient` selects an exact owner-canonical email or phone
identifier within one tenant. It never normalizes addresses. Supply `UserID`
for an original known subject; omit it only for trusted discovery, keeping the
resolved user separate from the anonymous command binding. Signin/reset require
`RecipientVerified`; verification/change may use `RecipientPendingOrVerified`.
Missing, inactive, foreign-subject and ineligible records return `Suppressed`
without a selected identity. Infrastructure errors remain errors.

Freeze the selected record into original workflow custody. The exact native
feature invocation calls `Work.RequireRecipient` before staging delivery:
primary user and identifier locks fence original versions until commit/abort,
and an ignored denial poisons Work. A suppressed record cannot authorize real
delivery. Records are snapshots, not authentication, risk evidence or renewable
validity leases; callers must not log or serialize them. Install the existing
identifier, status and credential-authority migrations before using this port.
Public OTP Send orchestration remains under development.

## Protected OTP effect binding

Inside its registered `ApplyFeature` callback, a native feature can call
`work.OTPConsumption(theExactFeatureOwner)` to obtain a scalar copy of the
original checked consuming reservation. Bind composed effects to its command,
attempt, generation and fingerprint; it is not a completed proof or a commit.
Unchecked reservations, non-consuming checks, foreign owners and returned Work
deny access. This performs no comparison, mutation or token delivery. Session
issuance still needs its own complete native effect and commit-gated delivery.

## OTP current-authority checks

The generic native feature invocation also exposes
`Work.RequireActiveUserAuthority(ctx, participant, UserAuthorityAdmission)`.
Only its exact live `FeatureExecutionContributor` may compare the active primary
user and all three original security epochs. No credential is fabricated for
passwordless issuance, and aggregate user versions remain separate. The lock
lasts until commit or abort; a live failure poisons Work, while returned or
foreign invocations cannot borrow it. This does not replace directory, policy,
flow or credential-specific admission.

`OTPAttemptWork`, `OTPReservationWork`, `OTPApplyWork` and `OTPFinalizeWork`
expose `RequireActiveDirectoryAuthority`, `RequireActiveCredential` and
`RequireActiveUserAuthorization` to their exact registered OTP owner. They also
expose `RequireActiveUserAuthority` for passwordless users without credential
references: compare original user, identifier and credential-security epochs
and active status under a primary user share lock. Aggregate `User.Version` is
not an authority epoch. Credential-bearing workflows still require their exact
credential check, including eligibility and expiry. These
reuse primary kernel and authorization-owner checks in the original transaction,
with unchanged frozen expectations, locks and bounded deadlines. A live failure
poisons Work even if ignored; a returned handle cannot affect a later phase.

Expected epochs and scope must be authenticated parts of the original native
command, not values adopted from a current read. Success checks only the named
dimension: it does not authenticate a code, establish current session/pre-auth
authority, decide policy, renew validity, issue a session or consume proof.
`OTPReleaseWork` deliberately has no current-authority admission gate, because
coordinator-proven noncommit must permit terminal release after revocation.
Production OTP session/pre-auth orchestration remains under development.

Protected apply/finalize handles lend the separately submitted bearer through
`PreAuthCookie` to the exact live owner, without exposing the OTP code or full
command. Missing or returned custody denies. The owner must independently
authenticate the original cookie commitment and admit current session-owned
flow state; access itself grants no authority. Never retain or disclose the
borrowed bearer. Recovery/release have no cookie accessor.

## CAPTCHA consuming declaration

`CommandPlan.CaptchaEvidence` carries bounded signed consuming custody,
distinct from issuance replay ownership. Its deterministic historical profile
binds issuance identity, original signature, evidence lookup, consuming
signature, retained key/risk-policy versions and unchanged validity interval.
The immutable native command must additionally bind the full original trusted
flow/configuration and all protected target/version fields; this declaration
cannot substitute for them or authenticate its own inputs. Risk policy is
separate from authorization policy. CAPTCHA, phone evidence and counters share
one exact risk-store contributor and must agree on risk-policy version.

Existing plan bytes are unchanged when this declaration is absent. Preparation
requires the exact registered `CaptchaUseReservationContributor` and its pure
native validation before SQL. `ReserveCommand` invokes reserve or exact
predecessor rebind through `CaptchaUseReservationWork` inside the same primary
command reservation transaction as every other declared participant. Errors,
panic, unfinished rows, poisoned SQL or cancellation roll back that whole unit.
Live/terminal replay invokes no new evidence reservation. Callback return
expires every handle and native-input alias; copies cannot renew ownership.

`Begin` additionally requires the complete `CaptchaExecutionContributor` phase
set. Reservation-only owners remain rejected without consuming their handle.
The coordinator invokes `CheckCaptchaEvidence` before the protected mutation and
again after provisional effects, then `FinalizeCaptchaEvidence` in the same
domain transaction as the mutation, audit/outbox and command result. Only the
exact native owner receives invocation-bound `CaptchaApplyWork` reads or
`CaptchaFinalizeWork` terminal SQL; no provider callbacks or private commits.
Failures poison the whole Work, including ignored SQL errors and open rows.

After proven domain rollback and current owner/tenant exclusion, the coordinator
invokes `ReleaseCaptchaEvidence` through `CaptchaReleaseWork` at the unchanged
generation. Unresolved recovery requires every frozen participant to prove
noncommit under primary exclusion before exact predecessor release at its
successor. Unknown/conflicting/absent proof retains the reservation. Release
must be terminal and never grants a new reservation. `RecoveryWork.CaptchaBinding`
supplies frozen linkage only to the exact risk owner, not release authority.
Elapsed expiry or lease time is never noncommit proof.

The native risk adapter implements consuming reservation but not yet this
complete execution phase set. SQL integration fixtures prove the coordinator's
atomicity, lifetime and primary noncommit protocol, not production CAPTCHA
authentication, protected workflows or final consuming composition.

## Native CAPTCHA replay reservation

`CommandPlan.CaptchaReplayReservation` explicitly selects the native risk
store's `CaptchaReplayContributor` before domain work. Only the exact user or
anonymous-flow CAPTCHA issuance schemas admit it; declaration alone supplies
no authority. The existing coordinator commits the alias reservation with the
original command reservation, then invokes domain work separately. A domain
rollback cannot erase that independently committed replay winner.

`CaptchaReservationWork` exposes only bounded SQL, primary time and the exact
original immutable command, authoritative fingerprint and owner generations.
The registered native participant authenticates signed custody/configuration
and enforces alias uniqueness. Callback return or panic expires every handle
copy; takeover uses exact predecessor CAS, never a timeout-based release.
False leaves historical plan bytes unchanged. The risk PostgreSQL adapter now
supplies production issuance and original-result recovery; protected consumption
remains pending;
applications must not implement private replay stores to fill these gaps.

## Exact original final-authentication outcome recovery

`QueryAuthenticatedCommand` is a read-only bridge for the owned authenticated
session adapter. Supply the original mapped command, opaque final proof,
prepared plan and trusted current actor context. The configured `QueryPolicy`
must allow disclosure. The bridge compares the complete original input using
the global claim's exact retained fingerprint-key version, original proof
namespace and frozen plan before returning the safe feature receipt and audit
event ID. Generic `QueryCommand` remains metadata-only.

Expired proof metadata is historical: the bridge validates original private
provenance at the original issuance instant; it cannot renew authentication,
authorize a session, consume a proof or return a credential. Wrong input/plan
conflicts; missing, retired, malformed or unavailable evidence fails closed.
Absence never becomes rollback proof or an implicit reservation.

`RecoverAuthenticatedCommand` first establishes that same original input and
current access policy, then uses the existing sole reconciliation owner only
for an already observed pending command. It repeats exact-input lookup after
reconciliation. Live leases remain pending, and unresolved effects remain
unknown. It never reserves missing input, executes a session transition or
reveals a bearer. Retain original safe request/proof custody and old keys for
this request-bearing path; general restart recovery from command identity and
the complete public session execution service remain unfinished.

## Final-authentication proof-use storage

`SignInProofUseMigrationSource{Base, Version}` appends bounded proof-use
tombstones after the complete existing history. Existing IDs, status and
versions are unchanged; no destructive downgrade or pruning is provided.
Proof IDs are unique within a stable trusted authentication-source namespace,
across tenants and versions. Changing that namespace must not bypass prior use.
The original full-width proof version and nanosecond expiry remain exact.

The private staging phase writes through the original Work only. A unique
command cannot acquire another proof; concurrent commands cannot commit use of
the same proof. Rollback discards provisional use with every other effect.
Primary time is checked after the uniqueness lock, so a proof expiring during
a wait cannot leave usable Work. A denied or ambiguous attempt must follow the
coordinator's existing abort/recovery path, never guess rollback or mint another
proof or bearer. Session deletion cannot make a committed proof reusable.

This is **not authenticated issuance**. The private storage phase neither
authenticates its metadata nor checks current authority or creates a session.
The native issuer still needs configured opaque-proof validation, immutable
command binding, current locked eligibility, session/family effects, final
temporal checks, audit/lifecycle and terminal recovery. No ordinary feature or
public session issuance is activated by this migration or storage phase.

## Privacy admission storage

The native private command codec now binds the complete closed privacy request
and its original authenticated proof to the existing global command claim.
It reuses the core's deterministic intent digest, wrapping it and the exact
opaque proof-envelope digest in separate framed, retained-key HMAC domains.
Proof header/payload validation retains the existing bounded capability codec.
Session IDs, projection choices and proof correlation fields do not enter
persisted collision fields. Historical non-privacy command bytes are unchanged.

Exact replay regenerates the original fingerprint under its stored key version;
it never re-signs the proof, changes its lifetime or promotes a changed session
or privacy epoch. Even another valid signature over identical proof metadata
is distinct submitted custody. This encoding and private claim check neither
consume a one-time use nor expose public privacy reservation/execution. Full
native proof consumption, all cuts, audit/lifecycle and terminal recovery must
still be composed under the sole coordinator.

Journal persistence and request-bearing replay also compare the queued receipt
against the retained original intent: identity/authority/privacy versions,
artifact policy and every contributor projection must match. A structurally
valid receipt from a changed session or policy cannot replace the original.
Scope-only observation remains structural and preserves the stored bytes for
the service's separate retained-key snapshot verification. Neither path proves
cut provenance or authorizes new execution, and neither needs a live proof.

`PrivacyExportAdmissionContributor` is the native session owner's read-only
eligibility role. The private invocation selects the already registered exact
`identity/session/postgres` participant; registration alone cannot enable it
as a public command. Its `PrivacyExportAdmissionWork` has no constructor or
write/transaction-closure methods. Initial checks precede allocation; terminal
checks require the same Work's stored allocation/snapshot and frozen request.
The role borrows existing kernel credential, directory and authorization checks
and bounded primary reads without defining another policy owner. Every ignored
denial poisons Work, handles expire when the invocation returns, and repeated or
reentrant phases cannot renew authority. Session/proof freshness remains the
original authority owner's responsibility, never a new lease from this handle.
The actual native session adapter must implement these checks; this invocation
plumbing is not proof of session validity or complete queued admission.

Compose `PrivacyExportJobMigrationSource{Base, Version}` after the privacy
epoch migration to add bounded immutable request/snapshot metadata and the
closed six-state job profile. Existing applied migrations are unchanged.
The private persistence phase uses the same Work's allocation and frozen intent,
verifies the retained evidence key, rejects changed scope/time/projections and
rechecks active identity, authority and privacy fences at its write. Command ID,
export ID and per-subject epoch uniqueness prevent metadata rebinding; no upsert
or snapshot re-signing is used. Exact JSON bytes retain full unsigned counters
without JSONB coercion; the deterministic-CBOR MAC remains key-owned.
Returned receipts are copied, provisional and not publication evidence. The
metadata includes personal scope correlations, so restrict database access and
apply the eventual legal-hold/erasure owner; do not log it. No worker or public
admission API is activated by this migration or storage phase.

`PrivacyExportMigrationSource{Base, Version}` appends authoritative `privacy_epoch`
and `privacy_disposition` fields to existing user rows. Compose Base with
`StatusMigrationSource` first and allocate Version after every Base version.
The migration preserves existing IDs, user/authority versions and blocked state;
defaults keep explicit-column old creation/read paths compatible. No destructive
down is supported. Resetting the epoch would resurrect prior export authority.

The private native allocation phase locks the exact user row, rejects blocked,
pending-anonymization/deletion, stale or overflowing authority, samples primary
time after locking, generates a random export ID and advances only privacy epoch
inside the existing Work. All failures poison that Work. No transaction is opened
or closed by allocation; rollback removes its entire provisional prefix.

This is **not queued admission**. Allocation does not prove session freshness,
configured authorization, original proof consumption or cut provenance, and
cannot make an export runnable. Public privacy execution remains disabled until
the protected owner captures every contributor cut and persists the immutable
snapshot, job, proof consumption, audit/lifecycle and command result atomically.
Pending destructive lifecycle owners must set the disposition under the same
user lock before initiating cascades. The initial wire profile still rejects
unmapped imported directory IDs rather than rewriting them; profile reconciliation
is unfinished. Worker, publication, download and recovery composition remain work.

`KernelAuthorityKeys` derives canonical version-one keys for kernel-owned
global, tenant and user lifecycle dimensions. Session admission must compare
these exact keys as well as current positive versions. They are correlation
values, not authentication evidence; do not log them. Existing custom keys
require explicit adoption and cannot be silently refreshed into this profile.

## Protected identifier admission

Identifier reservation requires `CapabilityPlan.ProofFingerprint` to equal the
submitted verified `Grant.EnvelopeDigest()`. Equal ID, expiry and use limits
alone cannot substitute another signed envelope. The capability owner derives
keyed replay metadata; callers must not invent it. This comparison changes no
historical command encoding or frozen-plan decoding and grants no authentication
or execution authority.

`CommandPlan.IdentifierAdmission` selects the exact registered
`identity/session/postgres` checker through `IdentifierAdmissionContributor`.
This role is frozen into the journal, separately from mutation contributors:
it cannot claim a durable recovery outcome. Nil retains historical plan bytes.

`IdentifierAdmissionWork` is available only during the coordinator's check
callback. Its complete command and initial/final phase are available only to
the selected instance. Bounded queries and existing credential, directory and
user-authorization checks share the original transaction and lock lifetime;
there is no write or transaction-closure method. Ignored denial poisons Work.
Close all rows before returning; do not retain the handle or perform network
callbacks. The private persistence pipeline invokes initial admission before
locking/mutating the identifier partition or consuming its proof. Final
admission runs after provisional effects and before proof finalization and
terminal journal persistence. Each phase runs once; reentrant, duplicate,
out-of-order or failed checks poison the same Work.

`IdentifierAuthorityVersion` returns the original expected epoch initially.
At final admission it returns only the exact successor from this Work's owned
mutation receipt, with matching subject, intent, record, action and predecessor.
It does not replace the original session snapshot or renew its freshness.
Historical role-free provisional plans are unchanged; this optional role is
not sufficient to activate public execution.

These checks alone do not authorize mutation, consume proof, or
establish credential-specific reauthentication. Public identifier `Begin`
remains disabled until complete native session, access policy and recovery
composition exists.

## Scoped user authorization authority

Native participants can call `Work.RequireActiveUserAuthorization` with their
exact instance and a frozen `UserAuthorizationAdmission`. Bind all three
`authorization/postgres.AuthorityScope` fields and the expected positive epoch
into the native keyed command before reservation; compare that frozen intent
at execution. The namespace is trusted native configuration owning user-ID
uniqueness, not a request-selected subject kind. Subject must match the command's
effective `UserID`, not its separate actor or calling workload. Organization
and impersonation profiles require their own explicit authority contracts;
this user-only helper cannot approximate them.

The existing authorization owner performs its exact primary lookup through the
generation-bound `WorkRows`, retaining a share lock until the sole coordinator
commits or aborts. Missing or unequal epochs deny without creating defaults.
Malformed input, foreign invocation, cancellation and storage failures poison
live Work even if ignored. Earlier deadlines win and no freshness is renewed.
Use the owner's separately allocated forward-only authority migration through
the owned migration composition; do not copy its SQL or bootstrap during login.

This is a lifecycle epoch check, not policy `Allow`, authentication proof or a
completed session issuer. The existing policy engine, every other contributing
authority owner and atomic one-time proof finalization remain mandatory. These
admission checks are opt-in and existing participants remain compatible.

## Deployment and tenant authority

Compose `DirectoryAuthorityMigrationSource` into the single owned migration
history after its complete existing source. Allocate a permanent later version,
one explicit `GlobalAuthorityID`, and up to 256 exact initial `TenantIDs` from
trusted bootstrap configuration. The source creates independent full-width
epochs at version 1; it does not discover tenants from users, create missing
authority during authentication or modify user/credential versions. An empty
tenant set deliberately enables none. Tenant order is canonicalized; duplicate
IDs fail. Never edit the source configuration after its version is applied.

`Repository.GetDirectoryAuthority` returns a bounded structural primary
projection, including disabled tenant state. It is not authentication, an
authorization decision or renewable validity evidence. Missing exact scope
returns redacted `identity.ForbiddenError`; corrupt/unavailable storage fails
closed. No replica/cache fallback exists.

An exact active native participant can call
`Work.RequireActiveDirectoryAuthority` with `DirectoryAuthorityAdmission`.
Bind the deployment/tenant IDs and both expected epochs into the native command
before reservation, deriving deployment identity from trusted composition.
The helper retains share locks until the original coordinator terminalizes
Work. Missing, disabled or changed epochs poison the transaction, including
when a participant ignores denial after provisional writes. Earlier deadlines
still win; driver cancellation may leave `Unknown`, requiring existing command
recovery, never another command or an invented rollback acknowledgement.

These are current kernel checks only. Credential admission, scoped existing
authorization-owner checks, optional owners and one-time proof finalization
remain required before session issuance. Public tenant onboarding/transitions
and global-compromise lifecycle/cascade acknowledgements remain in development;
consumers must not replace them with SQL callbacks or mutate migration history.

## Locked credential eligibility

During its synchronous native feature invocation, a registered participant can
call `Work.RequireActiveCredential` with its exact instance and a frozen
`CredentialAdmission`. The native command must bind all expected fields before
reservation: credential reference/version plus independent user-authority,
identifier and user-wide credential epochs. The aggregate user version is not
a security epoch. Existing participants need not opt in.

The helper checks the current kernel rows under share locks retained until the
coordinator commits or aborts, then samples primary time for exclusive expiry.
Absent, blocked, disabled or stale credentials deny uniformly; an ignored
denial poisons Work and prevents commit, including earlier provisional writes.
No callbacks, external services or separate transactions run in this helper.

This is only kernel eligibility, not session issuance or bearer authentication.
Native issuers must additionally establish private proof provenance, current
global/tenant/authorization and optional-owner authority, and atomic one-time
finalization. The returned time is not a renewable validity lease. Real-primary
coordinator tests use a synthetic participant, not a completed session issuer.

Anonymous email/phone sign-in can use `Work.RequireRecipientCredential` with
the original `RecipientRecord` and `CredentialAdmission`. Their tenant, selected
user and all three security epochs must agree. The kernel rechecks the original
identifier/verification under retained locks before checking that exact
credential. It does not replace the anonymous command binding with the selected
user or rediscover a newer recipient. Bind both snapshots into original intent;
password verification and every other issuance policy remain the native owner's
responsibility.

During protected Apply only, `Work.FeatureCommandIdentity` returns owned copies
of the original binding, keyed fingerprint and reservation generation for native
effect correlation (including pre-auth consumption). Foreign, admission-only,
expired and returned invocations deny. This tuple is not proof, a new command,
or refreshed authority evidence; never log it or use it to reset freshness.

## Original-command capability issuance

`CommandPlan.CapabilityIssuance` declares 1..16 one-use grants and the exact
`capability/postgres` owner, contract `capability.issuance`, version 1. This
participant follows the base contributors and precedes optional delivery.
Its purposes name future protected operations, not the originating mutation.
Only immutable IDs, signed expiry/maximum, original-envelope fingerprints and
independently keyed replay metadata enter the journal. Nil retains historical
kernel, feature and delivery plan bytes.

The trusted issuing adapter stages authenticated `capability.Grant` values with
`Work.StageCapabilityIssuanceFor`. Every grant must match its plan position,
tenant, command user, purpose, ID, whole-second expiry and single-use maximum.
This profile requires subject-bound grants, not subjectless bearer authority.
Descriptor equality does not allow a foreign instance to stage custody.
The exact owner receives `CapabilityIssuanceWork` only during coordinator-owned
persistence; its aliases and SQL authority expire on return, including panic.
The owner must verify original-envelope and keyed replay provenance, insert
absent issued state and retain originating command/fingerprint/generation
separately from subsequent consuming-command identity. It must never resurrect
terminal records, open a transaction, sign, call providers, or retain the handle.

Issuance runs after the actual mutation and before delivery/audit/lifecycle and
the sole commit. Missing staging, failure/panic, later phase failure and expiry
before terminalization roll back the original mutation and issued records.
`RecoveryWork.CapabilityIssuanceBinding` exposes frozen metadata only to the
exact registered issuer; recovery never signs or reveals replacement tokens.
The optional versioned envelope composes with encrypted delivery and bounded
historical decoding, without a second ledger or coordinator.

No bearer bytes are staged or returned by this adapter. Queued credentials must
use independently authenticated encrypted delivery custody; synchronous custody
must not be revealed before a proven commit. Coordinator tests use an owned SQL
phase to prove transaction and lifetime semantics, not the unfinished native
capability producer, encrypted-delivery interoperability or end-user workflow.
Consuming capability-bearing domain execution remains disabled.

## Original-command encrypted delivery

`CommandPlan.Delivery` optionally declares 1..16 required effects and the exact
last contributor `identity/delivery/postgres`, contract
`identity.delivery.effects`, version 1. Its logical `IntentDigest` must bind all
behavior-affecting inputs using the owning workflow's confidential fingerprint;
randomized ciphertext is not logical replay identity. Safe effect/resource and
template IDs are 1..128 printable non-space ASCII bytes. Purpose is a canonical
lowercase event name; template/provider versions are positive. Expiry is an
exclusive post-epoch microsecond-exact instant, never renewed on replay.

The original owned delivery adapter stages prepared secret-envelope ciphertext
with `Work.StageDeliveryFor` and its exact enlisted pointer. Equal descriptors
or configuration do not allow another instance to stage its own preparation.
The existing `Work.StageDelivery` remains a trusted low-level composition seam,
not participant authentication. Each envelope is at most 524288 bytes and total custody is
at most 1MiB. Encryption/provider work must happen before opening the mutation
transaction. Only the coordinator invokes the exact enlisted
`DeliveryContributor.PersistDelivery`. During that synchronous invocation,
`DeliveryScope` exposes an owned original-command declaration and
`StagedDelivery` returns copied ciphertext. The owner must verify complete AAD
and confidential logical input, and persist custody plus outbox admission via
this Work. Neither a descriptor nor this plan authenticates an HTTP caller.

Missing staging, persistence error/panic, later audit/lifecycle failure, or
expiry before terminalization rolls back the original mutation and delivery.
Recovery invokes every frozen participant; `RecoveryWork.DeliveryScope` allows
only the exact enlisted owner to inspect its original declaration. Unknown or
conflicting delivery evidence cannot prove noncommit. No second enqueue command,
transaction, sender invocation, or workflow engine exists here. The optional
versioned plan envelope conserves historical base-plan bytes and excludes
ciphertext from command journals. Closed Work drops custody references; this
does not promise secure erasure of Go heap bytes or caller-owned copies.

Coordinator integration tests use a deliberate owned SQL seam. They are not
production queue/envelope/provider interoperability proof: those remain part of
the separate, unfinished `identity/delivery/postgres` implementation.

## Typed one-use risk reservation

`CommandPlan.RiskEvidence` declares the scalar projection of risk's signed
`PreparedEvidenceUse`. No bearer, provider facts or keys belong in the plan.
Preparation owns copies and freezes every declaration field in the distinct
`identity-feature-risk-plan-v1` profile. Existing feature v1/v2 bytes are unchanged.
Only the exact native `identity/phone` operation
`identity.phone.password-reset-request`, schema
`identity.phone.password-reset-request.native-v1` version 1, required-record
profile with subject kind `phone`, is admitted. This is not the public HTTP
request schema. Other schemas and reset completion are rejected, not approximated.

Enlist the exact `identity/risk/postgres / identity.risk.store / 1` participant
implementing `RiskReservationContributor` alongside the identity, audit, outbox
and native phone contributors. `ReserveCommand` invokes `ReserveRiskEvidence`
or exact-predecessor `RebindRiskEvidence` inside its existing command reservation
transaction. Participant failure, panic, poisoned SQL or unclosed rows rolls
back both command and evidence ownership. A live command replay skips mutation.
The invocation-only `RiskReservationWork.Binding(participant)` verifies the
exact registered instance; retained copies cannot run SQL or disclose bindings.

The risk adapter must authenticate the projection, compare the native command's
complete recovery scope and current policy, then lock the already-issued row
using primary time and original expiry. Structural preparation is not that
authentication. `CheckedAt` preserves nanoseconds; compare it against returned
primary time without rounding or passing it as a microsecond-only SQL parameter.
No method refreshes the precheck or evidence lifetime.

`RiskReleaseContributor` adds native retained noncommit evidence through
`RecoveryWork.RiskBinding(participant)` and terminal release through an
invocation-only `RiskReleaseWork`. Recovery requires this phase before taking
over ownership. Under the primary command and tenant fences, every frozen
participant must prove noncommit before risk release, failure audit and aborted
receipt commit in one transaction. Missing, mismatched or unknown native
custody must remain unknown. Evidence expiry neither proves rollback nor
reactivates a reservation; proved noncommit releases even expired reservations.
Audit/release errors, panics, poisoned SQL and open rows roll back takeover,
release and terminal receipt together. The new recovery generation never grants
domain authority. Terminal receipt replay invokes no new participant mutation.

After a proved nonretryable domain rollback, `Abort` instead rechecks the same
live owner and frozen plan, acquires the tenant exclusion, and releases custody
in the failure-audit/aborted-receipt transaction. `RiskReleaseWork.Binding`
returns that current generation in both generation fields; an owner that took
over generation 2 releases generation 2, not its former predecessor. Private
coordinator provenance distinguishes this path from successor-generation
recovery without widening reservation/rebind authority. Missing failure audit,
release phase, matching custody or live ownership retains pending/Unknown;
errors, panic, open rows and poisoned SQL leave no durable terminal prefix.

The same proven-rollback rule applies to `CapabilityReleaseWork`: Abort
terminal-releases the exact reserved capability under the current generation
only after rollback, live-owner/frozen-plan rechecks and tenant exclusion.
Release, failure audit and aborted receipt commit together; a missing phase,
wrong custody, failed rollback, lost owner or callback failure leaves Unknown
and no terminal prefix. Recovery release still advances exactly one generation.
Private release provenance cannot be reused as reserve/rebind authority.
Release is terminal, not permission to reuse the proof, and does not enable
the still-incomplete protected identifier workflow.

`RiskExecutionContributor` is the separate opt-in for domain execution. The
exact registered owner must implement pure `ValidateRiskEvidenceCommand`,
read-only `CheckRiskEvidence` and terminal `FinalizeRiskEvidence` in addition to
reservation, recovery and release. Reservation/release-only owners remain
closed at `Begin`. The coordinator compares the entire original command before
any effect, checks risk immediately before native feature mutation, and checks
again after provisional audit/outbox persistence. It then finalizes the exact
reserved row in that same transaction before terminalizing the command receipt.
The native owner must authenticate complete recovery scope, current policy and
provider versions, original exclusive expiry, current counters and journal
custody; finalization must recheck expiry and CAS the original generation.

`RiskApplyWork` exposes bounded reads/primary time and immutable native input
only to its exact owner. `RiskFinalizeWork` additionally permits bounded trusted
terminal SQL. Both are invocation-only, redact diagnostics, reject serialization
and share the domain Work's nonrenewing budget; no raw driver or transaction
closure is exposed. A retained apply handle is already invalid when finalization
begins. Neither copies nor late effects renew original evidence freshness.
Errors, panic, SQL poisoning and unclosed rows roll back domain effects,
finalization, audit/outbox and receipt together; the existing proved-noncommit
release protocol then terminally releases custody. Unknown commit never implies
release or reuse. Exact committed replay does not invoke the phases again.

This boundary does not yet enable phone recovery. The official risk adapter
still supplies only reservation/release, and must implement native current
checks and finalization before adoption. OTP/capability issuance/consumption and
phone orchestration remain required. Applications must not provide their own
SQL participant to substitute for the owned adapters.

## Trusted command admission observation

### Protected counter reservation

Counter-bearing domain execution additionally requires the exact registered
owner to implement `CommandCounterAdmissionContributor`. Reservation-only
participants still cannot open `Begin`. The new `CheckCommandCounters` phase
receives `CommandCounterAdmissionWork` immediately before native feature mutation
and again after audit/lifecycle persistence, before terminal commit. It must
recheck exact current-generation charge custody, policy, original evidence expiry,
authoritative counters and any explicitly selected lockout/override policy.
It must not increment, refund, refresh original observations, invoke providers
or open its own transaction. This bounded invocation exposes reads/primary time
and the original immutable command only to that instance, then expires.
The coordinator retains command input only in memory until Work closes.
The feature owner still owns current user/credential/organization/factor checks.

Late denial rolls back all provisional domain effects and persists classified
failure audit/aborted receipt through the ordinary proved-rollback path. Its
original charged attempt remains committed. Errors, panics, SQL poisoning or
unclosed rows fail closed. Counter and one-use risk declarations are distinct
closed profiles; neither substitutes for the other's authority. The native
adapter must implement the selected current-check contract before real protected
workflow composition can use either opt-in.

Native protected-feature composition may declare `CommandPlan.CommandCounters`
with the core's complete keyed counter fingerprint and risk-policy version.
It must enlist exactly one `identity/risk/postgres` participant implementing
`CommandCounterContributor`, in addition to the native feature, kernel, audit
and lifecycle participants. Both the feature owner and risk participant perform
pure native validation before the first SQL write. No raw subject/network
dimensions are serialized into the frozen plan; historical feature-plan bytes
remain unchanged when this profile is absent.

`ReserveCommand` calls that exact participant under the existing primary
command/tenant exclusions. `CommandCounterWork` returns frozen binding and the
immutable original native command only during its invocation; aliases and rows
must not be retained. Allowed disposition commits the charge and its original
snapshot with pending command ownership. Denied disposition commits the charge,
all declared denied audit slots and the aborted command receipt together, with
no domain mutation or successful lifecycle event. Returning an error instead
rolls back the reservation unit; SQL before commit is provisional. A commit
attempt error returns Unknown even when a deferred constraint rejects commit.

Live/terminal replay bypasses mutation. Expired-owner takeover supplies the
exact predecessor/current generation and must reuse the original charge, never
increment or refund it. `RecoveryWork.CommandCounterBinding` exposes exact
charge linkage to its registered owner for read-only reconciliation: a charged
reservation is prerequisite evidence, not proof that the domain committed.

The real risk adapter's durable counter storage/rotation/algorithm and current
domain checks are still being implemented. Counter-bearing `Begin` and
`ApplyFeature` therefore remain disabled. SQL integration seams prove this
coordinator boundary, not password workflows or native risk interoperability;
applications must not supply a replacement counter store to fill the gap.

Native feature adapters may configure `CoordinatorConfig.AdmissionPolicy`
separately from `QueryPolicy` and call `ObserveCommandAdmission(ctx, query,
caller)` before evaluating external providers. The current policy receives owned
`identity.command.read-admission=true` and `identity.command.recovery=false`
attributes; caller, tenant, operation and `identity.user` resource must match the
query at the configured revision. Only an authorized actual absent global claim
returns `CommandAdmission{Absent: true}`. Denial, wrong scope, retired claims,
orphan journals, corrupt history and outages never become absence.

Existing claims return only safe `CommandRecord` history and its original
terminal classification; expired pending commands remain pending. No command
or participant is reserved, repaired, locked, renewed or invoked. This is a
trusted native composition API, not a client lookup route. `QueryPolicy` alone
does not enable admission, and `AdmissionPolicy` alone does not enable lookup.

Absence is a point-in-time observation, not a reservation or proof that an
earlier ambiguous submission rolled back. A concurrent command may appear
immediately afterward. Native adapters must compare their own retained
pre-evaluation intent before replaying protected results, and must still submit
through `ReserveCommand` for the full immutable command collision fence. This
method neither returns nor verifies native bearer/proof payloads.

## Primary credential eligibility metadata

Compose `CredentialMigrationSource{Base: existingHistory, Version: allocated}`
with the owned migrations runner, after every installed kernel/session/status
migration. It adds non-secret references and the independent tenant/user
`credential_version`; existing status, aggregate and identifier epochs are
unchanged. Old creation writers receive epoch 1 but no fabricated reference.
Keep disabled references as retained state; this migration never re-enables one.
Down SQL is unsupported. Expiry is nullable (indefinite), otherwise finite UTC
microsecond precision, strictly after the Go zero instant and before year10000.

`Repository.GetCredentialAuthority(ctx, identity.CredentialAuthorityQuery{...})`
implements the core port with one consistent primary statement matching exact
tenant, user and credential ID. Missing schema fails unavailable, not absent;
missing exact references return `identity.ErrUserAbsent`. All versions preserve
full uint64 precision, with no aggregate/security/credential substitution.
Blocked users, disabled references and expired instants remain visible to
`identity.CheckCredentialAuthority`, which denies them rather than repairing
stored state. Earlier caller/configured deadlines bound reads; driver details
and partial records do not escape failures.

This is metadata eligibility, not secret verification, factor/provider status,
authentication proof, authorization or a cache freshness lease. Credential
reference mutations, their atomic epoch bump/audit/outbox and final proof
consumption are still under development; applications must not supply private
SQL callbacks to replace them. User-owned references do not represent
organization-owned API-key authority, which belongs to its separate owner.

## Durable user-status admission

Opt in with `StatusMigrationSource{Base: MigrationSource{}, Version: allocated}`
and the owned migrations runner. Allocate its version after every composed
kernel/session migration; do not renumber installed history. Migration defaults
persist user-security epoch 1 and no legal hold while preserving every existing
status, aggregate version and identifier epoch. They also keep prior creation
and ordinary field writers compatible. A database missing this migration fails
closed; readers never invent security versions.

`Repository.GetStatus(ctx, identity.UserStatusQuery{TenantID: tenant, UserID: user})`
implements the core primary status port. `User.Version` is aggregate CAS;
`AuthorityVersion` is the independent user-security epoch. Profile and ordinary
administrative field edits advance only aggregate CAS. Suspend/ban and
restore/unban advance both, so restoring eligibility cannot restore old vectors.
Expired restrictions remain blocked until a fresh audited restore/unban.

Construct `NewStatusUnitOfWork(coordinator, repository, config)` with the exact
enlisted repository and typed audit/outbox contributors, then pass it and the
repository to `identity.NewUserStatusService`. That service supplies current
authorization, policy admission and redaction; calling the adapter directly is
not an authenticated endpoint. Configuration contains the same explicit status
policy/reasons as the service, a positive status-policy revision, finite cascade
deadline and reviewed version/fingerprint for every exact manifest consumer.
These are deployment metadata, not consumer stores or callbacks. Every change
to that configuration needs a new status-policy revision. The owner durably
rejects conflicting definitions for an already-used tenant/revision.

One shared commit persists status, reason/absolute expiry, both successors,
random cascade ID/generation 1, exact manifest and ordered consumer contracts,
trigger event/version, deadline, current legal-hold state, audit, lifecycle and
original receipt. Row locks precede the final primary-time expiry check. Exact
replay precedes current CAS and retains original IDs, timestamps and consumers,
even after restoration or a composition change. Preserve command identity and
use `Recover` after unknown closure; recovery never reexecutes the mutation.
Retain cascade admission rows alongside non-reassignable command evidence;
current user state or pruned payloads cannot substitute for retained evidence.

The returned cascade is **pending**. This admission path does not acknowledge
consumers, complete cleanup, manage legal holds, or implement cascade closure.
Those remain distinct generation-bound phases. Nor does a primary status read
alone establish authenticated session issuance or the shared-issuer 30-second
cache/resource guarantee; actual proof consumption and all authority owners
must still be composed. All epochs retain full unsigned 64-bit precision;
exhaustion denies a successor rather than resetting or wrapping.

Experimental Go 1.27 module implementing `identity.UserDirectoryRepository` using
the owned `go-postgres` pool. Tenant and user IDs are matched exactly; lifecycle
states and the full uint64 version range are preserved. Reads are primary-only,
bounded and uncached. Configure primary endpoints explicitly.

Construct with `NewRepository(pool, Config{MaximumDuration: time.Second})`, then
compose it through `identity.NewUserQueryService` for policy and redaction.
The caller owns pool shutdown. No globals or background goroutines are created.
Driver errors are discarded rather than exposed through `errors.As` or logs.
Cancellation and deadline classifications remain observable.

## Feature operation registration

Durable feature adapters may implement `FeatureContributor` alongside the
existing `Contributor`. The same immutable registry snapshots their compile-time
`identity.FeatureOperation` descriptors once, including all supported schemas,
explicit record policy and exact adapter owner.
An explicit `SubjectRequirement` also freezes the user or anonymous-flow
namespace. Anonymous feature scope persists `AnonymousFlowID`, never a fake
`UserID`; current-policy admission/query/recovery must use the exact
`identity.anonymous-flow` resource and retain the separately verified actor.
Record-free audit/lifecycle targets use that flow ID. User-only descriptors
retain their existing canonical command/plan bytes and JSON receipt shape.
This uses existing command claims/journals; no extra replay owner or schema
migration is introduced. Concrete CAPTCHA persistence remains separate work.

Each core owner maps to its
`<owner>/postgres` adapter; each operation belongs to one exact contributor
across schema versions and subject namespaces. A schema/version may declare
both user and anonymous-flow subjects; selection still matches the complete
descriptor. Duplicate/conflicting schemas within a subject and foreign ownership
fail construction before any transaction opens. Limits are 64 declarations per
feature contributor and 1024 total. Legacy contributors need no new methods.

`ContributorRegistry.FeatureOperations` returns an owned scalar projection for
trusted composition; it performs no callbacks. This is **not** enabled-feature
discovery, registration of codecs, authorization or execution readiness.
Kernel command plans remain closed. Native non-one-time feature execution uses
the same coordinator; production session issuance remains in development.
Do not advertise routes from these declarations or substitute private journals.

The existing private command codec also maps immutable `identity.Command`
feature inputs for future owned phases. Exact owner/record policy and every
named scalar kind/value affect the keyed fingerprint; all scalar values are
conservatively digested before canonical encoding. Scope remains separate from
private intent, and retained-key replay regenerates the original fingerprint.
This is not schema validation or execution readiness.

Opaque `Command.OneTimeCode` custody contributes a separate `one_time_code`
payload digest using the fixed canonical path `one-time-code` and the existing
`identity-command-secret-v1` profile. Raw code bytes never enter canonical
payloads or safe collision fields. Absent custody preserves historical bytes;
replay recomputes from the immutable submission under the stored retained key.
The central preparation path rejects these commands before generic feature
admission. Fingerprinting alone does not count attempts or consume challenges;
native OTP reservation/current/finalize/recovery phases remain required.

`CommandPlan.OTP` freezes the complete server-issued attempt projection: random
attempt ID, keyed attempt fingerprint and version, challenge/scope digest,
digest-key version, expected challenge version and check/consume mode. It is
private correlation, not proof or current authority. Historical decoding binds
all fields and supports optional CAPTCHA/risk declarations without creating a
second journal. Generic feature admission remains closed to OTP custody.

For a native `OTPAttemptContributor`, `PrepareOTPAttemptPlan` authenticates the
original opaque submission through that exact registered owner before SQL.
`RecordOTPAttemptDenial` then locks the existing command before the owner's
bounded challenge comparison. The owner proposes the wrong-attempt charge and
exhaustion; the coordinator commits these with required denial audits and the
aborted command in one transaction. No risk, CAPTCHA, capability or session
reservation runs on this narrow path. Exact retries return history without
another comparison; changed code or attempt conflicts. `OTPAttemptUnchanged`
rolls back provisional effects and grants no successful precheck or reservation.
Returned callback handles cannot access SQL or opaque custody.

Native metered checks use the additive `OTPMeteredCheckContributor`, the same
OTP owner as the declared record-free feature, and an exact `OTPCheck` plan.
`RecordOTPMeteredCheck` uses the existing transaction and journal to commit
check/total counters with required audit and a redacted check receipt. It does
not invoke domain application, risk/capability consumption, lifecycle delivery
or session effects. `OTPAttemptChecked` is accepted only on this explicit path;
the existing denial path cannot turn a correct check into success.

For correct checks, `CommitOutcomeCommitted` describes committed metering only,
not authentication proof, reservation or protected mutation. Wrong checks retain
the denial outcome; disabled/exhausted checks roll back unchanged. Exact replay
does not compare or charge again. `RecoverOTPMeteredCheck` binds the original
attempt plan and current query authorization to retained check history without
needing a bearer/code or granting current authority. Commit ambiguity remains
Unknown and must be resolved through the original command, not a new attempt.

Any commit-attempt error is Unknown. Keep the original command and complete
attempt identity; `RecoverOTPAttemptDenial` uses the configured current
`QueryPolicy` and one primary read without code, comparison or mutation. A
historical denied result is NotCommitted plus Forbidden. Changed attempt fields
return no history. Pending remains InProgress, including after lease expiry;
it never authorizes a replacement submission, takeover or challenge release.
The production OTP adapter and composed protected workflow remain required
before adopting a complete OTP workflow.

`OTPReservationContributor` additionally enables `PrepareOTPReservationPlan`
and `ReserveOTPCommand` for consuming mode only. Its reserve callback runs last
after the existing one-use participants inside their shared claim/journal
transaction. Native failure rolls back every prefix; a commit-attempt error
returns Unknown and no ownership. A live same-command retry does not compare
again. Expired-owner takeover invokes only exact predecessor CAS rebind, never
reserve/comparison, and cannot transfer another command or generation. Returned
reservation handles enter `Begin` only when the same exact registered owner
implements `OTPExecutionContributor`. Current checks run before protected
mutation and again before finalization, without another code comparison or
attempt charge. `OTPApplyWork` permits only primary reads; apply/finalize
`CommandSpec` returns code-free feature scope. `OTPFinalizeWork` terminal CAS,
domain effects, audits, outbox and original receipt commit together. Returned,
foreign and wrong-phase handles deny. Callback failure, panic, unfinished rows
or poisoned SQL roll back all provisional domain/finalization effects.

`OTPReleaseWork` runs only after proven domain rollback or unanimous retained
primary noncommit evidence. `RecoveryWork.OTPBinding` exposes exact frozen
challenge/attempt/command linkage to that native owner, never submitted code or
release rights. Missing/divergent evidence, ambiguous commit and expired leases
do not release a challenge. Release is terminal: a new challenge is required,
not reuse of the released OTP. Release failure retains reserved custody and a
pending journal. These coordinator phases are tested with native SQL fixtures;
the production OTP store, cryptography and authenticated final-login admission
remain required. They are not an adoptable complete OTP workflow.

`CommandPlan.Feature` selects one exact frozen registration. Public
`PrepareCommandPlan` copies the matching contributor order, 1..64 strictly
ordered required audit slots and lifecycle declaration, and computes
`FeaturePlanDigest` using the current retained-key command fingerprint. The
preparation profile requires identity, audit, lifecycle/outbox and the exact
feature contributor; audit/outbox contributors must implement their typed phases.
Each audit slot has exactly one record, schema 1, positive retention version and
at most 16 KiB record/aggregate bounds. Required record lifecycle versions are
one checked successor; record-free declarations keep both zero. Feature-owned
adapters remain responsible for exhaustive native schemas and action policy.
Feature capability/cascade inputs fail rather than being silently discarded.

An empty `CommandPlan.SubjectType` retains the historical v1 structural-only
profile and cannot reserve. For native execution, select a valid subject type
and explicit `AuditPlan.RetentionClass` (`standard` or `protected`) for every
slot. These fields are bound into canonical feature-plan-v2 bytes. The native
adapter must implement `FeatureExecutionContributor`, exhaustively validate the
immutable command and full security plan before reservation, and inspect retained
effects during recovery. Every selected participant must implement recovery.

Use `FeatureAuditBindingDigest` for exact feature scope, subject and actor binding.

Native adapters call `Work.FeatureScope(themselves)` during Apply and
`RecoveryWork.FeatureScope(themselves)` during recovery to verify the exact
registered instance, active invocation and frozen version transition. Matching
descriptors or a still-open Work after Apply returns are not native authority.
The check performs no IO and returns owned scalar scope declarations.
Then `PrepareCommandPlan`, `ReserveCommand`, `Begin`, `ApplyFeature` and `Commit`
execute through the sole coordinator-owned transaction; always defer `Abort`
after a successful `Begin`. The native phase owns current authority checks and
its domain mutation, never kernel-table writes, audit/lifecycle staging, external
IO or transaction closure. The coordinator binds the provisional receipt to the
frozen transition and stages all audit/lifecycle effects. Only a successful
`Commit` proves durability; ambiguous commits return unknown and never locally
retry or reveal a bearer. Exact replay returns the original safe receipt.

Historical feature plans and command scopes are decoded as bounded, canonical
records. Authorized `QueryCommand` returns an owned `CommandRecord.Feature`
descriptor for feature history; it remains nil for kernel history. The stored
scope, frozen plan and terminal receipt must agree on owner, operation, schema
and record policy. Observation does not consult today's contributor registry,
replay commands, renew authority or expose native response/credential payloads.
Missing, wrong-scope and denied callers retain the same policy/read shape.

`RecoverCommand` observes live/terminal history. Expired native v2 commands can
take a new generation only with the exact frozen typed participants. Unanimous
retained non-commit evidence permits failure auditing and an aborted receipt in
one transaction. Unknown/conflicting evidence stays pending; success is never
reconstructed from current rows. Audit recovery can obtain an owned copy of all
slots through invocation-scoped `RecoveryWork.AuditPlans`; the existing singular
getter still rejects multi-slot plans. Historical v1 remains observation-only
and never takes over. Capability and OTP-consuming profiles remain disabled
until their atomic typed phases exist; risk consumption additionally requires
its native current-check/finalize owner. This is not a working session issuer.
Kernel digest bytes and the kernel-only scope decoder remain unchanged.

## Stable status-filtered listing

Compose the same repository through `identity.NewUserDirectoryService` for
collection/row authorization, redaction and authenticated wire cursors.
`List` materializes structural IDs, statuses and versions atomically in the
primary database; it is not a live OFFSET query or an authorization cache.
Migration 7 creates the owned snapshot/row tables without changing users or
migrations 1–6. Existing get-only consumers keep their APIs and configuration.

Ordering is bytewise ascending canonical user ID. Filters are an exact closed
status set. Continuations require the original tenant, status set and expiry,
and survive repository replacement and live insertion/update/deletion.
Expiry retains nanosecond identity, lasts at most 15 minutes and cannot be
renewed; primary time plus a shortened local deadline bounds each operation.
Snapshot status is historical directory data, never current identity authority.
The public service must reauthorize every page and each scanned row.

`Config.ListSnapshots` defaults to 10,000 users and 32 retained snapshots per
tenant. Explicit profiles require both positive limits, at most 100,000 users
and 32 snapshots. Pages are at most 100 rows. Each status branch uses the
existing tenant/status/user index and bounds candidates before materializing.
Quota or size pressure is `identity.UnavailableError`, never a partial snapshot
or silent truncation. Mismatched/expired continuations are redacted invalid
input; database failures disclose no diagnostics. An ambiguous snapshot commit
returns no page/cursor and remains bounded by retention/quota.

New snapshot admission removes at most one expired snapshot. Trusted platform
maintenance must also call `PruneUserListSnapshots(ctx, tenant, maximum)` for
inactive tenants, with `maximum` in 1–32; primary expiry and SKIP LOCKED keep
active/in-use snapshots intact, and removal cascades to their rows. The library
starts no worker and never closes the caller's pool. These storage APIs confer
no tenant permission. Grant the selected storage role the snapshot-table CRUD
and existing user SELECT permissions; no DDL or table ownership is required.

**Remaining scope:** exact identifier filters require the remaining identity-
owned identifier lifecycle store and fail closed today. Arbitrary attribute
search, complete fields, privacy/lifecycle snapshot erasure and full domain
commands remain unfinished. Do not create a list-only identifier authority or
application-written domain store to fill those gaps.

## Current development boundary

### Consistent self-profile reads

The repository also implements `identity.ProfileRepository`. Select it explicitly
with `Config.ProfileSchema: ProfileSchemaRef{ID: "fields", Version: 1}` and
declare that same schema in `Config.AttributeSchemas` and
`identity.ProfileConfig.Fields.Schema`. Zero leaves profile reads disabled.
The selected schema must contain at most 123 additional fields, without aliases
for name/image, credentials, identifiers, roles or other privileged core fields.

`GetProfile` observes the user, name/image and typed attribute document in one
primary SQL statement. The stored schema key and immutable definition must match
the selected declaration exactly. A missing structural user is `ErrUserAbsent`;
an incompatible/corrupt stored document is `Unavailable`, with no partial output.
The whole document is validated even for a narrow projection. Empty requested
fields select all output-readable fields; explicit fields must be unique and
known, with schema output permission. Structural ID/tenant/version remain bound
to the aggregate; unselected values are not returned. Returned collections own
their memory. Existing false/zero/empty values and full versions remain exact.

Forward migration 8 adds the owned `identity.user_profiles` name/image table.
It preserves migrations 1–7, structural-only users and old writers. Missing rows
produce empty name/image, not invented additional-field defaults or backfills.
No independent profile version or authority is created. Grant selected storage
roles SELECT on profile, attribute and schema tables along with user reads.

Compose through `identity.NewProfileService` for current-human self scope,
active status, authorization, schema output filtering and current redaction.
Storage reads confer no caller authority. Database image strings are bounded,
never fetched, and still require the public service's exact HTTPS origin policy.
The existing creation UnitOfWork can supply the service's dependency for reads;
select the profile composition below to enable mutation and recovery. Indexed/
secret storage and privacy erasure remain required platform work, not
application-written repositories or SQL workflows.

### Durable self-profile mutations

Use `NewProfileUnitOfWork(coordinator, repository, CreationUnitOfWorkConfig{
RetentionPolicyVersion: revision})` as the `identity.NewProfileService` command
dependency. It requires the exact registered repository, selected ProfileSchema
and typed audit/outbox phases. The existing creation owner remains creation-only.
This is an opt-in composition of the same Coordinator, not another transaction,
claim, receipt or recovery engine. No caller-written plans or SQL are needed.

`ProfileUpdate` admits current self scope and per-field policy before SQL.
The storage owner resolves exact command replay before CAS, then requires an
active user at the expected aggregate version. Name/image omissions preserve
existing values; explicit additional false/zero/empty values replace only their
named fields, preserving all omitted values without default backfills. Selected
schema definitions must agree exactly. Name/image, the canonical typed document,
one full-uint64 version increment, privacy-safe `identity.user.update` audit,
`identity.updated.v1` outbox event and original receipt commit atomically.

`RecoverProfileUpdate` and exact retries preserve the original result after
later mutations; current authorization/redaction still control its disclosure.
A changed command conflicts; stale or blocked new writes close with audited
NotCommitted and no domain/outbox prefix. Participant failure/panic rolls back;
unproved or ambiguous closure remains Unknown. Expired pending recovery requires
all frozen participants' negative evidence. The domain's original unchanged
version is negative evidence under the journal and tenant fences; a missing or
changed aggregate remains unknown, never inferred success. No fresh authority,
session, provider call or background worker is created.

Storage roles need UPDATE on users and SELECT/INSERT/UPDATE on profile/value
tables, with SELECT/INSERT on immutable schema definitions and the existing
command, audit and outbox permissions. Migration 8 already supplies profile
storage; migrations 1–8 and existing structural writers are unchanged.
The remaining kernel lifecycle profiles are unfinished.

### Durable administrative attribute updates

`NewUserUpdateUnitOfWork` supplies the existing `UserUpdateAdminService` with
the sole Coordinator's command protocol. Register the exact Repository and
typed audit/lifecycle phases as for creation. Select frozen `AttributeSchemas`;
the independent `ProfileSchema` feature is not required. Current operation and
per-field authorization remain in the core service, not role labels or direct
adapter calls. The current audit actor profile supports human and service
accounts; API-key actor composition remains unsupported and fails closed.

`ApplyUserUpdate` locks the authoritative aggregate and replaces individual
whole typed values, preserving omissions, explicit zeros, output-denied stored
fields, and the existing lifecycle status. Deleted/anonymized users cannot be
updated. The expected version fences exactly one full-width successor. Neither
name/image storage nor credentials, identifiers, roles or authority versions
are changed. Each command uses its exact registered schema ID/version; stored
definition mismatches and corrupt documents fail without a partial result.

One transaction persists the values, protected `identity.user.update` audit,
`identity.updated.v1` lifecycle and original structural receipt. Exact replay
precedes current-state CAS; a live parallel retry can return InProgress and
must retain the same command ID. Recovery observes the original receipt under
current core authorization/redaction. Expired pending commands close only with
the unchanged original aggregate version and negative evidence from every
frozen participant; missing/changed evidence remains unresolved. No second
transaction owner, callback inside SQL or migration is introduced. Storage
roles need the existing user and attribute/schema read/write permissions;
administrative updates do not require writes on the self-profile table.

Focused real PostgreSQL tests exercise these adapter semantics through the
public service with typed SQL audit/outbox test phases. Updated production
audit/outbox administrative composition and complete lifecycle/release gates
remain pending; the self-profile production composition is separately proven.

### Owned creation service composition

`NewCreationUnitOfWork(coordinator, repository, CreationUnitOfWorkConfig{
RetentionPolicyVersion: revision})` supplies the core `identity.UnitOfWork`
dependency for `identity.NewUserCreationService`. The exact repository instance
must already be registered with typed audit and lifecycle contributors. The
adapter owns plan construction, privacy-safe audit records, primary time,
reservation, execution, closure and scoped receipt lookup. Consumers do not
implement a domain store or supply Work, audit-record builders or command plans.

This is a trusted storage seam, not a transport endpoint: only the core service
provides current caller authorization, field preparation and output redaction.
Creation supports human and service-account actors; API-key actor audit mapping
remains unsupported and fails before reservation. Failure evidence is built
before domain writes and staged after proven rollback, never by unpoisoning SQL
Work. No success prefixes survive participant failure. A failed failure-audit
commit or ambiguous transaction remains Unknown. Replay preserves the original
receipt and audit ID, including after retained fingerprint-key rotation.

Recovery returns historical creation, not current user status. Live pending
returns InProgress without changing ownership. Expired creation can take a new
generation and atomically abort with failure auditing only when every exact
frozen contributor supplies `RecoveryContributor` and proves non-commit.
Missing, unknown or conflicting evidence remains pending. Existing users never
become reconstructed success receipts. Other command profiles, recovery-deadline
alerting and transaction retry policy remain unfinished. Existing test SQL
contributors prove coordinator atomicity, not production audit/outbox adapter
interoperability; that composition remains required before package completion.

`RecoverCommand(ctx, query, caller)` uses current `QueryPolicy` authorization
and returns metadata only; owned core recovery uses the trusted storage seam
without synthesizing caller identity. `RecoveryWork` is invocation-bound, exposes
only scope, bounded evidence queries and the participant's frozen declaration,
and cannot stage mutations or close transactions. Contributors read retained
bindings even when payloads have been pruned. QueryCommand remains observational.

`RecoverFeatureCommand(ctx, query, caller)` uses that same current disclosure
policy and recovery owner, but returns the full **safe feature receipt**:
original binding/operation, terminal audit ID and declared before/after versions,
or pending retry metadata. Kernel user/profile commands are forbidden before
reconciliation; generic `RecoverCommand` remains metadata-only. Missing commands
are never reserved. Unsupported expired participants leave pending evidence
unchanged; ambiguous commits return `UnknownCommitError` without credentials.
Feature receipts carry no session, proof or native response and grant neither
current authority nor credential reveal permission. Native feature adapters must
match their own exact retained intent/evidence and enforce current result-access
policy before composing recovery. Original frozen participants, not today's
domain state, determine the historical outcome.

### Primary command lookup

`CoordinatorConfig.QueryPolicy` optionally enables `QueryCommand(ctx, query,
caller)`. Configure the existing `authorization.Service`, a trusted `clock.Clock`
and positive current `PolicyVersion`; nil keeps lookup disabled. Policy callbacks
run before the single primary read, never under an open transaction.

Trusted authenticated composition supplies the `authorization.DecisionContext`:
the actor/kind, tenant, original operation and `identity.user` resource targeting
the query's user must match at that current revision. Do not decode caller
identity or authorization attributes from client overrides. Every historical
query field—including optional record ID and link mode—must match the stored
command. Current policy permits disclosure but never rewrites old policy/schema
versions or correlation. Reserved `identity.command.*` attributes are rebuilt
from the exact query: ID, record ID, decimal link mode and recovery/read-admission
flags cannot be replaced by caller attributes. Missing, wrong-scope and denied requests all perform
the bounded decision/read shape and expose zero receipt plus ForbiddenError;
this is not an identical wall-clock latency guarantee.

Pending, including an expired lease, remains InProgress. `CommandRecord` exposes
only historical scope, outcome and retry metadata, never stored profile,
attribute, account or credential payloads. It is not current user status or fresh
authentication authority. Protected replay values stay inside owned core
recovery and its current field-redaction policy. Orphaned,
legacy/incomplete or corrupt history fails closed. Lookup neither locks for
mutation nor changes a lease, generation or contributor. `RecoverCommand` and
the owned UnitOfWork service bridge remain unfinished; callers must not implement
their own transactions or participant recovery to replace them.

## Identifier and verification partitions

Apply forward migration9 before calling `GetIdentifierState`. It adds the
positive `identifier_version` authority dimension to users (initial version1)
and identity-owned identifier/verification rows. Existing users retain their
aggregate versions; structural writers that omit the new column remain valid.
The migration takes PostgreSQL DDL locks and validates the new user constraint;
run it through the bounded migration Runner during a reviewed migration window.
No destructive downgrade or application-written backfill is supported.

`GetIdentifierState(ctx, identity.IdentifierQuery{TenantID: tenant,
UserID: user, MaximumIdentifiers: 128})` implements the existing public storage
port. One indexed SQL statement returns the complete ordered partition or an
error with no partial state. The limit must be1..128; oversized partitions are
unavailable, not truncated. Missing users return `ErrUserAbsent`. The configured
repository budget and any earlier caller deadline bound pool acquisition and
query execution. Returned slices own their memory; the pool remains caller-owned.

Canonical values are exact, case-sensitive, at most512 UTF-8 bytes with no C0/C1
controls. Optional display values have the same bounds but may be empty. IDs
preserve the existing validated directory-ID profile. Record and canonical-value
uniqueness is tenant-local; canonical uniqueness also includes kind. A user has
at most one verified primary identifier of each kind. Verification state and
identifier flags share a row and database constraints; pending has no timestamp,
verified requires one, revoked may retain the original timestamp. Reads reject
future or otherwise inconsistent verification timestamps and preserve uint64
versions without signed-bigint truncation. Neither snapshots nor structural
validation grant authorization or prove a challenge.

`IdentifierMutationMigrationSource{Base: source, Version: allocatedVersion}`
appends forward-only retirement history after all migrations in `source`.
Allocate a unique version greater than every installed/composed Base version;
do not replace or renumber existing migrations. The new table retains tenant,
user and identifier IDs, exact retired record/verification versions, original
retirement and reuse-expiry instants, and a keyed digest rather than retired
canonical/display values. ID history remains necessary after a value cooldown
expires; this source intentionally supplies no deletion or downgrade policy.
Run it through the same bounded migration Runner in a reviewed DDL window.

Native provisional writes now implement all five identifier transitions under
the existing Work transaction. They lock the complete bounded partition,
preserve original verification instants, demote the old primary before promotion
and atomically persist retirement history with exact optimistic version fences.
Stored value-cooldown expiry is not renewed by key/policy changes; missing keys
for still-active history deny, while expired history does not require those
keys forever. Retired IDs cannot be attached anew even after value expiry.

This remains a storage foundation, not a complete identifier workflow. The
writer is private and public capability-bearing Begin remains disabled. Use the
existing `IdentifierService` for admission once native current-authority,
challenge/final-access checks, atomic capability/risk consumption, audit,
lifecycle, complete commit receipts and recovery composition are implemented.
Do not supply application-owned SQL or transactions to bypass those requirements.

`MigrationSource{}` owns `identity.users` with `tenant_id`, `user_id`, `status`
and `version`. Compose the source with the existing `go-migrations/v3` Runner
and PostgreSQL backend before constructing the repository. The source creates
no private ledger or migration runner. Initial install requires an unoccupied
`identity` schema and runs atomically. Replayed migrations preserve populated
data; destructive downgrade is unsupported. Future changes append history.

It is not yet an adoptable complete durable identity adapter. Do not
write application-owned identity tables or transactions to bridge that gap.
Commands, snapshots, attributes, imports, lifecycle cascades, audit/outbox,
reconciliation and the shared transaction coordinator remain unfinished.

The appended command-claim migration installs the global ID claim and scoped
journal foundation. Private admission runs inside the Coordinator's
transaction, never commits independently, and does not grant mutation authority.
Exact replay selects the stored fingerprint-key version; missing retained keys
or missing scoped rows fail closed. Retired IDs conflict permanently. The owned
retirement policy and scoped recovery still require implementation; the later
migrations provide leases, terminal receipts and frozen plans.

The private codec maps core commands, including privacy requests,
account link/unlink and all identifier actions, through typed accessors. It uses the closed
`identity-command-v1` deterministic encoding profile, framed HMAC-SHA-256
digests for all private fields, and stored-key regeneration on rotated-key
replay. Directory IDs retain their exact validated representation, including
ULIDs; random command IDs become fixed-width byte strings. Attribute times
must be microsecond-exact within PostgreSQL years 1..9999; no rounding is
performed. Equivalent whole-field replacement ordering does not change intent,
but list ordering does. No raw command, name, image or attribute value enters
persisted collision fields. Invalid command values fail closed.
Provider subjects/issuers, identifier values and the complete authenticated
capability authority are represented by framed keyed digests. Capability owns
its canonical payload representation; the adapter never JSON-serializes core
commands or consumes a proof during encoding. Proof header/key metadata, all
version fences, link modes, credential references, provider-revocation choice
and session/pre-auth continuations are included. A changed authenticated proof
is changed intent, not an implicit recovery credential. The claim phase does
not yet reserve or finalize proof use with a domain mutation.
The encoder follows [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949.html);
full protocol interoperability and release evidence remain pending.

The third forward migration extends the existing command journal with private
pending ownership, positive generation/attempt counters and database-time lease,
heartbeat and creation/update fields. Matching live reservations return bounded
retry delays; expired reservations acquire a new generation inside their caller's
transaction. Heartbeats cannot renew expired or stale ownership. A takeover is
not public apply authority: all declared participants must still be rebound in
that same transaction before the future Coordinator can commit it. No private
helper owns commit/rollback or infers a terminal result from lease expiry.
Foundation-only rows keep NULL ownership metadata and remain readable by older
claim code; the new reservation path rejects them until authoritative recovery
can prove their history. This migration does not fabricate ownership, classify
them as aborted or enable terminal rows without complete safe receipts.

The fourth migration enables committed/aborted rows only with a positive
supported receipt version, bounded body, database terminal time and closed
classification. Private terminalization locks and rechecks live generation and
owner; it never commits independently. Exact replay returns the original typed
receipt, not current user authority. Core `CommandResult.Validate` owns receipt
invariants; the private version-1 JSON storage representation rejects unknown
fields, duplicates, alternate spelling, lossy values and trailing input by
requiring exact re-encoding. JSON is not used for command fingerprints.
Retained attribute instants are encoded from an owned UTC copy and must be
microsecond-exact within PostgreSQL UTC years 1..9999. Second-offset time zones
cannot lose offset seconds in JSON, and caller-owned receipt values are untouched.
Receipts may retain authorized profile/attribute snapshots and private identifier
intent digests; treat this restricted replay storage as identity data under
retention/access policy, never logs, metrics or transport responses. Encoding
validates bounded core values before allocation; decode rejects bodies over
8 MiB. Required audit/participant staging and public scoped recovery are not yet
implemented, so private terminal SQL is not a conforming composed mutation API.

### Final-authentication coordinator admission

Configure `CoordinatorConfig.FinalAuthentication` with an explicit trusted
`authentication.AuthorityAuthenticator` and a stable durable namespace. Do not
derive either from request data or change the namespace while proof-use
tombstones exist. An exact registered `AuthenticatedFeatureContributor` owns
exhaustive native-command mapping and initial/final current-authority checks.
Its checks run inside the coordinator-owned Work and must not write, perform
network IO, consume proofs, renew freshness, or retain transaction authority.

Use `PrepareAuthenticatedCommandPlan` and `ReserveAuthenticatedCommand` with
the same original opaque proof and native command. The existing retained-key
fingerprint binds the original namespace, credential/proof IDs and versions,
scope, method, assurance, and exact original timestamps without exposing raw
correlations in canonical intent. Ordinary `ReserveCommand` cannot execute
`identity.session.issue`. Preparation validates provenance, not current
eligibility; reservation does not consume the proof.

Initial admission stages the proof-use tombstone in the same transaction as
native effects, audit, lifecycle and the terminal journal. Final admission
rechecks original proof expiry and native current authority. Failure rolls back
provisional effects and consumption. Exact replay returns historical metadata,
never a new bearer or refreshed authority; retained fingerprint-key rotation
preserves replay identity. Pending recovery cannot classify the kernel as
effect-free when a proof-use tombstone exists.

This is coordinator admission, not a session service: complete native
session/family issuance, their authority checks and recovery, bearer custody,
and composed login remain unfinished. The integration fixture's synthetic
feature proves coordinator atomicity only, not production session behavior.

### Domain begin admission

Private domain-begin admission now revalidates the retained-key global claim,
locks the scoped pending journal and verifies generation, owner and lease using
database time read after lock waits. A key rotation with the retained original
key preserves admission; changed intent, stale/foreign/expired ownership and
terminal rows never become apply authority. Missing history or keys fails
closed. The future Coordinator owns rollback on every failure and bounds Work
by the remaining lease; this private snapshot neither renews validity nor
begins/commits/rolls back a transaction or invokes participants. Public Work
issuance and complete Begin orchestration are still unavailable.

### Restricted Work execution

`Work` now provides `Scope`, `Exec`, `Query` and `DatabaseTime` for trusted
compile-time enlisted adapters. Its constructor is private; application code
cannot acquire valid Work until the complete Coordinator is available. All
aliases share generation, scope, deadline, failure and closure. Work/WorkRows
are serial, not concurrent APIs. The deadline starts before the authoritative
clock read roundtrip, cannot restart on construction, and is never renewed by
DatabaseTime. The coordinator must invalidate aliases/active rows before closing
its transaction and retain sole commit/rollback ownership.

SQL must be a trusted compile-time SELECT/INSERT/UPDATE/DELETE/WITH statement
up to 64 KiB with no more than 64 closed scalar parameters/1 MiB total. Inputs
do not admit driver options, query rewriters or custom marshalers. Extended
protocol executes the exact SQL through a fixed owned binary scalar profile,
even without parameters; prepared-name aliases and caller-installed codecs
cannot replace it. Multi-statements are rejected by PostgreSQL. Initial execution
errors are resolved before returning rows. `WorkRows` exposes no driver or connection and permits only closed
typed scan destinations, not RowScanner or custom scanners. It returns at most
256 rows, 64 columns and 1 MiB raw result bytes. Close rows before another
query, inspect Err, and discard all destinations after a Scan error. SQL/scan/
budget/cancellation failures poison further execution; diagnostics are redacted.
Empty byte parameters remain non-NULL and are copied before I/O.

This is not a sandbox for malicious adapter SQL, a tenant query rewriter, or a
bound on server-side query work. Contributors must use scoped/indexed statements
and cannot invoke functions changing transaction ownership/isolation or external
state. No raw transaction, connection, nested transaction or closure API exists.
Audit/effect writers, typed participant phases and complete Coordinator issuance
remain required next; this partial execution surface is not full command authority.

### Kernel audit admission

`AuditPlan`, `AuditBindingDigest` and `Work.StageAudit` now implement the kernel
staging boundary. Coordinator-private admission freezes the plan before SQL;
the current kernel mapping requires exactly one action for its command, including
the canonical user action for profile/admin aliases. It rejects empty, duplicate,
late or rebound plans. No public method can enlist an audit or obtain valid Work.
Records must match the declared index/action/schema, command, tenant, actor,
target aggregate, policy and correlation. Exactly one immutable record is staged
per index; missing or duplicated staging fails closed. Invalid staging poisons
Work. Record/aggregate bounds may lower the 16 KiB identity security ceiling.

The current kernel profile accepts privacy-processed no-change/redacted records,
closed aggregate/version/reason attributes, safe opaque context IDs and bounded
producer tokens. Free descriptions, raw network/user-agent data, unknown
attributes, arbitrary structured changes and delegation are unsupported and
rejected. Feature-specific fields, composed multi-action mappings and the typed
complete `IdentitySecurityEventV1` builder remain required implementation.
The identity profile requires 128-bit-or-stronger opaque IDs: configure
`audit.Builder` with a trusted random generator, such as `identity.NewSubjectID`,
before `Build`. The primitive default UUID has fewer than 128 random bits and
is not selected by this profile. Staging preserves IDs; it never derives them
from a command or replaces them. Canonical base64url 128-bit and lowercase hex
128-bit ID profiles are accepted; format validation cannot attest randomness.

This is owned in-memory staging, not persistence, an independently committable
audit transaction or complete command authority. The registered audit contributor
must persist each canonical record and its command/index binding through the
same Work; the future Coordinator must enforce completeness before commit and
retain denial/unknown recovery evidence. Those durable paths are not yet present.

### Contributor registration

`CommandPlan.Lifecycle` adds one typed kernel notification plus the exact
`outbox/postgres` `identity.lifecycle` v1 contributor. `Work.StageLifecycle`
constructs a safe scalar-only record with a stable command/class/index ID;
`StagedLifecycle` returns an owned snapshot only after successful required audit
staging agrees on its target and before/after versions. It accepts no arbitrary
payload, identifier value or bearer. The trusted adapter obtains occurrence
time from `Work.DatabaseTime`; staging itself does not perform I/O. Closed or
failed Work cannot produce notifications. Mismatches poison the Work.

The open `LifecycleContributor` will persist these records through the same
Work, not a separately committable transaction. Persistence, cascade consumer
snapshots/checkpoints, encrypted delivery/provider effect profiles and complete
Coordinator invocation are still pending. Older audit-only admission remains
compatible, but cannot satisfy a successful future mutation commit. The deletion
notification is `identity.deletion_requested.v1`, never proof of completed erasure.

`AuditContributor` supplies the open durable audit phase.
`Work.StagedAudits` exposes owned declaration/record pairs only when every
required slot is staged. The registered audit adapter uses this snapshot to
write canonical records and immutable command/index bindings through that same
Work. It cannot retain Work or own transaction closure; success is staging,
not commit. Complete Coordinator phase invocation remains under development.

`CommandPlan` declares ordered contributor descriptors, required audit slots
and a digest. `KernelPlanDigest` binds the current kernel-only profile to the
exact command scope and authoritative fingerprint using deterministic CBOR.
Admission snapshots the slices against the exact registry; later input mutation
cannot change admitted work. Audit binding rejects foreign-registry Work,
different commands and late/repeated enlistment before SQL.

This intermediate profile supports exactly one domain and one audit contributor.
It does not accept feature, risk, capability or OTP contributors without their
typed inputs; it cannot substitute for their atomic reservation. The Coordinator
must resolve retained-key fingerprints before plan admission. Public command
issuance, durable audit delivery and complete participant phases remain pending.

`CommandPlan.Capability` can now freeze one scalar, single-use capability input
for deterministic digest preparation and bounded historical decoding. It binds
the exact signed ID, purpose, expiry/use bound, independently keyed replay digest
and retained key version, and immutable proof fingerprint. The enclosing command
fingerprint binds target/version intent. Existing audit-only and lifecycle plan
bytes are unchanged. Formatting redacts this input and JSON export is rejected.
This declaration is not proof validation. Exact identifier commands can now
prepare/reserve when the registry supplies a `CapabilityReservationContributor`.
The coordinator freezes owned inputs, checks signed ID/expiry/use and target
versions, and invokes Reserve or exact-predecessor Rebind under the same claim,
journal and tenant locks. Failure, panic or unfinished rows rolls back every
prefix; returned invocation handles and rows cannot outlive the phase. Retained
fingerprint keys remain authoritative on replay. Contributors never own closure.
The additive `CapabilityExecutionContributor` seam provides separate
`CapabilityApplyWork` and `CapabilityFinalizeWork` invocations. Their bindings
select the original frozen input and current generation, never predecessor
release authority. Only the exact registered instance can inspect them; wrong
phase, foreign registry and retained copies fail. SQL uses the existing bounded
Work, with no pool, transaction closure or raw driver escape. Callback errors,
panic and unfinished rows poison the underlying work. These custody contracts
do not yet provide a production consumption algorithm or native identifier
mutation, and cannot consume an `authentication.AuthenticatedProof`.
`Begin` still rejects these reservations before consuming their opaque handle:
domain/session/risk/apply/finalize phases and the production
capability store are pending. No capability use or complete workflow is claimed
by a reserved journal. Existing creation/profile/admin composition is unchanged.

Expired identifier-attachment commands additionally support primary recovery
when every frozen contributor supplies `RecoveryContributor` and the capability
participant supplies `CapabilityReleaseContributor`. Missing targets and exact
reserved capability bindings are negative evidence, never sufficient alone.
Only unanimous non-commit evidence under journal and tenant exclusions grants
`CapabilityReleaseWork`; it CAS-releases the prior generation to a terminal
state with the new recovery generation. Failure audit, terminal capability and
aborted receipt commit together. Missing, conflicting or unknown evidence and
callback errors/panics roll back the entire takeover. Capability expiry does not
release an unknown outcome; terminal repeat returns the original receipt. These
SQL fixture tests prove coordinator atomicity, not production capability-store
composition. Other identifier operations and successful consumption remain open.

Contributor identities can now be composed with
`NewContributorRegistry([]Contributor{...})`. The registry snapshots 1..64
trusted compile-time adapter descriptors once, preserves composition order,
rejects nil/typed-nil, duplicate contract IDs and conflicting versions, and
allows only exact registered descriptors in private command admission. Owners
are bounded lowercase printable ASCII; contract IDs are bounded printable ASCII;
neither admits whitespace or normalization. Composition roots own canonical
IDs and contributor lifetimes. Returned `Descriptors()` slices are caller-owned
copies and registry reads are concurrent-safe. Implementations remain open to
independent modules. This is identity admission only: no transaction phase,
typed participant input, Work issuance, late registration or commit API is
provided by registration. Unsupported phase combinations and foreign plan rejection remain
part of the forthcoming complete Coordinator, not guarantees of this constructor.

### Command reservation

`NewCoordinator(primaryPool, registry, CoordinatorConfig{...})` owns bounded
reservation transactions. Configure positive operation/lease durations no longer
than one minute, a microsecond-exact lease, and 1..32 retained nonzero 32-byte
fingerprint keys with an explicit current version. Keep the pool primary-only
and caller-owned. Configuration/Coordinator diagnostics hide keys and reject
JSON serialization. Registration is immutable; contributor resources stay
owned by the composition root.

Use `PrepareCommandPlan(binding, typedCommand, plan)` to obtain an owned digest
with the current key, then `ReserveCommand(ctx, binding, typedCommand, plan)`.
The initial public profile requires user creation, one required audit slot and
the matching lifecycle declaration with typed audit/outbox contributors.
One-time and cascade profiles are rejected before SQL. Services must authorize
commands first; preparation is not authentication or authorization.

Migration 5 adds a bounded immutable canonical plan to the existing journal.
It leaves historical rows NULL, not invented participant history. A matching
replay uses the stored key version and fingerprint; key rotation cannot rewrite
the declaration. Changed scope, intent or plan conflicts; missing retained
keys, NULL historical plans and corrupt history fail closed. Plan replacement
is rejected by a SECURITY INVOKER trigger, not a defense against privileged
administrators or DDL owners. Cleanup remains the retention owner's obligation
and must preserve global non-reassignable claims.

A new or expired reservation returns opaque generation ownership and
`InProgress`. Busy replay has no ownership; terminal replay retains the exact
historical receipt, not current authority. A proven reservation commit is never
a user commit. Failures before durable observation or after proven rollback
return a zero result, not fabricated `NotCommitted`. Any commit-attempt failure
or unproven rollback returns `Unknown`; no automatic retry or rollback follows
a commit attempt. The detached rollback budget is finite and earlier operation
deadlines win. No contributor callback executes during reservation.

### Creation execution (development profile)

`Coordinator.Begin(ctx, reservation)` consumes exact ownership once and opens
one bounded primary transaction. Reservation copies cannot issue another Work.
The original lease is checked after command locks; waiting never renews it.
Kernel mutations also take a transaction-scoped tenant lock. Work and its
cursors are serial-use; every path must close through Commit or Abort, including
panic (normally with deferred Abort). No closure goroutine is started. An idle
transaction timeout limits abandoned server locks but does not substitute for
releasing the caller-owned pool connection.

`Repository.ApplyUserCreation(ctx, work, command)` requires the exact registered
repository and frozen creation command. It inserts an active version-1 user;
the returned user is provisional until Commit. Declare up to 32 copied,
versioned `Config.AttributeSchemas` for ordinary scalar/list storage. The exact
tenant/schema/version definition becomes immutable in the same transaction;
different definitions under that identity conflict. Undeclared fields/kinds or
unsupported indexed/secret profiles fail closed, not silently disappear.
Repeated apply poisons the transaction.
Stage the required successful audit with redacted structural changes and the
declared lifecycle record before `Coordinator.Commit(work, result)`. Commit
checks the caller result against the actual mutation, invokes the registered
audit then lifecycle persistence phases through the same Work, terminalizes the
journal and commits once. Missing evidence, open cursors, changed results or a
phase failure roll back all prefixes. All aliases close before transaction
closure. Any error after commit starts is Unknown, never automatically retried.

`Coordinator.Abort(work, cause)` proves rollback before a separate bounded
terminal transaction. A complete matching pre-staged denial/failure audit is
required for a known NotCommitted result; terminal audit and receipt commit
together. Missing evidence or lost ownership leaves pending/Unknown for recovery,
not fabricated success or denial. Detached cleanup remains bounded after caller
cancellation; driver and caller error text is never exposed.

Attributes use a private bounded version-1 canonical CBOR document, preserving
present false/zero/empty values, int64 extrema, ordered string lists and UTC
microsecond-exact instants without float conversion or JSON escaping growth.
They are private stored values, never diagnostic snapshots. Recoverable secret
fields require the future owned secret-envelope profile; there is no plaintext
fallback. Indexed fields need explicit field migrations, not arbitrary search.
Migration 6 adds schema/value tables without inventing values for old users;
old structural writers/readers remain supported. Definition update/delete/
truncate is rejected for ordinary writers, not hostile DDL/database owners.
Public reads still return structural fields only; field authorization,
redacted projection, attribute updates/backfills and secret/index profiles
remain required.

This is **not yet an adoptable identity.UnitOfWork**: remaining attribute profiles,
other domain commands, the owned service bridge, classified retries and scoped
query/recovery remain required. The integration suite proves actual PostgreSQL
transaction behavior with typed audit/lifecycle SQL seams, not production
audit/outbox adapter interoperability. Do not supply application-owned identity
transactions or stores to bridge the unfinished profile.

### Denial-only credential compromise

The registered password or passkey participant may implement
`CredentialCompromiseContributor` for its closed `mark-compromised` operation.
Its frozen command includes `CredentialCompromiseFields` plus native detection
and authorization metadata. The coordinator locks the exact user/reference and
checks the independent aggregate, credential-authority and reference versions
before invoking native verifier disablement. Banned/suspended and expired
credentials may be disabled; deleted/anonymized users and already disabled or
stale references are rejected. No credential is enabled or restored.

The existing outbox participant must also implement
`CredentialCompromiseLifecycleContributor`. Its same-Work phase persists both
`StagedLifecycle` and `StagedCredentialCompromise`, keeping all three version
dimensions distinct. These provisional values grant no current authentication
authority or cascade acknowledgement. Native mutation, kernel metadata, audit,
outbox and the original journal receipt use the sole coordinator transaction.
Only the shared commit establishes durability; replay preserves the original
receipt even after later changes. Retained participant evidence cannot be
replaced by a lookup of current credential state.

Compose `CredentialCompromiseMigrationSource` after credential-reference history
with an explicitly allocated later version; retain its evidence with command
tombstones. This is not password set/change/reset, passkey ceremony validation,
or production password detection. Those workflows still need their real native
owners, proof consumption and composed adapter evidence.

### Existing-password replacement

`CredentialReplacementContributor` enlists the kernel-owned effect for
`identity.password.change`. Its complete frozen command carries
`CredentialReplacementFields` and the native workflow's original policy intent.
For verifier writes use `identity.NewFeaturePasswordHashCommand`; native owners
select `PasswordHashFeature` and explicitly borrow `PasswordHash` for parsing
and SQL-driver storage. The coordinator binds exact hash bytes with the command
fingerprint key, never raw journal metadata. Changed verifier bytes conflict
with the original command ID, including terminal replay. Legacy hash-free
commands keep their encoding but cannot supply material through this custody.
The coordinator matches the native mapping, locks the primary user and password
reference, and checks active status, enabled state, expiry and all three exact
predecessors. Native hash replacement runs in the same `Work`; the kernel then
advances the user aggregate, credential authority epoch and reference version.
The credential's owner, identity, enabled state and expiry do not change.

Install `CredentialReplacementMigrationSource` after credential history with an
explicitly allocated later version. The existing outbox participant also needs
`CredentialReplacementLifecycleContributor`; persist `StagedLifecycle` and
`StagedCredentialReplacement` without conflating their version dimensions.
Native material, kernel metadata, audit, outbox and the original command result
share one recoverable transaction. Any failed phase rolls back all effects.
Pending-journal recovery treats retained effects as unknown, not success inferred
from the current credential. Exact terminal replay returns the original receipt.

This is a trusted persistence seam, **not an authenticated password-change
endpoint**. Native workflow composition must still own reauthentication proof
validation/consumption, HIBP, reuse policy, secret custody and session policy.
Do not supply application-written stores to bridge those unfinished workflows.
Registration, provider-only set, reset/recovery and hash-only rehash remain
separate pending profiles; this effect cannot enable or restore credentials.

### FAQ

- Can I use a replica? No; the repository's primary consistency contract is
  required for security composition.
- Are reads authorization? No; use the identity query service.
- Can I request extra fields? Only `id`, `tenant_id`, `status` and `version`
  are supported; unknown or duplicate fields are rejected, not ignored.
- Is the pool closed by the adapter? No; the application retains ownership.
- Is this released? No. Full adapter implementation and release gates remain pending.

## Integration testing

The private identifier storage path provisionally consumes its enlisted
capability through the same Work after locked state/cooldown checks and before
identifier writes. Only the owned exact identifier receipt can reach Commit;
the coordinator finalizes consumption after provisional audit/outbox effects
and before its terminal receipt. Phase failures poison Work and require Abort.
Public identifier Begin remains disabled until native session, current policy,
challenge, final-access and recovery composition is complete. Private tests
use a phase probe to prove invocation and storage rollback, not native
capability-store interoperability or an executable verification endpoint.

`go test -tags integration ./...` requires `IDENTITY_POSTGRES_TEST_DSN` pointing
to an explicitly disposable loopback PostgreSQL cluster with database
`identity_test` and database-creation permission. Each invocation creates and
removes its own random database; it never drops the supplied seed database.
Missing infrastructure fails the selected lane rather than skipping it.

PostgreSQL `numeric` with scale/range checks preserves all uint64 versions and
rejects fractional values; a scale-constrained type would round before checks.
See [PostgreSQL numeric semantics](https://www.postgresql.org/docs/18/datatype-numeric.html).
