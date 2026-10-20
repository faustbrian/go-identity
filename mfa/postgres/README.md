# PostgreSQL MFA authority (in development)

For explicitly selected verified-phone/password plus TOTP, the password owner
retains its distinct original primary and browser. `RequirePasswordSigninFactors`
and its method-bound variant admit only independent confirmed TOTP for that
phone origin, never the phone/SMS itself as a second factor. Apply
`PhoneContinuationMigrationSource` after the installed continuation history,
setting `UsernameSignin`/`VerificationSignin` to its actual predecessor selections.
Existing rows/checksums remain unchanged; an incorrect predecessor fails rather
than dropping an unknown constraint. This suffix does not compare passwords,
authorize another factor, issue a session or enable HTTP.

The bounded phone-password-reset integration reads the original confirmed
encrypted factor using `TOTPFactorReader.ReadForPhoneRecovery`; this is structural
custody, not recovery authorization, a fabricated login continuation or session.
`NewPhoneRecoveryTOTPVerifier` takes the existing secret-envelope service plus an
independent comparison key and positive retained key version. `Prepare` binds the
exact joint input or generated command and decrypts outside database locks. Its
exclusive original authority deadline must be microsecond-exact. Always defer
`PreparedPhoneRecoveryTOTP.Destroy`, including when execution never starts.
Copies share one-shot custody; verification moves the Secret under a short lock,
does SQL without that lock, and clears it on every return. Destroy waits for an
active bounded use outside the lock. A consuming phase must prepare afresh.

The exact native command retains `phone.reset.factor-id` (text),
`phone.reset.factor-version` (enrollment uint64) and
`phone.reset.factor-authority-version` (aggregate uint64), derived by the phone
owner from its verified original reset capability. `VerifyPhoneRecoveryTOTPAttempt`
accepts only the exact sealed input or generated command matching its prepared
custody through the registered `OTPAttemptWork` owner, never a generic feature;
its opaque, live-bound `Accepted` classification performs actual core TOTP
verification but never advances replay. Only an actual crypto mismatch/replay is
a false classification; stale or unavailable authority is an error. The OTP owner
alone decides/debits the existing SMS challenge budget. There is no MFA-specific
recovery budget, caller-writable successful-factor flag or scalar-step API.

The OTP reservation wrapper calls `RequirePhoneRecoveryTOTPReservation` and its
first protected check calls `RequirePhoneRecoveryTOTPApply` after primary/flow
admission, before challenge/lockout exclusions. Their exact live owner/command
checks lock current user, aggregate and encrypted factor without comparison.
`VerifyAndRecordPhoneRecoveryTOTP` independently rechecks the generated command
and current database time, verifies the original opaque code, then advances only
the internally verified replay step in the existing coordinator Work. Require its
opaque completion's `RequireRecorded` inside the same Apply immediately before
password effects. This rechecks the locks already acquired by the protected OTP
check and fences exact ciphertext, profile, enrollment, row, replay and authority.
The OTP owner's repeated commit check uses the actual opaque completion's
`RequireOTPApplyRecorded` to fence only its verified successor. Kernel-owned
`RequireFeatureOrigin` checks the exact same private Work and registered owners
before and after those current factor/time locks; no general retained Work
access is used. Ordinary `RequireRecorded` remains Apply-only. No decryption or
provider callback runs under those locks. The parent phone/password workflow must
still authenticate
the canonical reset capability, exact phone/pre-auth/OTP/attempt/risk binding and
current password authority and atomically commit all consumption, password/session
effects and replay. These helpers alone enable no reset service or endpoint;
unknown outcomes use the parent coordinator's existing original-command recovery.
Encrypted factor/enrollment storage and retained-factor behavior are unchanged.

`ReadPhoneFactors` supplies preliminary actual known-empty factor metadata for
the selected existing-account phone enrollment, replacement and removal profiles.
Freeze that positive generation as the `phone.factor-version` uint64 field in
the original command.
`RequirePhoneFactors` admits only the exact self-user `identity/phone/postgres`
owner's `identity.phone.send-verification`, `identity.phone.verify`,
`identity.phone.update` and `identity.phone.remove` native-v1 schemas under
`identity.phone` contract v1. Replacement sending additionally selects exactly
`identity.phone.send-verification.change.native-v1`, without attaching a new
identifier. Other schema aliases remain rejected. It rejects changed/missing
generation fields and unknown `phone.factor-*` variants. Acquire original account/session
locks first and call the guard in every protected admission phase, mutation and
final precommit check; its actual factor row lock lasts until Work closes.
Missing, enrolled, changed or corrupt authority denies without initialization,
weaker fallback, proof issuance or renewal of original validity. The selected
native owner must retain the original field through preparation and completion;
these seams do not themselves implement phone or OTP enrollment.

`RequireActionPrimaryFactors` supplies the selected known-empty-factor fence for
native username rename and organization ownership transfer. Freeze actual
`ReadPasswordSigninFactors` generations as `action-primary.actor-factor-version`
and `action-primary.target-factor-version` uint64 command fields. Rename is self-
only; transfer binds distinct actor and target. Freeze the bounded observations
before original intent. In every protected preparation stage that exists, and
at least in mutation and final admission, acquire user/credential locks in
canonical subject order before this guard. No separate preparation transaction
is required. It locks actual factor rows at their original versions;
first-factor activation, changed generation or unavailable state denies even
if the original password session remains live. No MFA-bearing transfer/rename
profile, proof issuance or factor initialization is enabled by this guard.

Required-email username signup reuses `InitializeSignup` under the exact native
password contributor's `identity.username.signup`/`username-signup` v1 scope.
It requires actual account creation and original registration evidence in the
same Work; a caller-supplied user ID or missing state cannot initialize absence.
Append `UsernameSignupMigrationSource` after factor authorities and any selected
historical magic-link suffix. It preserves all old rows and purpose arms and
backfills nothing. Actual signin still reads/fences current factor authority;
this initialization is not a proof, MFA bypass or permission to issue a session.

`RequirePasswordSigninFactors` also admits the exact native
`identity.username.signin`/`username-signin` v1 password custody for known-empty
factor admission. The owning password contributor must lock and fence the
original generation through Apply and final commit. This does not enable a
username MFA challenge: nonempty, missing or changed factor authority denies.
The separate `RequirePasswordSigninFactorMethods` challenge path admits exact
username/TOTP-only custody, and `PersistPasswordContinuation` retains that
original action and immutable scope. Install `UsernameContinuationMigrationSource`
after password continuations, with `VerificationSignin` set only when that
verification-origin predecessor is installed. Mismatched history fails rather
than silently adopting or rewriting a constraint. These seams do not compare
passwords, enroll factors, issue sessions or enable another fallback method.

The post-registration-verification signin profile uses
`ReadEmailVerificationSigninFactors` and fences its unchanged generation with
`RequireEmailVerificationSigninFactors` in Apply and final commit admission.
Missing, nonempty, changed or corrupt primary state denies; nothing initializes
or infers an empty account here. This is a known-empty profile, not enrolled MFA
continuation or permission to downgrade a required factor.

The separately selected enrolled-TOTP profile uses
`ReadEmailVerificationMFAFactors` and `RequireEmailVerificationTOTPChallenge`.
`PersistEmailVerificationContinuation` accepts only its exact native owner and
retains the separately committed confirmation ID in the signed scope. Install
`VerificationContinuationMigrationSource` after the existing password-origin
continuation history, at a new permanent version. Legacy persistence methods
reject verification-origin scopes. These APIs do not authenticate the original
signup proof or issue a session; the capability/session/native owners must
authenticate that parent and repeat current checks in the sole transaction.

For TOTP-protected email change, explicitly set
`TOTPActiveStepUpConfig.EmailChange` and install
`EmailChangeFactorMigrationSource` after existing factor-proof history at a new
forward version. `NewEmailChangeFactorSource` borrows that selected issuer.
Its opaque admission authenticates exact original signed evidence; it is not
an authorization ticket. The registered email owner must call `Admit`/`Consume`
inside protected request Work and `CheckConsumed` on confirmation and final
checks. It must separately fence original session, directory, credential and
authorization policy. `Prepare` and `Restore` also take the consumer's frozen
original session: a password/TOTP or password/recovery source retains its own
factor enrollment and authority, even when step-up used a different factor.
Protected checks and scanner discovery validate both original factor bindings.
Reuse of the proof store/use marker is atomic with the
email mutation; no second store, automatic verification consumption or fallback
is provided. Zero/unselected configuration retains MFA-management-only purposes.

`ReadEmailOTPFactors` supplies only the actual known-empty factor generation
for pending-email OTP preparation. `RequireEmailOTPFactors` must fence that same
generation in the registered native OTP Send/completion Work. Missing, enrolled
or changed authority denies before code use; neither method initializes account
authority, grants a factor proof or weakens MFA. They borrow the existing pool
or Work and retain its cancellation/lock lifetime.

`RequireAdministrativeEmailFactors` fences both the actual human actor and target
at their independently retained known-empty generations inside the existing
email-removal Work. Acquire canonical subject locks first. Missing, changed or
nonempty authority denies; this API never initializes factors or grants a proof.

`NewOTPFactorReader` reads confirmed owned OTP factors and their exact verified
recipients only under a real live OTP-enabled child grant. `Metadata` and
`Recipient` are original version/recipient custody, not code verification or
session permission. Protected sending/completion must repeat current account,
factor, identifier, policy, browser and absolute-time fences. Pending/revoked,
foreign, exhausted, stale or unavailable authority denies. Public OTP login
send/completion composition is supplied by the reference module for the selected
password-origin profile; constructing or reading this factor alone is not login.

## OTP factor storage under development

`FactorReferenceMigrationSource` follows existing TOTP/recovery history;
`OTPFactorMigrationSource` follows those references and the kernel identifier
history. Allocate permanent versions in the owned MFA namespace. Neither source
changes prior migration bytes or selects an HTTP feature. The shared namespace
contains immutable identity/method only, not verification or active-factor policy.
Per-method records and current native admission remain authoritative.

The forward reference migration backfills TOTP identities under table locks.
Existing TOTP inserts register the same identity transactionally. Recovery sets
retain their original TOTP default and gain a method-bound reference; generated
per-method references preserve factor-deletion restrictions without duplicating
the recovery store. New OTP recovery writes must explicitly select `factor_method`
`otp`. OTP rows bind exact identifier/verification versions; confirmation requires
attribution and revocation clears recipient references. None of this proves
possession of a code, recipient ownership, enrollment or authentication.

The migrations scan/backfill and acquire blocking DDL locks. Set bounded lock
and statement timeouts and plan headroom before adoption. Security-invoker
registration requires the native MFA writer's SELECT/INSERT privileges on the
new reference table; no privileged definer or runtime business callback is added.
Current local tests do not establish production-scale rollout or latency budgets.
`NewOTPEnrollmentConfig` and `NewOTPEnrollmentService` explicitly select native
pending enrollment without selecting a TOTP algorithm or generating its secret.
Supply the same actual `TOTPEnrollmentPrimarySource` port implemented by the
password primary adapter (including its cookie/CSRF variant), protected risk and
counter owners, keyring and coordinator/request-key configuration. The historical
port name does not create a second primary-proof authority. The constructor does
no IO and does not initialize unknown account factor state.

Call `Enable` with `FactorPolicy.Method="otp"`, a bounded recovery-code count and
`OTPEnrollmentSelection` containing an existing verified identifier ID and its
email/SMS channel. Native preparation freezes its versions; protected admission
locks/rechecks them. First-factor enrollment requires known-empty active-factor
authority and permits at most eight live pending TOTP/OTP ceremonies combined.
Primary proof use, pending factor, inactive recovery codes, audit and lifecycle
commit together. Only a fresh, error-free commit returns reveal-once recovery
material. Destroy each returned secret after its explicit delivery.

An identical retry preserves the original outcome and returns no recovery codes;
a known rolled-back command is not repeated under the same key. A new attempt
requires a new key and current admission. `RecoverEnable` takes the original
non-secret command scope and current result-access policy, not a password, code
or bearer. Changing recipient or configured counter namespace cannot restore a
retained original request. This pending service proves no OTP possession and
does not activate a factor or issue a session. Sending and confirmation are
separately selected below; OTP login and HTTP/reference remain under development.

### Native pending-OTP sending

Append `OTPSendMigrationSource` after OTP factors (selected MFA history versions
13/14/15 for factor references/factors/send attribution). Historical prefixes
remain unchanged. Select `NewOTPEnrollmentSendService` with the same
`OTPEnrollmentService`, password's actual `OTPEnrollmentSendPrimarySource`,
an `otp/postgres.NewMFAEnrollmentIssuer` and exact HTTPS origins. Initialize the
issuer's stable keys against installed OTP and delivery histories first.

Call `OtpSend` with the pending factor ID, exact enrolled channel, idempotency
key, trusted caller/origin/network and `OTPEnrollmentContext` containing the
original session and synchronizer. The server assigns one command/challenge ID;
no recipient, expiry or command ID is request-selectable. Current original
primary, consumed enable proof, pending factor/recipient versions and protected
risk must admit before generation and commit. Unknown outcomes retain the
original command; retry cannot select a successor code or recipient.

Challenge creation, factor send attribution and encrypted delivery commit or
roll back together. A committed `StateQueued` is historical queue acceptance,
not provider delivery or confirmation. The actual delivery worker invokes the
selected sender separately. `RecoverOtpSend` takes original non-secret scope and
current result-access policy, never code, bearer or primary proof. Partial-login
sends, confirmation, OTP session completion and HTTP are not supplied by this
pending-enrollment-only service.

### Native pending-OTP confirmation

Select `NewOTPEnrollmentConfirmationService(sender,
OTPEnrollmentConfirmationConfig{Primary: primary, AttemptKeyVersion: version})`
with password's actual `OTPEnrollmentConfirmationPrimarySource`. The sender
supplies the same real OTP owner and exact origin allowlist. Install OTP's
`ConsumingMigrationSource` after its challenge history; retain the selected
attempt key and all original wrapping, session, enrollment and digest keys.

Call `OtpVerify` with a new command ID, the pending factor ID, actual delivered
code, original `OTPEnrollmentContext` and trusted caller/origin/network. The
client cannot choose a challenge, recipient, parent proof or authority version.
The service authenticates the committed original send's complete static root
and encrypted output from existing request/preparation custody. It retains one
random server-owned attempt in that same journal, never in another intent store.
Wrong submissions debit the real OTP budget once; exact retry replays history.
Changed same-command code or intent conflicts instead of creating another attempt.

Protected native primary/CSRF, factor, recipient, account and risk admission
precedes comparison and is fenced again after waits. Confirmation atomically
activates the pending OTP factor and its existing recovery set, advances factor
authority and finalizes OTP, audit and lifecycle effects. Activation failure
rolls those effects back and releases its original consuming reservation; the
charged admission remains historical and a released challenge cannot be reused.
An unknown outcome carries no enrollment metadata and requires original recovery.

`RecoverOtpVerify` accepts original code/proof/session-free scope with current
result-access authorization. It never compares, debits, sends, reactivates or
reveals a code. Successful confirmation returns historical enrollment metadata,
not a login session or step-up proof. Trusted-device requests and login-child
variants deny. This service confirms enrollment only. The reference module and
opt-in HTTP handlers supply the selected password-primary continuation, sending
and atomic session completion. OTP management, other channels and full release
qualification remain pending; enrollment confirmation never issues a session.

## Native disable

`NewDisableService(enrollment, stepup, DisableConfig)` selects a distinct native
disable operation, not a factor-update alias. Provide real `DisablePrimarySource`,
session effects and the actual selected email-reset request/completion recovery
owner; both maximum ages are positive and at most five minutes. Missing, changed
or unavailable authority denies without fallback. Native calls own no private
transactions or new proof journal; the existing coordinator owns atomicity.

Install `DisableMigrationSource` at permanently allocated MFA version11 after
proof8/management9/removal10. Older histories and retained update receipts are
unchanged. Select the corresponding session-disposition v3 extension. One/all
are retained as distinct immutable request/effect scopes. All-target bounds older
pending enrollments before erasure, supporting at most63 pending siblings beside
the sole active TOTP, not arbitrary additional active factor methods. One-target
leaves untargeted pending factors and their recovery sets unchanged. Its fresh
result includes up to100 unexpired pending projections captured inside the same
protected transaction, excluding revoked history. Unknown/replayed outcomes
never return this snapshot. Safe metadata failure rolls back the mutation.
Any overflow or unsupported authority rolls back all effects.

## Safe selected-profile inventory

`NewTOTPListReader(enrollment)` borrows the existing real TOTP enrollment owner
and its primary pool/read budget. Compose it with `mfa.NewListService` and the
actual session/authorization owners; the reader alone is not an access endpoint.
Install the existing factor/recovery histories. Listing creates no new schema,
transaction, journal or goroutine and selects no ciphertext, verifier or replay
counter. One bounded primary snapshot validates known authority and complete
active recovery sets before reporting unused counts. Initial set epochs retain
their existing interpretation; they are not equal to global factor generations.

This explicit TOTP-only profile has no trusted-device issuance or security-key
owner. Its empty device projection is not fabricated empty unsupported storage.
Unexpected active-factor inventory, incomplete code rows, missing authority or
overflow fail without a partial result. Labels and usage times not stored by this
profile remain absent. Full trusted-device/security-key support and release
qualification remain required by the complete MFA goal.

## Native authenticated step-up and recovery replacement

Compose `NewTOTPActiveStepUpService` over the actual selected enrollment graph
with the native current-session primary owner, exact allowed origins, fixed
comparison key/version and original-evidence Ed25519 signing/retained public
keys. It borrows the graph's pool, encryption, risk/counters and transaction
coordinator; it starts no goroutine or independent journal. Persist original
evidence using `FactorVerificationMigrationSource`. In selected reference
graphs this is MFA version8, preserving password-continuation version7.

`ActiveStepUpRateSource` reads original authenticated session/factor custody
without decrypting, comparing, consuming or issuing. Retain its exclusive
deadline. Protected verification compares the actual enrolled TOTP and commits
replay advancement, original signed evidence and audit/lifecycle together.
Original prepared ciphertext is reused on retry; terminal replay/recovery
cannot disclose proof again. Retain verification keys for historical evidence.

Compose `NewRecoveryRegenerationService` with that same step-up/enrollment
graph, the native current-session primary and the session-owned replacement
effects. Count is 1..64 and maximum proof age is positive, at most five minutes.
The service uses authentication's existing original-proof validator, then locks
and consumes actual stored proof use in protected Work. It retires all preceding
sets, installs independent random128/base64url codes, advances factor authority
and enlists bounded session revocation and events in one transaction. Neither
source reads nor retries renew proof/session timestamps. Only the fresh known
commit returns secrets; destroy them after delivery. Recovery is metadata-only.

The reference graph supplies native owners and migrations through
`MFAEnrollment.ActiveStepUp`/`.Regeneration`; HTTP remains separately opt-in.
These operations do not provide the remaining OTP, trusted-device, security-key
or administrative-recovery workflows, nor complete module release qualification.

Install `MigrationSource` with a permanent version in the `identity_mfa` migration
namespace after the kernel user and command histories. The source deliberately
does not backfill existing users as having no factors. An unmanaged schema fails.

The native password owner invokes `InitializeSignup` after genuine same-transaction
registration. Neutral collisions, foreign invocations and pre-existing users
cannot initialize an empty generation. Rollback removes the account and generation
together; retries use the kernel command journal, not an MFA retry journal.

`RequireEmailRecovery` runs only in an unchanged native reset invocation. It locks
the subject's factor authority until coordinator commit/rollback. Missing state,
active factors and stale expected generations deny. Completion must provide the
nonzero factor version authenticated by original issuance custody. Propagate all
errors to the coordinator; do not retain returned views outside Work.

`RequireEmailRecoveryRequestPreparation` selects known-empty state inside the
exact anonymous native request preparation. Generation then binds that version
into original issuance; final application calls `RequireEmailRecovery` with
the same version. Neither preparation nor retry initializes missing authority.

Future factor writers must lock this same root and increment its version while
applying required proof invalidation, session effects and audits. This initial
module does not provide enrollment writers, protocol verification, recovery-code
storage, session issuance or a complete reset service. Existing-account authority
reconciliation remains necessary before email recovery is available to them.

## Partial-authentication continuation storage

`ContinuationMigrationSource` appends the MFA continuation table after the
factor-authority history. It preserves prior migration bytes and does not
backfill or reset existing factor state. Continuations contain original scope
metadata and proof digests, never bearer credentials or plaintext factor secrets.

The native magic-link challenge owner calls `PersistMagicLinkContinuation` only
in its protected Apply invocation, after provisional primary consumption.
The stored subject, original primary proof, browser flow, immutable scope digest,
policy/factor generations and absolute times must match the kernel's frozen
challenge. Missing, empty or changed factor authority denies. Duplicate insertion
fails rather than resetting lifetime or attempts. Native current-method, browser,
account, risk and policy checks remain the invoking workflow's responsibility.

The coordinator commits continuation, primary use, exact child issuance, audit
and lifecycle together; a late failure rolls them all back. This storage API
does not authenticate factors, complete a continuation, deliver a challenge or
issue a session. Public MFA challenge/completion remains in development.

`ContinuationReader` restores exact original scope only for an already verified
child grant and current primary authority. It is read-only, bounded and uncached;
its result is not permission to complete MFA or issue a session.

## Encrypted TOTP storage

Append `TOTPFactorMigrationSource` after the existing MFA history with a permanent
new migration version. Pending enrollment, confirmed active factor and revoked
factor are distinct states. Active factors require confirmation; revocation must
erase encrypted custody. No users or enrollments are backfilled or activated.

`TOTPFactorReader` accepts a verified live TOTP-enabled child continuation and
restores one confirmed factor's immutable encrypted snapshot. Foreign, pending,
revoked or stale authority denies. `Metadata` is a version fence, not a proof;
`Envelope` and `EncryptionContext` expose only encrypted custody and its exact
versioned tenant/user/factor/enrollment/profile binding. Changing that profile
cannot decrypt the original ciphertext. Wrapping-key rotation preserves context.

The MFA service decrypts outside locked callbacks and owns transient plaintext
cleanup and opaque-secret destruction. The reader never verifies a code, spends
an attempt, advances replay, activates a factor or issues a session. Final native
completion must recheck the entire snapshot under its protected transaction.
Enrollment writers, the public completion service and session wiring remain
unfinished; installing this schema or reading ciphertext is not usable MFA.

Within the exact native counted-denial callback, `LockTOTPAttempt` acquires
account, factor-authority, continuation and factor locks in that order. It checks
the original browser scope, generations, absolute expiry and complete encrypted
snapshot. Decrypt before entering the callback; the native MFA owner uses
`VerificationState` and the original opaque code for bounded local comparison
and separately checks current policy and primary-proof authority. No provider
or application callback may run under these locks.

On actual rejection call `RecordTOTPAttemptDenial` and return
`MFAAttemptDenied`. Propagate every error: the sole coordinator commits the
shared-budget charge with denial audit and the original aborted command, or
rolls them all back. Exact journal replay precedes comparison; exhaustion
revokes the continuation without advancing successful factor replay or using
the child. These serial-use handles deny after return or charge. Correct code
must follow the independently protected successful-completion path; this
denial-only storage API never authenticates a session.

Within the successful protected Apply, `LockTOTPCompletion` accepts only the
unchanged original TOTP command and exact registered MFA owner, after provisional
child consumption. It takes the same authority and full-snapshot locks as denial
accounting. The native MFA service verifies the original opaque code against
`VerificationState` using its already decrypted owned secret, then calls
`RecordTOTPCompletion` with the resulting counter. A counter alone is not proof:
zero, foreign, returned and already-recorded custody deny. The store never verifies
a factor on the caller's behalf or authorizes a session from a scalar.

Successful replay advancement and terminal continuation completion spend one
shared attempt and persist together in this transaction. Success on the final
attempt records `Completed`, not `Revoked`. Original scope, remember policy and
absolute lifetime are unchanged. Propagate any error and invoke the original-
primary session owner in this same transaction; a later denial must roll back
factor replay, continuation, child and session effects. The kernel owns exact
retry/unknown-outcome recovery; this adapter creates no second journal.

The native session composition calls `RequireRecordedTOTPCompletion` with the
same locked handle, Work, exact owner and unchanged command after recording.
It verifies that this invocation actually advanced factor replay and completed
the original continuation, with unchanged authority and committed original
primary-command provenance. Zero, foreign, unrecorded or returned custody
cannot be replaced by scalar session metadata. Returned original scope and
pre-completion metadata are structural projections, not reusable proof.

`RequireTOTPSessionFactor` is the MFA-owned current factor fence for selected
native session logout. It requires the exact registered session participant's
live Work, original enrollment and factor generation, and locks the account,
factor authority and confirmed factor. It starts no transaction, reads no secret
and does not revive an expired child or renew session evidence. Directory,
verified identifier and policy fences remain separately mandatory. Public
reference integration exercises this owner with protected rollback and recovery.

`RecordMissingTOTPAttemptDenial` handles an authenticated missing/ineligible
factor candidate in the exact live native attempt callback. The native owner
supplies the original command-bound factor selection after browser, primary,
directory, recipient and policy admission. The MFA owner independently locks
and rechecks the account-wide factor epoch, original pending continuation and
that factor's eligibility within the account before spending the existing
shared budget. It does not accept an absence assertion or fabricated snapshot.
A now-confirmed factor, stale authority, corrupt confirmed record or outage
cannot be charged as absence; there is no successful verification/generation
arm. The coordinator commits the provisional charge with protected counters,
required denial audit and original terminal journal, or rolls them all back.

The owning MFA service must still verify the actual original opaque code before
recording, enforce primary/browser/current policy, and persist the original-
primary session in this same transaction. Positive native composition and its
session effect remain in development; a guard or mapping alone is not MFA login.

## Native factor label management

`NewFactorUpdateService` borrows the same enrollment and active-step-up owners,
real native primary source and enlisted session effect. It owns no new pool,
transaction, journal or goroutine. Positive primary/factor maximum ages are
explicit and at most five minutes; earliest original proof, primary and
authoritative observation expiry wins without renewal.

Install `FactorManagementMigrationSource` after the factor-verification history
and the selected session factor-update disposition suffix. MFA v9 adds a bounded
label and retained effects without modifying factor secrets or prior migrations.
The default profile supports confirmed TOTP rename. Optimistic versions,
current authority and one-time proof fences give one mutation winner; lifecycle
failure rolls back label, proof and sessions. An unknown commit acknowledgement
requires original-command outcome recovery, never proof or metadata redelivery.

`NewTOTPManagementListReader` explicitly borrows this selected manager to read
the new safe label. Base `NewTOTPListReader` remains compatible with the previous
schema. Neither reader infers authority from optional fields or reads secrets.

To additionally select removal of the sole confirmed TOTP, set
`FactorUpdateConfig.RemovalRecoveryPath` to `authentication.RecoveryPathEmail`
and borrow `password/postgres.NewFactorRemovalRecoverySource` from the actual
selected native reset request/completion service. The source checks verified
email and exactly one usable password reference under protected Work, retaining
current row locks. Missing, ambiguous, blocked or unavailable recovery denies;
there is no fallback or scalar assertion of recovery availability.
Install the optional `FactorRemovalMigrationSource` v10 suffix after v9.
Remove consumes the original factor proof, erases secret/replay material,
retires dependent code sets, advances authority to known-empty and revokes all
subject sessions atomically. Historical outcome recovery reads the retained
removal disposition, not today's mutable email eligibility. Unsupported recovery
paths and general multi-factor removal remain denied.

## Selected pending TOTP replacement

Set `FactorUpdateConfig.Replacement` to `TOTPReplacementConfig{RecoveryCodes: 10}`
(allowed count1..64). Nil preserves rename/removal configuration identity and
does not enable replacement. Install optional `TOTPReplacementMigrationSource`
v12 after the existing MFA history, without rewriting installed prefixes.
The supported profile replaces the sole active confirmed TOTP using its original
fresh factor-update proof, observed row version and actual recent primary session.
Password/TOTP and password/recovery source sessions retain their existing factor
fences through continuation; they do not fall back to single-factor admission.
The initial optimistic version must be at most `MaxUint64-2`, reserving both
initiation and retirement increments. Exhaustion denies before proof consumption
or successor creation; rename/removal retain their original one-step bounds.

Initiation consumes the management proof but does not advance factor authority,
retire old codes or revoke sessions. It creates one pending successor and returns
its recovery material once. Explicitly compose `TOTPReplacementContinuationConfig`
into URI and confirmation configuration, borrowing the same management owner,
native original-session primary source and replacement session effect. The
reference graph supplies these concrete owners; no caller-created enable record
or forged password proof is needed. URI disclosure remains one-use and confirmation
requires the pending successor's actual code, not the old factor's code.

Continuations retain the original session, proof, predecessor and parent-command
identity. They acquire an actual current authority observation bounded at20seconds;
copies never renew freshness. Original primary/proof age and enrollment expiry
remain absolute ceilings. Benign predecessor replay updates are accepted while
unchanged management authority is fenced; account blocking, revocation, factor
epoch change or unavailable authority denies. Confirmation atomically retires
old factor/code sets, advances the epoch and revokes every bounded subject session.
Historical recovery authenticates retained effects without reviving a session or
repeating URI/code delivery. Multi-factor/device/admin replacement is not provided
by this selected sole-TOTP profile.

## Native OTP-only signin admission

`ReadOTPSigninFactors` supplies preliminary known-empty state for the exact
native `identity.otp.signin`/`identity-otp-signin` v1 consume profile. Freeze the
original positive generation in encrypted native signin custody. The native
owner must call `RequireOTPSigninAttemptFactors` before comparison or charging,
`RequireOTPSigninReservationFactors` before reservation/rebind,
`RequireOTPSigninApplyFactors` during protected admission, and
`RequireOTPSigninFinalizeFactors` before finalization. Each accepts only its
exact live opaque phase and registered native owner; no general Work is exposed.
Supply the actual recipient authenticated by original custody, not the anonymous
flow identifier. Missing, enrolled, corrupt or changed factor state denies; the
same MFA row stays locked until the coordinator transaction closes. These guards
never initialize state, enable weaker-factor fallback, renew authority, or alter
historical recovery/release. Propagate every error to the coordinator.
