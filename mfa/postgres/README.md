# PostgreSQL MFA authority (in development)

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
