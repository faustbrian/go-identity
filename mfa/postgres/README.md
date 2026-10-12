# PostgreSQL MFA authority (in development)

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
