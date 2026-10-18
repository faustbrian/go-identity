# Password PostgreSQL adapter

## Optional link-verification hooks

Select an immutable `email.VerificationHooks` on
`SignupConfig.Verification.Hooks` or
`EmailManagementConfig.VerificationHooks`. Nil preserves existing behavior.
Version callback semantics with the enclosing `ConfigurationID` and retain
original configurations for recovery. Management selection applies only to
pending-address verification links, not OTP or primary-email change.

Before runs outside SQL before reservation; rejection leaves no command claim,
proof use or protected change. Final native authority/expiry checks still apply.
After runs outside SQL only after a fresh known commit. Its failure preserves
the committed outcome and recovery but withholds address projection and any
following verification-signin attempt. It is not rollback. Scanner validation,
replay, recovery, unknown results and rollback never invoke observers. A failed
attempt that passed reservation retains the existing anti-abuse charge; a hook
rejection precedes that charge. Use the durable outbox for external delivery.

## Original-browser verification and signin

Explicitly compose `NewVerificationSigninService(signup, config)` over the native
signup owner. `VerificationSigninConfig` supplies the session issuer/CSRF key and
email-grant audience/authority profile; its policy namespace must be the one
initialized by signup. Install the session owner's forward verification-signin
migration and select compatible session read/logout. Existing `SignupService`
confirmation remains verification-only.

`VerificationConfirmAndSignin` authenticates the original encrypted signup intent
and browser cookie, recovers its remember choice, commits verification, then
attempts one distinct email-possession signin with current counted risk, explicit
authorization and known-empty MFA. It never reuses the signup password result.
Inspect both outcomes and the error: failed/unknown login does not erase committed
verification. Replay and `VerificationSigninRecover` cannot mint or redeliver
credentials. Ordinary signin is the recovery path after missed credential
delivery. Enrolled MFA continuation is not supported by this selected profile.

To additionally support enrolled TOTP, explicitly set
`VerificationSigninConfig.TOTP`. A fresh pending result supplies
`VerificationMFAChallenge`, not an authenticated session. The native owner
authenticates the original committed registration/confirmation, encrypted
preparation and current authority through `ReadMFAVerificationPrimary`; the
selected TOTP executor must repeat protected parent/factor checks during actual
completion. Original browser, expiry and remember policy cannot be replaced.
This selects no recovery/OTP/trusted-device fallback. Known-empty admission is
retained; missing or unsupported factor authority denies. The reference graph
composes these owners with `PasswordSignup.VerificationTOTP` and a permanent
explicit `VerificationSessionLineage`.

## TOTP-protected email change

`NewEmailTOTPPrimarySource` explicitly composes the existing session/CSRF and
authorization owner with MFA's `EmailChangeFactorSource`. Select only self-user
`identity.email.change-request` and a matching proof audience, then construct the
ordinary managed/keyed email service with `email.RequirePrimaryAddress`.
Install the MFA email-use forward migration first; reference composition owns
this wiring when `Email.TOTPChange` is selected. The actual original TOTP proof
must be consumed with pending attachment and delivery, and its enrollment,
factor generation, original session family and earliest deadline remain binding
through confirmation. Recovery/retries do not renew that authority. Default
password admission continues to require authoritative known-empty MFA.
The selected source accepts retained password sessions and genuine
password/TOTP or password/recovery sessions. An MFA-origin session's own
factor enrollment remains binding separately from the fresh step-up factor;
neither is dropped or substituted during keyed restoration or confirmation.

## Safe email removal

For administrative targets, select `EmailPrimaryConfig.AdministrativeTargets`
only for `identity.email.address-remove`. Supply
`EmailPrimaryRequest.TargetSubjectID` (or the email-owned request's corresponding
field), with the actual actor's original signed proof, cookie/bearer and CSRF
custody. Current policy must grant the exact target action; the flag and ID are
not authority. The sole Work fences actor credential/authorization, independent
known-empty MFA states, and the target's actual remaining configured password
signin/reset path. Target revocation never replaces the actor's session.
Retries retain original input/proof and pending cascade identity; unknown is not
rollback. Empty target retains legacy self custody and unsupported factors deny.
Every unfinished preparation/restoration reevaluates exact target permission
outside database locks; retained custody and a general actor epoch are not an
Allow decision. Terminal keyed replay preserves original historical metadata,
not permission to execute another mutation. Native recovery still has its own
current disclosure policy.

`NewEmailRemovalService(primary, signin, reset, config, keyring)` requires actual
password `SigninService` and complete emailed `ResetService` on the same pool.
Their global/authorization scopes must match primary admission; selected material
and verifier limits must cover its accepted range. Address counts, eligibility
booleans or substitute stores cannot establish this. Select original password
proof action `identity.email.address-remove`, explicit audience/age and transport.
Known-empty MFA is required; unavailable/enrolled factor authority denies.

`EmailRemovalConfig` supplies directory reuse/cascade policy, request-key/intent
custody, protected provider/counter policy and local envelope key. Retain original
configuration/keys through request retention. Install native email proof, MFA
authority, capability target-retention and kernel request/preparation/status/
retirement/identifier-cascade histories. Set issuer
`RetainEmailVerificationTargets` for new verification links; unclassified live
historical grants conservatively deny instead of guessing unsigned targets.

`AddressRemove` binds exact address/versions, reason and primary/recovery
disposition. It conserves a verified address actually eligible for selected
signin/reset under the sole native Work. Required proof/token, directory/session,
audit and pending lifecycle effects are atomic. No provider IO/callback runs
under directory locks; no primary or authentication is silently issued.
Exact retries preserve the original result after session epoch invalidation.
`AddressRemoveRateSource` authenticates retained possession before transport
admission without removal or renewed freshness. `AddressRemoveRecover` uses
original scoped correlation and current query policy, not historical proof.

## Managed email request adapter

`NewKeyedEmailManagementService(native, keyedConfig)` optionally adds durable
request correlation to the same native owner. Construct `keyedConfig` with
`NewKeyedEmailManagementConfig(requestKeys, independentIntentKey)` and install
kernel `RequestKeyMigrationSource` plus `RequestKeyPreparationMigrationSource`.
Retain the namespace/lookup/intent keys, original policy configuration and
decrypting envelope keys through mapping retention. There is no new journal.

Its `VerificationSend`, `VerificationResend` and `ChangeRequest` take exactly one
`identity.IdempotencyKey`. Command IDs must be empty; add/change address IDs must
also be empty because the winning input selects them server-side. Resend names
the existing pending address. Exact submitted address/callback/network and
borrowed bearer/proof/CSRF intent are bound; changed intent conflicts. Matching
retries restore encrypted original session/proof, address/version, previous
recipient and counter instants before live lookup. They return historical
metadata even after original proof consumption, without fresh token generation,
provider assessment or delivery. Retained signer eligibility and original
bearer/CSRF possession remain mandatory. Fresh execution still repeats native
current authority and atomically consumes proof/effects. Raw bearer, CSRF and
initiating key are not retained. A different retry key is not a retry.

Unkeyed request behavior below remains available for trusted native callers.
For known original scope use the existing proof-free request recovery methods;
after an ambiguous keyed call retry the exact original request/key, never create
a substitute command. Busy/unknown exposes no address or successful versions.

`RequestRateSource` supplies only the authenticated user/canonical destination
for the HTTP rate owner's keyed projection. Call it before mutable session
lookup so a committed retry is not rejected merely because its original session
epoch is stale. It reads exact retained input first; absent mappings allow only
bounded source preparation, not durable mapping creation, counters, signing,
provider assessment or delivery. The result is sensitive metadata, not current
session/mutation authority. Corrupt/conflicting history never chooses a fresh
source, and errors return no subject or destination.

For `identity.email.change-request`, select `EmailManagementConfig.Change` and
`ChangeNotification` together. Choose `RequirePrimaryAddress` or the explicit
`PrimaryOrSoleVerifiedAddress` establishment policy, plus
`InvalidateIdentifierSessions`. Missing/ambiguous old authority denies. Install
the risk adapter's `EmailChangeCounterMigrationSource` after selected counter
history; it preserves existing windows and selected dimension constraints.

`ChangeRequest` retains original old-address identity/independent versions in
authenticated encrypted output and signed link intent. `ChangeConfirm` repeats
current policy/factors/credential authority, atomically verifies/promotes the
candidate, demotes the previous primary if present, advances identifier authority
and stages one encrypted old-address notice. Existing stateful sessions then deny;
this profile issues no replacement cookie. Renderers receive no proof or candidate
address for the notice and run outside SQL; the existing worker sends after commit.

Use `ChangeRequestRecover` for original pending-request metadata and `ChangeRecover`
for exact confirmation history without old proof/session. Exact confirmation replay
cannot duplicate notification or expose a fresh address. A known failed command
returns noncommit with its retained typed failure cause; it is not an unknown commit
or renewed permission. New-address links that terminally abort stay unusable.

Select `EmailManagementConfig.ResendInterval` explicitly to enable
`VerificationResend`: 30 seconds through 10 minutes; zero disables it. A selected
initial request signs the mailbox family so its unused links can be replaced.
Legacy unselected links and signup grants are not superseded. Install the existing
kernel `CounterPreparationMigrationSource`, email password-proof migration and
capability adapter migration 004 before selection. Signing/rendering stay outside
SQL; the common family fence precedes account/factor/domain locks. The actual
committed issuance creation time owns cooldown, not the password proof's time.

Resend targets the unchanged pending, non-primary mailbox. Supply a fresh original
action-bound proof and current session/synchronizer; an identifier change can
invalidate the old source session, so use genuine login, not a promoted epoch.
An omitted `Address` uses stored canonical identity; a different address denies.
The protected transaction advances both pending versions, invalidates older
selected unused links and enqueues one encrypted delivery. Cooldown denial or
late rollback preserves the old link and does not consume the primary proof.
Scanner reads consume nothing; explicit confirmation uses the original successor
versions. Request retries still require live primary authority. After uncertainty
or lost source authority, use `VerificationSendRecover` with exact original scope
and current disclosure policy: it returns historical metadata, not another link,
address ownership, session or fresh permission. Busy/unknown returns no address.

`NewEmailManagementService` composes the email owner's selected password-origin
request with the original `EmailPrimarySource`, kernel identifiers, real MFA,
protected counters/provider admission, capability issuer and encrypted delivery.
`VerificationSend` attaches a new pending address; `ChangeRequest` attaches its
change candidate without replacing the verified primary. Source action, policy,
normalization, callback allowlist, templates and providers are frozen startup
configuration. Requests cannot select actors, authority versions or clocks.

Generation uses the existing acknowledged preparation journal. Original issuer
and delivery checkpoints restore without another token transfer or expiry
renewal. A commit reports queued custody, not that a sender ran. Process through
the owned delivery worker outside the mutation transaction. Missing/enrolled MFA
denies the selected single-factor profile. Missing authority is never interpreted
as "no MFA".
`ReadManagedVerification` is a trusted native seam for authenticating the
signed issuance origin and original encrypted intent. Its current caller must
be authorized for the signed user and exact confirmation action; it must not
impersonate the historical human or restore that user's session. Returned intent
is sensitive and is not a public response or current authority.

`ReadChangeOrigin` implements `email.ChangeOriginSource` for independently issued
OTP change workflows. It authenticates the committed change request directly,
without a delivered link or another password proof. Current exact OTP-change
disclosure policy is required. Candidate, old-address policy, original session,
factor/directory generations, expiry and the exact retained-ciphertext digest
remain original, including after completion. These are private provenance, not
current authority: consuming workflows still fence current state and original
validity atomically. Generic pending attachment cannot supply this provenance.

`PrepareOTPChangeNotification` retains its genuine-primary-only contract.
`PrepareOTPInitialPrimaryNotification` is the separate optional notice port for
an explicitly enabled first-primary OTP consumer. It authenticates the original
sole-verified change policy and renders/seals the retained old-mailbox notice;
neither method stages delivery, grants current authority or renews the origin.

`ValidateManagedVerification` is scanner-safe boolean inspection. It checks
original callback, current unused issued state, active account, exact pending
address/verification versions, original credential and authorization epochs,
original known-empty factor generation and
mandatory provider facts. Repeated inspection does not consume, reserve, charge
protected counters, send another message or extend any original time. Its entire
read budget is at most20s; success is an observation, not an execution ticket or
durable validity lease. Explicit confirmation must repeat protected admission.

`VerificationConfirm` authenticates that original intent again and atomically
verifies the pending address with one-use proof, protected counters and required
audit/lifecycle effects. The historical session need not remain live; its source
credential, authorization and factor authority must remain valid. Exact-command
replay returns metadata only. `VerificationRecover` uses current scoped authority
and the original recovery correlation, not the consumed proof or a new execution.
Unknown outcomes remain unknown. An aborted proof reservation is terminally
released; retry with a fresh authorized delivery, not a resurrected grant.

`ManagedVerificationRateSource` authenticates the original signed subject,
actual grant ID and immutable signed lifetime for HTTP rate admission, including
consumed provenance needed for exact-command replay. It charges no counter and
grants no execution authority. The optional `http/email` managed-confirmation
selection consumes this seam and `VerificationConfirm`; the password adapter
does not import HTTP. Retries preserve the first command's audit correlation,
but changed proof/callback/protected-counter intent still denies or conflicts.

Install every selected history named by the constructor, including verification
counter history through its capability dimension. Resend and primary change
require their explicit profiles described above; safe removal is a separate
workflow. The reference module supplies selected application composition. No
automatic signin or session issuance occurs.

The selected recovery source below also admits exact native `identity.mfa.disable`
with a closed one/all target. It borrows the same complete request/completion,
HIBP and delivery composition; it does not translate disable to factor-update
authority, open another transaction or issue a reset. Recovery after a committed
disable reads its original retained disposition, not today's email eligibility.

## Selected recovery for TOTP removal

`NewFactorRemovalRecoverySource` borrows a fully configured native `ResetService`
with request, completion, HIBP and delivery dependencies. Keep that service and
its dependencies alive while management uses the source. It opens no transaction
and retains no Work: current active account, verified email and exactly one
enabled, unexpired password reference are fenced inside MFA's protected Work.
Multiple password references deny even when one is disabled, matching the real
reset request owner's unambiguous selection. No reset grant or factor proof is
created by this check. After removal, use the actual public reset-request,
delivery and completion workflow; removal does not automatically issue a session.
Other recovery methods are not selected by this source.

Development checkpoint: owned forward-only password material storage and a
consistent primary credential reader plus native existing-password material
replacement/recovery, native authenticated password change and backend
single-factor signin/recovery with atomic automatic rehash, plus required-email-
verification signup and password-free signup recovery. Immediate-session/MFA
signup, reset HTTP/reference wiring, history and deletion remain unimplemented. Original signup-link
confirmation is implemented; the complete generic email lifecycle is not.

`NewMFASigninService` explicitly selects password-first TOTP challenge creation
using `SigninConfig` plus `MFAChallengeConfig`. Install the complete capability
adapter history and MFA continuation/TOTP history, including
`PasswordContinuationMigrationSource`, alongside the existing password/session
histories. Configure independent child signing/replay/envelope keys through the
capability issuer and custody configurations. Known empty factor authority may
issue SFA; enrolled accounts receive only a continuation. Missing authority denies.
Password evidence, original browser consumption, child issuance, audit/lifecycle
and automatic hash upgrade commit atomically. No session, cookie or synchronizer
is issued for a challenge. Password-free `RecoverSignin` checks the original
browser and current disclosure policy, preserving ID/expiry without redelivering
the proof. Live leases remain pending; expired unresolved attempts use the
existing coordinator's owner reconciliation. The native password-origin
completion and selected HTTP/reference wiring remain in development.

Native signup now also initializes known-empty second-factor authority in the
same protected transaction. Install `mfa/postgres.MigrationSource` in the owned
`identity_mfa` namespace after kernel users/commands and before signup. Neutral
collisions and rollbacks create no factor authority. Existing users are not
backfilled as factor-free; their unknown state denies email-only recovery until
reconciled by the factor owner. This adds no enrollment or MFA bypass.

`NewResetService` supplies the public `password.ResetService` interface.
Select `ResetConfig.Request` to enable `ResetRequest` and `RecoverResetRequest`;
nil keeps existing completion-only composition and explicitly denies requests.
Request composition selects email normalization, request-key policy, original
issuance custody and encrypted delivery. Install kernel request-key/preparation
histories, independent MFA authority and delivery histories before enabling it.
Completion requires real issuer-owned durable provenance, a verified email and
current credential/account/factor authority; missing factor authority denies.
Password screening precedes hashing. Credential replacement, required session
revocation, one-time consumption and audit/lifecycle effects commit together.
Original retries preserve the generated verifier and reject changed input.
Proof-free recovery returns historical metadata only, not authority or secrets.

For observed HIBP composition, select `ResetConfig.CollectReset` and leave
`Screening.Collect` nil. Exactly one mode is required. The native owner invokes
the attributed collector only after original issuer/proof and counted-admission
validation, passing the original `CommandBinding`, verified challenge ID,
original risk scope and borrowed exact-byte candidate. Correlation remains the
original command's correlation, not a retry's transport correlation. Supply the
owned observed HIBP adapter and existing audit recorder in that callback; required
unknown audit delivery must deny and retain unchanged records through that
recorder's reconciliation path. Never substitute a random attempt or derive one
from an identifier. The callback is synchronous, bounded and concurrency-safe;
native restoration/recovery never invokes it. Change `ConfigurationID` when its
semantics change. Collection mode is also bound into preparation identity, while
legacy profiles keep the existing digest unchanged. This binding point does not
itself establish provider interoperability or observed audit delivery.
A proven rollback can return `NotCommitted` with `identity.UnavailableError`
retaining the original dependency failure; its released proof cannot be reused.
Selected reset HTTP/reference composition remains unfinished; backend public
request/delivery/completion integration does not claim transport readiness.

Native request preparation now transfers real issuer-owned reset tokens into
encrypted delivery checkpoints. The PostgreSQL integration journey stages those
restored checkpoints atomically and captures the email through the actual worker
before calling public completion. The public-request journey also proves stable
acknowledgement without duplicate issuance/messages, conflicting raw input,
proof-free recovery, old-password rejection, replacement-password signin and
atomic revocation of the predecessor session set. Missing, enrolled-factor and
genuinely unknown-factor selections receive the same committed acknowledgement
without an issued grant or delivery intent. Retained output restores original
recipient, factor/credential epochs, token and message, not current replacements.

For signup rate admission, debit the trusted IP budget first, then use
`SignupService.SignupRateSource(ctx, input)` to obtain the frozen creation
parser's canonical identifier for the shared identifier budget. Pass the same
address to `Signup`. Treat the returned identifier as private: never log or
disclose it. This pure projection reads no account or flow, performs no password
work and grants no registration authority. Native signup still checks original
flow possession and keyed intent; the projection does not prevent historical
keyed retries when the live flow has been consumed or deleted. Invalid input or
cancellation returns no identifier. This method does not add a signup HTTP route.

Select `http/password.NewSignupFeature` with the native `SignupService` for
the required-email-verification profile. Borrow the strict PostgreSQL shared
rate owner, match the original flow/remember and HTTPS origin/callback policy,
and select the signed device codec and the same input field schema. Supply the
original byte-exact `Idempotency-Key` header on explicit retries; transport
normalization does not require a live flow, so retained native history remains
recoverable after consumption/deletion. Fresh and occupied identifiers return
the same verification-required acknowledgement without account, mailbox or
session credentials. Original recovery metadata is not authority. Immediate-
session/MFA signup remains unsupported in this selected profile. No route or
metadata is exposed when omitted; this is backend composition, not a UI.

Select `http/password.NewSigninFeature` with this native `SigninService`, the
strict PostgreSQL rate owner, original pre-auth cookie and signed browser-device
codec. Match the original lifetime/remember, HTTPS origin/callback and session
cookie profiles. Omission exposes no route or metadata. The real HTTP integration
checks both browser and persistent sessions: wrong-password attempts leave the
flow issued without orphan sessions, and fresh cookie/CSRF delivery matches the
primary session record after atomic original-flow consumption. Restart recovery
returns credential-free history under original possession and current policy.
This fixture's explicit policy/risk callbacks are not durable-risk or provider
proof; browser, full password lifecycle and release qualification remain pending.

Original signup links can be explicitly confirmed with
the typed `email.RegistrationVerificationService` implemented by `SignupService`:
`VerificationConfirm(ctx, email.VerificationConfirmRequest)` and proof-free
`VerificationRecover(ctx, email.VerificationRecoveryRequest)`. The existing
`ConfirmRegistrationVerification` receipt API remains compatible. Select the borrowed native
`SignupVerificationConfig.Counters` at startup and install the forward kernel
`EmailVerificationMigrationSource` and risk `VerificationCounterMigrationSource`
after their selected existing histories. Nil counters preserve signup/scanner
behavior but disable confirmation. The service authenticates the actual issued
proof and encrypted signup intent, checks the exact callback/current policy,
and coordinates original-grant counters, one-use consumption, address/version
changes, audit and lifecycle in one protected command. It does not fabricate a
session, resend mail or use scanner validation as permission to execute.

Use a stable confirmation command ID for retries; replay preserves the original
receipt without charging again. `RecoverRegistrationVerification` accepts only
the original command/tenant/user/actor/identifier scope and current authorized
caller, not a bearer. It reconciles retained metadata after restarts without
renewing proof or revealing address/session data. This native registration
bridge is not yet the complete generic email lifecycle.
There is deliberately no independent setter or application-written workflow.

Select `http/email.NewConfirmationFeature` for the original-signup HTTP route,
supplying this `SignupService` as its borrowed `ConfirmationService`. Use the
strict PostgreSQL rate adapter and its schema/atomic migrations, mapped tenant
host, exact trusted HTTPS origin, current query-policy revision and service
actor. The feature owns wire parsing and server audit correlation; the native
service retains proof/current-policy admission and the atomic command. Omission
exposes no route or metadata. This selected profile returns no session.

Fresh typed confirmation returns the exact active verified email projection only
after commitment, current disclosure authorization and a bounded primary read.
The address and verification versions must match the retained transition, not a
later replacement. Replay and recovery return original correlation/outcome only;
they never return an address or session. One deadline covers mutation and the
post-commit read. A later read, authorization, cancellation or panic failure
clears address output without erasing known commitment. Inspect both outcome and
error before using a result; retry/recovery must preserve original command scope.
The projection is not a current authorization lease or cached validity evidence.

`RegistrationVerificationRateSource(ctx, proof, callback, caller)` supplies
authenticated original subject, signed grant ID and unchanged signed lifetime
for verification rate admission after trusted-IP counting. Current query policy
and the exact original callback apply; no mailbox or command is exposed. It
also permits counting consumed provenance for an original command replay, not
reuse. It neither charges counters nor proves current account/proof eligibility;
confirmation still owns those checks and the atomic mutation. Do not log the
returned identifiers or substitute a request-claimed subject or command ID.

## Native required-verification signup

`NewSignupService(primaryPool, SignupConfig, localKeyring)` implements the public
`password.SignupService` port. Configure the actual identity field processor and
schema, canonical address owner, bounded canonical user-ID selector, registration
policy, original pre-auth keys/allowlists, risk admission, HIBP screening, and
native capability issuer/codec and encrypted delivery owners. ConfigurationID
pins callback/provider semantics that cannot be inferred from function values;
change it when those semantics change. Keep original configuration and keys for
the retention lifetime of request mappings. Active envelope-key rotation alone
does not select a new request profile.

For subsequent native signin, select `SignupConfig.AuthorizationNamespace` to
match the user-policy namespace consumed by signin/session admission, and install
the authorization owner's authority migration. Signup initializes that owner's
policy epoch inside the same protected transaction as password, factor authority
and account creation. Occupied-address acknowledgement never resets existing
authority. Leaving the namespace empty preserves the registration-only profile;
it does not provide the policy authority needed for later signin. Namespace
changes select different preparation custody, so retain original configuration
for outstanding recovery.

Install the existing kernel registration/neutral-acceptance, request-key/input,
preparation/admission, password, pre-auth session, capability issuance, delivery,
audit and lifecycle histories before calling the service. It borrows a primary
pool and local keyring and does not migrate, send email, retry or create a second
journal. Remote decryption providers are not selectable. Each call owns its
participant; simultaneous callers must each own equal independent passwords,
not share one live Secret borrow.

Call `Signup(ctx, request)` with one original pre-auth cookie and initiating
idempotency key. Required verification returns an anonymous policy acknowledgement
with no subject/session for both creation and occupied identifiers. Hashing occurs
only after original risk admission and the configured HIBP decision. Issuance
bearers transfer directly to encrypted delivery and never enter public results.
Identical retries retain original IDs and effects; changed intent conflicts.

Persist the explicit `result.Recovery.Bindings()` projection through trusted
transport and reconstruct it with `password.NewSignupRecovery`. Call
`RecoverSignup(ctx, password.SignupRecoveryRequest)` using the original cookie,
correlation and fresh caller provenance, without password/address/retry key.
Recovery checks current disclosure policy and authenticates the original encrypted
input before reconciling the existing journal. Deleted or expired live flows do
not renew historical input, credentials or delivery. Unknown remains unknown;
an input read is never proof of rollback or permission to execute.

After an interrupted final transaction, reconciliation requires every frozen
owner's authoritative evidence. Missing issuance records are not negative
evidence: the command remains pending rather than claiming rollback, generating
another credential, or disclosing account/session authority.

Native email composition uses `ReadRegistrationVerification(ctx, proof, caller)`
to authenticate the durably issued signup proof and original encrypted mailbox
intent. Supply the actual confirmation caller, current query policy revision,
`identity.email.verification-confirm` action and signed `identity.user` target;
never impersonate the signup actor. No original cookie/password/live flow is
required. The returned sensitive spec and original replay-key version are only
for the native email owner, not a public scanner result or current authority.
Read-only reconstruction neither verifies the address nor consumes a proof,
issues a session, regenerates input or renews original expiry. Confirmation must
still fence current identity/capability state and apply protected effects in the
sole native coordinator transaction. Keep original configuration/encryption and
email-intent keys through retention; changed profiles fail closed.

For public scanner inspection, call
`ValidateRegistrationVerification(ctx, proof, callback, caller)` on the same
signup service. It returns only boolean eligibility, never address, account,
grant or originating-command metadata. Match the exact original allowlisted
callback and current confirmation policy context described above. A scanner may
omit the user resource ID: the authenticated proof selects it without rewriting
the actual caller. An explicitly supplied foreign target still denies. Issued, unused,
primary-unexpired proof state and current active account/pending identifier must
agree with original signed/encrypted intent. Foreign callbacks, changed records,
inactive accounts and unavailable checks fail closed. Validation is read-only:
repeated/concurrent scanners cannot consume, renew, deliver or create a session.
It is not an execution ticket; explicit confirmation must repeat admission.

This initial profile requires verified email and issues no session. Immediate
session, MFA continuation and the complete reset lifecycle remain
in development; unsupported startup profiles fail closed. This is backend
composition, not a signup UI or a complete platform/release-readiness claim.

## Original password-signin storage

`NewSigninSigningKey(id, privateKey)` freezes a complete consistent Ed25519 key
for the native password-login owner. Destroy the deployment's original input
buffer after construction. The value exposes no public signing operation or
private-key projection; it is not a standalone authentication service. Retain
the corresponding public verification key across rotation according to original
command/proof retention. The private native execution path uses the sole kernel
coordinator for signed-original, pre-auth, session, synchronizer and required
audit/outbox effects. The session owner alone grants original reveal-once bearer
and synchronizer delivery after a new successful commit. A delivery-time failure
does not rewrite committed history as rollback; no credential is returned.
`NewSigninService(pool, config)` composes the exported backend Go
`password.SigninService` port, not a UI or an HTTP handler. The constructor
freezes original flow keys, email normalization, signing/verification keys,
current policy, bounded password verification and session/risk configuration.
It does no IO, installs no migrations and starts no background work. Select
exact HTTPS origin/callback allowlists and install every owner's existing
migration history before using it.

`Signin(ctx, request)` accepts the original opaque pre-auth cookie and caller-owned
raw password. It resolves verified canonical email through the email/kernel
owners, counts risk before real or dummy comparison, authorizes current policy
and commits original authentication with pre-auth consumption and session/CSRF
effects. Preserve the resulting server-generated `Recovery`; destroy password
custody after the call. Only an error-free original commit permits reveal-once
bearer/CSRF delivery. Errors never deliver credentials, even after a known commit.

`SigninRateSource(ctx, request)` authenticates original pre-auth cookie, origin,
callback and remember choice, then returns the same email normalization used by
`Signin` (including unchanged invalid-email input for dummy work). Debit the
trusted IP budget before this read, then debit the identifier budget and invoke
`Signin` with the same immutable request. The result is not account existence,
authentication or permission to signin. It performs no account lookup, password
comparison, risk charge, command creation, flow consumption or session issuance.
Errors and cancellation return no identifier. Do not log its sensitive result;
the caller retains password ownership and destruction.

`RecoverSignin(ctx, request)` accepts original cookie possession and password-free
correlation with fresh trusted caller provenance. Current disclosure policy
controls historical visibility before and after primary reconciliation.
Consumed/expired pre-auth and deleted live session payloads do not erase the
original committed `SessionID`. Recovery returns no live `Session`, bearer,
cookie or synchronizer and never compares a password, charges another login
attempt, generates a new session or renews authority. Unknown outcomes retain
their original correlation; do not resubmit secrets to retry the mutation.

This development profile supports verified-email single-factor login only.
Successfully compared obsolete hashes are upgraded to the bounded current
issuance profile in the original signin transaction. Material and kernel
credential versions advance once, the user aggregate and credential-authority
epoch advance independently, and the new session uses only that successor.
Earlier credential-authority-bound sessions are invalidated; user/identifier
authority and original risk/policy/expiry bounds are not renewed. A digest of
the complete salted replacement binds it into the existing keyed command;
neither the verifier nor password enters the journal. Concurrent predecessor
changes and required-effect failures abort every provisional write.
Same-password rehash retains the original signin risk decision; it does not
establish a different password. Signup, set, change, reset and administrative
establishment still require their HIBP-screened preparation profiles.
MFA continuation, verification-policy variants and the canonical phone
entrypoint remain pending.
HTTP transport is a separate opt-in feature; complete login parity and release
qualification are not established by these backend checkpoints.

Migration 5 adds immutable original password-signin records, distinct from
password-verification records. `Repository.SignInAuthentication(ctx, proofID)`
implements the upstream `authentication.SignInSource` optional read contract:
exact primary lookup exposes only the original committed password-signin command.
Missing, pending and aborted rows return the same invalid-proof classification;
corrupt, oversized or foreign-index records fail closed without partial output.
Original signatures, full-width versions and nanosecond timestamps are retained.
The reader performs no signing, authentication, consumption or freshness renewal.

Forward this read through the configured authority source; do not replace the
expected authenticator or reconstruct its opaque `AuthenticatedProof` from a
password comparison. There is no independent record setter: the native signin
workflow above persists only real successful authentication through its
coordinator with pre-auth, session and audit/outbox effects. This read contract
alone is not an authentication endpoint and does not establish registration,
MFA or complete login parity.

## Original reauthentication records

Migration 3 adds immutable original signed password-verification storage, bound
to the original kernel command. `Repository.Reauthentication(ctx, proofID)`
implements `authentication.ReauthenticationSource` using a bounded primary-only
read. The globally unique proof ID supplies the lookup key; indexed tenant/user
must match the complete upstream record. Pending, aborted and absent commands
return `authentication.ErrInvalidProof`, never a provisional original.

Signature bytes, full-width versions and original nanosecond timestamps retain
their exact values. Closed canonical bytes reject duplicate/unknown fields,
foreign scope and corrupt or oversized payloads. No private signing key, raw
password, hash, session bearer or renewable validity lease belongs in this table.
The upstream authenticator owns configured evidence-key verification, exact-use
and freshness validation; this reader does not authenticate signatures or check
current credential/session authorities. An expired original remains historical
data, not renewed permission.

The native service below issues originals; password change consumes them in the
protected transaction. No independent writer, automatic cleanup, replay framework or application-written
proof store is introduced. Lifecycle/retention must be coordinated before this
profile is released; original records cannot be removed independently of their
command history. The native SQL fixtures prove retrieval and installed schema
constraints. One-use protected mutation remains separate from verification.

## Native password reauthentication

`NewCookieVerificationWorkflow(service, retainedCSRFKeys)` selects the separate
portable cookie-verification port. Freeze 1..4 distinct dedicated keys at startup;
the complete session state names the sole eligible key. Missing, foreign, wrong
or retired synchronizers deny before password work. The same session-owned
`RequireCSRF` authority fences the original record and active family under the
existing proof/audit/outbox transaction; rotation without a version change denies.
The base bearer service is not mutated. Synchronizers remain reusable and unchanged,
and concurrent valid non-keyed invocations issue distinct original proofs.
Scoped recovery returns only history, without password/token/proof redelivery.
HTTP origin/channel enforcement and complete release qualification remain pending.

### Email-management primary admission

`NewEmailPrimarySource` selects exactly one startup-allowlisted
`identity.password.verify` target: `identity.email.verification-send`,
`identity.email.change-request` or `identity.email.address-remove`. Audience is
explicit; proof age is positive and capped at five minutes. Transport must be
explicit too: cookie requires retained synchronizer keys and the original
session-bound token; bearer rejects synchronizer keys/tokens rather than falling
back to ambient cookie authority. Dependencies are borrowed and concurrent-safe.

`Prepare` authenticates the original bearer and signed password proof using the
existing authentication validator and native record source. It retains the
original session, action, credential/version and exclusive expiry, not a renewed
session or boolean clearance. `Original` and `Deadline` disclose that unchanged
intermediate custody, never current permission. `Command` freezes exact command,
address, original session and proof digest plus bounded typed domain fields.
Implicit formatting/serialization redacts or denies custody export.

The registered native email owner calls `Admit`/`Consume` in its protected Work
and `Check` in its final callback. Current directory, password reference,
authorization version, session/family and selected synchronizer are fenced in
that same transaction. Consumption uses the existing password record and
exclusive one-use lock, checking original expiry again after waiting. A rollback
rolls back proof use; a second command cannot consume a committed use. The
coordinator owns required audit/lifecycle staging and closure. Propagate every
error; neither preparation nor a consumer marker proves the complete email
transition or its outcome after an ambiguous commit.

Install `EmailReauthenticationMigrationSource` in `identity_password` before
protected email use. It includes the unchanged eight predecessors plus opt-in
version 9, widening only the named consumption purposes while preserving the
original foreign keys, one-use index and populated records. Use the existing
bounded migration runner; changing the CHECK constraint requires a table lock
and validates retained rows, so plan the upgrade for the table's actual size and
traffic. Default `MigrationSource` remains unchanged; no new route is enabled.

The email workflow separately owns current factor/risk/admission policy, request
keys, address comparison/collision, delivery, required token/session/lifecycle
effects and complete recovery. This port is not a finished email-change service.

### Original password reauthentication

`NewReauthenticationService(pool, config)` composes the real password verifier,
primary session lookup, kernel coordinator, authorization engine, risk admission,
security audit and lifecycle outbox. Install their owned migration histories,
including password migration 3, before use. The configuration is trusted startup
input: select the password single-factor session profile, independent lookup,
identifier/risk and Ed25519 evidence keys, bounded verifier/dummy-hash policy,
current authorization/query policies and an exact target allowlist. The constructor
does no IO and never creates schema or starts background work.

`Verify(ctx, request)` accepts opaque source bearer/password custody, a trusted
tenant and human caller, trusted network/device provenance and an allowed target.
It derives the account abuse dimension rather than accepting a client-selected
digest. Authentication counting and audit precede real password comparison.
Wrong, blocked or changed credentials return a neutral result with no proof.
Protected execution locks and rechecks original directory, credential,
authorization, session/family and material authority through the sole kernel
transaction. The original signed proof, mandatory audit and lifecycle event
commit together. Verification neither extends the source session nor consumes
the proof. Unsupported organization, factor and source-method profiles deny.

The result's sole `authentication.ReauthenticationProof` is released only after
a new known commit and final freshness checks. TTL is positive and at most 15
minutes, capped by original session and credential lifetime. Destroy the caller's
password after the call. Never serialize or log requests, configuration, keys,
raw driver errors, bearer values or verifier material.

When an outcome is unknown, retain its server-generated command ID and use
`Recover(ctx, tenant, commandID, caller)` under current disclosure policy.
Recovery accepts no password/bearer and reports original outcomes without
reissuing proof, renewing freshness, recharging risk or retrying the mutation.
A failed protected transaction leaves no proof or lifecycle event; a known
rollback includes its required terminal failure audit. An audit outage can
prevent terminalization and therefore remains unknown rather than being called
successful or certainly aborted. Do not automatically resubmit the password.

The pool and callbacks remain caller-owned and must support concurrent use.
Earlier caller deadlines win; the service owns no goroutine or retry loop and
never closes the pool. This backend composition is not an HTTP endpoint or a
completed password-reset workflow. Retention, all-factor composition and
release qualification remain pending.

`NewVerificationWorkflow(service)` binds that same native owner to
`password.VerificationService` without changing existing direct APIs. Supply a
complete trusted `DecisionContext` and original bearer/password/target custody;
the native owner still selects current policy and validates original authority.
No caller-written store, proof engine or transaction workflow is required.
This bearer-input seam does not supply a cookie-protected verification profile;
HTTP must acquire only its explicitly selected channel, not ambient cookies.

Portable `Recover(ctx, query, caller)` requires matching tenant, original human
user/actor, operation `identity.password.verify` and record equal to command ID;
anonymous/link scopes and foreign/incomplete context deny before native IO.
The existing direct recovery signature derives the same scope and remains
unchanged. The integration lane exercises portable issuance and proof-free
recovery against native signed records and atomic SQL effects, while retaining
legacy direct callers. Complete cookie lifecycle, browser interoperability and
full release qualification remain pending.

The optional password HTTP module now selects real native verification through
`NewBrowserDeviceBearerVerificationFeature`: original Authorization bearer
plus signed `__Host-identity_device` correlation from the configured browser
initialization issuer. Native Authentication risk requires this device signal;
the generic cookie-ignoring bearer handler alone cannot satisfy that profile.
Compose native session validation, strict atomic PostgreSQL rate storage and
`NewVerificationWorkflow(service)`, retaining the issuer's dedicated device
keys/namespace and original tenant/HTTPS origin/expiry. No consumer workflow or
device minting in verification is needed. Focused in-process integration retains
the stored signed original, audit/outbox and unchanged-session assertions;
it does not prove browser interoperability or complete release qualification.

For original cookie sessions select `NewCookieVerificationFeature` with
`NewCookieVerificationWorkflow(service, retainedCSRFKeys)`, the original secure
session-cookie policy, exact trusted HTTPS origins and the same dedicated device
issuer. The distinct native cookie owner validates the synchronizer in the
original proof transaction; HTTP parsing is not authority. Selected-router
integration exercises absent device/CSRF, wrong synchronizer/password and the
known committed proof projection against actual OpenAPI. The returned locator
loads the stored signed original and feeds real cookie password change, which
consumes that original proof atomically. Verification preserves session and
synchronizer state and never issues or renews credentials. These in-process
HTTPS facts are not real-browser or deployment qualification.

## Native authenticated password change

`NewPasswordChangeService(source, config)` borrows a configured native
reauthentication source and composes the upstream signed-proof validator, core
password screening/preparation and native protected counters. Install additive
password migration 4 and the selected risk counter migrations. In the source's
session namespace install the unchanged base history, then
`CSRFMigrationSource`, `OTPMigrationSource`,
`CredentialContinuationMigrationSource` and `PasswordChangeMigrationSource`
in permanent forward-only migration slots. Upgrade relevant session readers
before enabling continuation; older readers reject its stored profiles.
The source must
allow the exact purpose `identity.password.verify`, action
`identity.password.change` and configured audience. Select explicit HIBP policy,
bounded provider collection and the source's existing password primitive.

For a credential-mutation policy requiring `velocity`, collect only genuine
provider facts (including HIBP): native preparation and primary-time rechecks
defer that signal to the mandatory transaction-owned counters. Supplying a
velocity observation is rejected. Existing profiles without that signal retain
complete provider assessment; neither profile can omit protected counters.

`Change(ctx, request)` accepts the original opaque bearer, original signed proof,
new owned password secret and trusted caller/network scope. It denies current
password reuse and rejects incorrect proof bindings. HIBP collection and hashing
run before SQL locks; original provider observations are checked again against
primary time without refreshing their timestamps or calling providers in Work.
The proof's original expiry and configured maximum age bound the remaining
operation. Destroy the caller's secret when the call returns.

The sole kernel transaction consumes the original proof exactly once, updates
password material and credential/user authority, and writes mandatory audit and
lifecycle outbox effects. Rollback restores proof availability and material;
the protected risk attempt is not refunded. Original signed record bytes remain
unchanged. Startup `SessionDisposition` selects preserve, revoke-other or
revoke-all; `MaximumSessions` limits the complete active-state set, not each page.
Zero values select **revoke-all**, including the source, and a cap of 100000.
Requests cannot override policy. The original command freezes the selection and
limit; exceeding the cap rolls back all effects, including proof consumption.

Preservation continues eligible single-factor password sessions against the
exact successor reference and credential epoch without changing historical
authentication, login freshness, activity/lifetime, remember policy, bearer
lookup, session/family versions or CSRF state. Stale/expired/family-denied
supported sessions revoke; an unsupported preservation profile denies the whole
transaction rather than manufacturing authority. Revoke-other keeps the source
and terminally revokes others; revoke-all also revokes the source. Fresh password
reauthentication over a continued bearer uses its effective credential version,
not the original login version. `AuthorityInvalidated` describes predecessor
credential authority, not revocation of every continued session.

Session effects and their original-command recovery evidence share the existing
password transaction; applications supply neither a session store nor a second
transaction. Retained evidence survives live session cleanup. Administrative/
reset replacement, history, other-factor preservation and complete lifecycle
qualification remain in development.

Retain the result's server-generated command ID. Unknown outcomes must be resolved
with `Recover(ctx, exactQuery, caller)`, not automatic password resubmission.
Recovery uses original committed effects under current disclosure policy and
accepts no password, bearer or provider callback. Positive successor/authority
results require a known commit. This is backend composition, not an HTTP endpoint
or full password lifecycle/release qualification.

## Composition

1. Install the identity kernel and its credential-reference migration history.
2. Install `MigrationSource{}` through the owned `go-migrations/v3` Runner and
   PostgreSQL backend, using the permanent `identity_password` ledger namespace.
   Existing unmanaged schema objects fail rather than being adopted. History is
   forward-only; keep installed version 1 unchanged across upgrades. Version 2
   adds retained, hash-free replacement-effect bindings and supports populated
   version-1 upgrades. Install kernel `CredentialReplacementMigrationSource`
   before enabling the native replacement profile.
   Version 6 permits reset-complete effects in the same retained material table;
   prior migration bytes and password-change receipts are unchanged. Reset uses
   only the private native workflow, not the registered hash-only change writer.
   The complete public reset workflow is still in development.
3. Construct the reader using an existing caller-owned **primary-only**
   `go-postgres.Pool` and the password owner's constructed primitive policy:

```go
reader, err := passwordpostgres.NewRepository(pool, passwordpostgres.Config{
    MaximumDuration: time.Second,
    HashPolicy: selectedPasswordPolicy,
})
if err != nil { return err }
// Supply reader as password.VerifierConfig.Repository.
```

The module is `github.com/faustbrian/go-identity/password/postgres` and package
name is `passwordpostgres`. Core verifier composition still requires an exact
current-policy dummy hash, explicit byte/time bounds and trusted clock.

## Ownership and security

- `ReadPasswordCredential` takes a trusted tenant and already canonicalized
  kernel account ID, without email/phone lookup or normalization.
- One SQL statement joins material, kernel reference, user status and the
  credential epoch. Material/reference versions must agree. Full uint64 values
  round-trip without narrowing; inactive eligibility is preserved, not restored.
- The exact encoded hash retains algorithm parameters. The primitive parses it
  under the selected owner's verification limits, including permitted legacy
  profiles; this adapter never hashes, verifies or chooses issuance policy.
- Hash transfer is bounded in SQL before client allocation. Missing scope is
  `password.ErrCredentialAbsent`; corruption, missing schema and storage failures
  are redacted `password.ErrPasswordWork`. Cancellation/deadline errors survive.
  Do not expose missing-credential classification through an enumeration-prone
  endpoint; the core verifier owns neutral comparison results.
- Returned `CredentialSnapshot` uses the core's opaque immutable custody. Its
  explicit hash projection is sensitive: never log it or raw driver errors.
- Reads neither cache nor create a proof/freshness lease, and perform no mutation,
  provider calls or network retries. Core comparison rechecks primary state; a
  protected command must still recheck authority and coordinate all effects.
- The repository owns no background work and never closes the borrowed pool.
  Keep it alive until calls finish. Each call derives its explicit bounded
  lifetime; earlier caller deadlines win. Zero repository/configuration denies.

The material table's tenant/account primary key supplies lookup and uniqueness;
its FK retains the kernel reference. No extra covering index or performance
improvement is claimed. Deletion needs the future coordinated participant rather
than an independent delete or cascading loss of credential state.

## Existing-password material replacement

Register this exact repository as the `identity/password/postgres` contributor
in the kernel coordinator. Its sole current `FeatureOperations` declaration is
the existing-password change storage profile, schema `password-change` version
1. Construct `identity.NewFeaturePasswordHashCommand` with the eight exact
`kernel.CredentialReplacementFields`, original binding and the already generated
verifier. Scalar hashes, hash-free commands and undeclared fields are rejected.
Select the original protected audit, credential subject and `password.changed.v1`
lifecycle with exact reference predecessor/successor. The existing outbox owner
must implement `kernel.CredentialReplacementLifecycleContributor` and persist
both staged lifecycle and the independently owned replacement successors.

The repository's pure `ValidateFeatureCommand`/`CredentialReplacement` methods
enforce the configured current issuance algorithm and selected work parameters.
`ApplyFeature` runs only during this exact instance's native coordinator
invocation, after the kernel has locked active user/reference authority. It
locks owned material, bounds transfer before allocation, checks the full-width
material/reference predecessor and parses existing material under legacy read
limits. One CAS changes version, exact verifier bytes, algorithm and monotonic
update time, then inserts original-command evidence in the same `Work`. It does
not write kernel tables, perform cryptographic work, invoke a policy callback,
begin/close a transaction or retry. Earlier deadlines win; cancellation survives.

Only the coordinator commits the provisional receipt together with kernel
versions, audit and outbox. Retained material effects complement its journal,
not a second success authority. Recovery matches original scope/transition;
missing effects prove native noncommit, while conflicting/missing infrastructure
is unknown. A later password replacement cannot erase the original effect or
receipt. Do not prune effects independently of command-owner retention, deletion
and legal-hold rules; that lifecycle remains pending.

This is a **trusted persistence seam, not an authenticated password-change
endpoint**. Use the native service above for authenticated change; do not expose
this lower-level seam directly. Browser transport and the remaining password
lifecycle still need their owned composition. Do not provide application-written
stores or workflows to bridge those unfinished contracts.

## Native verification and remaining work

### Keyed authenticated password change

For adapter-neutral composition, call `NewChangeWorkflow(keyedService)` and
pass the returned owner as `password.ChangeService`. Its `Change` accepts the
core `password.ChangeRequest`, including the sole required `IdempotencyKey`;
its `Recover` accepts original code-free correlation and current trusted caller
policy. The native service still owns the entire execution and recovery. This
binding adds no transactions, retry, provider call, mutation authority or store.
It borrows the existing service and must be drained before borrowed owners close.
Zero/missing owners and keyless inputs deny. Earlier caller cancellation is
preserved without entering native work. Existing direct keyed and unkeyed
service APIs remain available unchanged. The optional HTTP module supplies
selected bearer and cookie change handlers; complete lifecycle and browser/
release qualification remain pending.

Use `NewKeyedPasswordChangeConfig` with a kernel-constructed `RequestKeyConfig`,
a dedicated nonzero intent HMAC key and the active encryption key ID. Compose
`NewKeyedPasswordChangeService` with the existing native reauthentication source,
password-change policy and a borrowed local `keyring.Provider`. Pass one
`identity.IdempotencyKey` to `Change` alongside the native request. This is an
additive service: the existing unkeyed `NewPasswordChangeService` is unchanged.
Public retry-capable endpoints must explicitly choose the keyed service; it
does not silently fall back when keyed custody is unavailable.

Install the kernel's request-key, request-key-preparation, preparation,
admission-preparation and counter-preparation migration sources in that order
after the credential-replacement history, using your selected monotonic migration
versions. Existing password, session, risk, audit and outbox prerequisites still
apply. Missing histories fail rather than creating application-owned stores.

Matching retries restore original encrypted custody before current-material
lookup, hashing or external screening. They return the original command's
outcome, including after its source bearer has been revoked. Different password,
proof or network input conflicts under the same key. Busy and unknown outcomes
are not permission to submit a new key: use `Recover` for authorized code-free
original-outcome reconciliation. Neither recovery nor matching terminal replay
extends proof or risk freshness or recharges the original counters.

Keep the namespace, lookup/intent keys and behavior configuration stable while
their mappings are retained. Active envelope-key rotation is supported only
while original decrypting keys remain in the borrowed local keyring. This
profile intentionally excludes network/KMS providers so restoring custody never
introduces network work inside a protected transaction. Passwords, bearer bytes
and retry keys are never stored in the encrypted preparation; the original
predecessor verifier is sensitive retained encrypted material. Destroy the
caller-owned password secret after the call, and keep borrowed owners alive
until all calls finish. Earlier caller, proof and original risk-signal deadlines
win. Provider failures and expiry deny rather than renew observations.

The integration lane requires a task-owned disposable loopback PostgreSQL 18.4
cluster and fails when absent; it never silently skips. It installs real kernel
and password histories and exercises the public core against the real reader.
Synthetic material is not provider/interoperability or migration-import proof.

Complete transactional lifecycle, schema-health/reference composition, populated
legacy migrations, backup/restore, exact coverage/mutation, production-shaped
benchmarks, clean consumer and release qualification remain pending.

See [CHANGELOG.md](CHANGELOG.md).

### Strict cookie password-change composition

For adapter-neutral browser composition, bind a constructed strict cookie owner
with `NewCookieChangeWorkflow(cookieService)` and consume the core
`password.CookieChangeService` interface. The wrapper forwards the original
`CookieChangeRequest.Request` retry key, upstream proof, password and token to
the same native owner; it does not create a workflow, journal or CSRF engine.
Zero/canceled/structurally invalid inputs deny before native work. Exact-origin
and channel admission still belong to trusted HTTP composition, not this wrapper.
Real PostgreSQL tests use this portable port for commitment, fresh-owner replay,
retired-key denial, changed-token conflict and code-free recovery.

The optional `identity/http/password` module can select this cookie workflow,
this repository's original signed-proof source and the session owner's primary
`NewSessionService`. Supply one shared atomic native PostgreSQL rate owner with
both rate migrations installed, exact trusted origins and mapped tenant hosts.
The HTTP module owns strict wire parsing and destroys its request password;
this adapter still owns the original journal and atomic protected effects.
The integration lane contributes `NewChangeFeature` to the selected base
router, sends the cookie change through its actual handler, and validates
native success, matching replay, missing-CSRF denial and changed-input
pre-command conflict against the same selected OpenAPI 3.1.1 response schemas.
In-process HTTPS facts do not prove a real browser or network journey.
Browser and full lifecycle/release qualification remain pending.

Select `NewCookieKeyedPasswordChangeService` over a configured native keyed
service and 1..4 distinct eligible session CSRF keys. The constructor copies
the selection and does not change the original bearer service. Submit one
`CookiePasswordChangeRequest` containing the native input, exactly one
`IdempotencyKey` and an opaque `session.CSRFToken`. The selected transport must
also enforce exact trusted origin, strict cookies and one canonical CSRF
channel; the native service does not interpret HTTP requests.

Tokenless sessions and absent/foreign tokens deny. The session owner checks the
exact original named-key state both before preparation and under the existing
primary session fence before protected admission/mutation. A primary rotation
after observation denies even when the old token initially matched. No raw
CSRF bytes are stored or revealed. The session digest engine also supplies
domain-separated stable token intent; this correlation is not admission and
does not renew original evidence. Retain eligible old keys while their sessions
are supported. Removing an original key fails closed; bearer and cookie intents
cannot silently share an original outcome under the same retry key.

The native integration lane exercises a known cookie commit, exact session
continuation, retained-key restart, code-free recovery and original receipt
replay after source revocation. Retiring the original named key denies even
committed receipt replay; submitting a different CSRF token under the original
retry key conflicts before provider work. Original outcome disclosure does not
renew authentication or reauthorize a mutation. Complete password HTTP lifecycle
and browser/release qualification remain
in development; synthetic local provider seams are not HIBP interoperability.
