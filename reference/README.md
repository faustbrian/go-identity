# Identity reference composition

## Optional native passkey backend

`Passkey.TOTP` selects original UV-passkey plus independent confirmed-TOTP
completion through `FeatureSet.PasskeyTOTP()`, using real native owners and
common session read/logout. Native selection enables no new HTTP route. Select
`HTTPPasskey.MFAContinuation` with `Signin` and independently select
`HTTPMFA.PasskeyTOTPVerify` for explicit challenge-only signin and exact
`X-MFA-Variant: passkey` completion. Without that opt-in, generic signin rejects
the native MFA profile. See [the profile and lineage limits](PASSKEY.md#original-passkey-plus-confirmed-totp).

Completed passkey/TOTP sessions can use safe inventory and explicitly selected
`Passkey.SessionManagement` with `TOTP:true` for a fresh action-bound UV label
rename. That selection requires the native TOTP owner and original current
factor/session authority; it does not enable MFA key enrollment/removal or
another secondary-factor fallback. Native selection adds no HTTP route.

For the HTTP completed-MFA inventory/rename profile, independently select
`HTTPPasskey.Inventory` and `HTTPPasskey.SessionUpdate` with that native cookie
management selection, the original graph CSRF keys and shared rates. Use the
completed TOTP session cookie for safe inventory, then a new action-bound UV
assertion for the two-phase rename. Original factor authority and metadata-only
retries remain native-owned. See [the HTTP walkthrough](PASSKEY.md#http-inventory-and-fresh-uv-rename-after-totp).

Independently set `Passkey.SessionEnrollment.TOTP` with the selected transport
and `Passkey.KeyedOptions` to add a key from a completed passkey/TOTP session.
The existing three-phase API requires fresh action-bound UV, preserves original
factor/session and assertion expiry, and returns only metadata on retries.
The new key still requires independent MFA at signin. This native selection
does not enable HTTP enrollment or MFA key removal.

For HTTP enrollment, independently select `HTTPPasskey.SessionEnrollment` with
that native cookie/TOTP selection and safe inventory. Keep password-proof
`HTTPPasskey.Registration` disabled: the shared registration routes select the
three-phase current-session UV workflow explicitly. Original CSRF/Origin,
factor authority and retry custody remain mandatory. See the
[HTTP enrollment profile](PASSKEY.md#http-additional-key-enrollment-after-totp).

Independently set `Passkey.SessionDeletion.TOTP` with `Passkey.TOTP` and
`Passkey.KeyedOptions` for resident-key removal from a completed MFA session.
Fresh action-bound UV and another usable key are mandatory. Removal invalidates
old sessions; surviving-key signin must complete TOTP before original metadata
recovery and read/logout. The ordinary profile remains separate; this selection
adds no HTTP route or secondary-factor fallback.

Independently select `HTTPPasskey.SessionDeletion` with that native cookie/TOTP
owner for the existing HTTP delete/recover workflow; password-proof `Delete`
remains disabled. After removal, discard the old session, sign in with the
surviving key and complete TOTP before metadata-only recovery and logout.
See [the HTTP MFA removal profile](PASSKEY.md#http-resident-key-removal-after-totp).

For a passkey-only backend, explicitly select `Passkey.Standalone`,
`Passkey.Signup`, `Session.Passkey` and durable PostgreSQL admission. The same
sealed construction graph runs with no password, OTP or delivery configuration
and zero delivery-worker arguments. Opt-in signup and discoverable-only HTTP
compose the genuine registration -> read/logout -> fresh signin journey;
`HTTPPasskey.DiscoverableOnly` rejects identifier-based requests without an
email parser. See [the standalone deployment profile](PASSKEY.md#passkey-only-deployment)
for exact configuration, owner migrations and excluded mixed/management modes.

`HTTPPasskey.Conditional` separately selects conditional presentation of
discoverable options, including in that standalone graph. The native facade
also exposes explicit conditional option methods. Request/ceremony mode,
remember choice, expiry and consuming verification remain unchanged; this is
backend option generation, not browser UI. See [the conditional profile](PASSKEY.md#conditional-presentation).

`StoreConfiguration.Passkey` composes the delivered existing-account native
enrollment, identified signin, safe inventory and cookie-CSRF session/logout
owners. `FeatureSet.Passkeys()` retains graph startup, tenant and shutdown
guards. No passkey HTTP route, named HTTP method or UI is enabled implicitly.
See [passkey configuration and consumer journey](PASSKEY.md) for exact scope,
matching keys, selected migrations and the genuine registration-to-passkey test.
Identifier-free resident signin is separately enabled by the trusted
authentication policy's `PasskeyDiscovery`; false retains identified-only
signin. Both modes use the same guarded passkey session read/logout owner.
`Passkey.KeyedOptions` separately enables native original-key options and
metadata-only retry through that handle; it creates no HTTP routes.

`Passkey.Signup` additionally composes native passkey-first account creation.
Supply its distinct `identity.passkey.register-verify` browser-flow config and
protected provider custody keys, leaving their clock/evaluator absent for graph
injection. No email or password is required for the new account. The existing
deployment's enrollment/signin configuration stays explicit and unchanged.
Apply the selected forward migrations, then use `PrepareSignupFlow` ->
`IssueSignupFlow` -> `KeyedSignupOptions` (or `SignupOptions`) -> `Signup` on
`FeatureSet.Passkeys()`. Only fresh acknowledged commitment reveals bearer/CSRF;
retry/recovery returns original metadata, not replacement credentials. Common
read/logout requires `Session.Passkey`; signup itself enables no HTTP route.

Select `HTTPPasskey` separately for cookie enrollment options/verification,
original-flow signin options/verification and safe inventory. Each group is
explicit; identifier-free mode additionally requires both HTTP and native risk
opt-ins. Common session read/logout remains independently selected. The graph
supplies actual native owners, signed device custody, shared rates and exact
email comparison policy, not application-written handlers. `HTTPPasskey.Signup`
separately selects passkey-first HTTP signup when native `Passkey.Signup`,
`Passkey.KeyedOptions`, `HTTPPreAuth` device custody and `Session.Passkey` are
configured. Begin with `POST /v1/session/preauth-issue` method `passkey-signup`,
then use the canonical registration pair with explicit `mode:"signup"` and
the original flow/cookies. Enrollment retains its unchanged proof/session
variant; failure never selects another branch. See [the passkey guide](PASSKEY.md)
for the closed payloads. Browser UI remains outside this HTTP profile.
Independently select `Passkey.Management` for signed-proof label rename, and
`HTTPPasskey.Update` for its cookie endpoint. Retain original retry custody;
the graph appends forward metadata/proof histories without changing signin
authority. See the linked passkey guide for the exact configuration and rollout.
For current-passkey-session UV rename without a password proof, separately
select `Passkey.SessionManagement` and `Passkey.KeyedOptions`, then obtain the
guarded `Passkeys().SessionManagement()` handle. It also works with
`Passkey.Standalone`; its native selection exposes no HTTP routes. Explicitly
select `HTTPPasskey.SessionUpdate` for its two-phase cookie endpoint; it is
mutually exclusive with password-proof `HTTPPasskey.Update`. See the
[passkey guide](PASSKEY.md#current-passkey-session-rename) for the two-phase API.
For additional resident keys without password proofs, explicitly select
`Passkey.SessionEnrollment` with `Passkey.KeyedOptions` and obtain the guarded
`Passkeys().SessionEnrollment()` handle. The graph delegates genuine UV options,
compound authorization/registration options and finalization to native owners;
it supports the passkey-only deployment and enables no HTTP enrollment profile.
See [additional enrollment](PASSKEY.md#current-session-additional-enrollment).
Select `HTTPPasskey.SessionEnrollment` independently for the cookie-only
three-request registration profile. The graph supplies actual session/CSRF and
shared rate owners; no password proof or device cookie supplies enrollment
authority. Signup may share the route pair without sharing its flow authority.
Select `Passkey.Deletion` independently for fresh-proof credential removal;
it requires this graph's actual configured email/password reset recovery owner,
not label management. `HTTPPasskey.Delete` separately enables its cookie-only
endpoint. Removal revokes affected passkey sessions, preserves the original
password session for metadata-only retries and returns no replacement secret.
For passkey-only removal instead, select `Passkey.SessionDeletion` with
`Passkey.KeyedOptions`, then obtain `Passkeys().SessionDeletion()`. The guarded
native handle supplies genuine removal UV options, exact completion and current-
session metadata recovery. Another usable resident ES256 key must remain; no
password/email/OTP fallback is inferred. Install WebAuthn history through
migration 6. Native selection enables no delete HTTP route. See
[resident-key removal](PASSKEY.md#current-session-resident-key-removal).
Select `HTTPPasskey.SessionDeletion` separately for its cookie-only
options/completion/recovery endpoint. The graph supplies the same native owner,
session/CSRF and shared keyed rate admission, not a password proof or device
cookie. It is mutually exclusive with password-proof `HTTPPasskey.Delete`.

## Native secondary-OTP enrollment

`StoreConfiguration.MFAOTPEnrollment` selects pending OTP enrollment separately
from TOTP enrollment, password-origin OTP login and HTTP. Supply configuration,
keys, a consuming MFA OTP policy, templates and the existing external sender;
the graph composes its actual password-proof, session, risk, OTP, delivery and
coordinator owners. `Native.Primary` and `Native.Risk.Evaluation` must be absent.
Session lookup and CSRF keys must match this graph's genuine current sessions.

After applying the selected owned histories and calling `FeatureSet.Initialize`,
use `MFAOTPEnrollment().Enable` with fresh purpose-bound primary proof, original
session/CSRF and an exact existing verified identifier. The result is pending;
only its fresh committed response reveals recovery codes. Destroy that material
after explicit delivery. Use `MFAOTPEnrollmentConfirmation().OtpSend`, run the
selected delivery worker, then call `OtpVerify` with the captured code and
original enrollment custody. Confirmation activates the factor but issues no
login session. Original recovery returns no replacement codes or new authority.

Password-origin secondary login separately selects `PasswordSignin.OTP` and
`HTTPMFA.PasswordOTPSend`/`PasswordOTPVerify`. Its primary returns only a child
continuation; final OTP completion issues the usable session. Enrollment and
login share OTP's configured resend family: retain its original cooldown rather
than resetting it. The graph exposes no enrollment HTTP route implicitly.
Retained handles deny before initialization, outside the selected tenant and
after `Close`, including historical recovery. No domain stores, migration SQL
or replacement authentication engine are supplied by the application.

## Optional anonymous browser workflows

`StoreConfiguration.Anonymous` composes actual native guest signin/read and
optionally deletion/upgrade. It enables no HTTP. The reference graph injects
its counted risk and password-proof owners; applications supply configuration,
keys and bounded policy callbacks, not domain stores or substitute workflows.
`FeatureSet.Anonymous()` retains selected native operations/recovery under the
initialized tenant and shutdown lifetime. Recovery never redelivers credentials.
`FeatureSet.AnonymousPreAuth()` exposes the same guarded native initiation owner
for Prepare/Issue and metadata-only Recover, without selecting any HTTP feature
or changing the existing OTP/password flow profiles.

`HTTPAnonymous` independently selects `Signin`, `Read`, `Deletion` and `Upgrade`.
Signin adds the named `anonymous` method to `/v1/session/preauth-issue`; Read
extends the existing cookie `/v1/session/get` with explicitly unprivileged guest
metadata. The three mutation routes require one `Idempotency-Key`; upgrade
additionally needs both original cookies/synchronizers and a genuine fresh
password action proof. See [the exact browser contract](../http/anonymous/README.md).
Nil selection exposes no routes, metadata, named method or guest read fallback.

Select the same installed session store as password/OTP composition, separate
guest/permanent cookie names, matching retained lookup/CSRF keys and the common
signed device/exact Origin profile. `Anonymous.Validation.Clock` and deletion's
validation configuration stay absent for graph injection. Upgrade additionally
requires password signin/verification and permanent read/signout selection; its
primary uses cookie custody, `identity.anonymous.upgrade` and the target-session
audience. The graph injects password verification CSRF keys. The finite upgrade
preserves its existing password target and transfers no application resources.
Its issuer cookie must match the permanent cookie policy; permanent reading and
signout must retain its lookup/CSRF keys. Incompatible selection fails before
serving, while retained rotation keys remain supported.

Apply every selected native history through `ReferenceMigrationApply` before
initializing or serving. Anonymous histories append last to the existing kernel,
session, password, MFA, capability, risk, audit and outbox predecessors; they do
not rewrite installed prefixes. Keep the installed session lineage when adding
later profiles. Readiness checks the selected successor constraints as well as
the original migration ledgers. Closing the graph cancels/drains active native
and HTTP work and permanently denies retained handles.

### Explicit abandoned-guest maintenance

Select `Anonymous.Cleanup` independently of `Anonymous.Deletion` and HTTP.
Supply native `anonymouspostgres.CleanupConfig` with this graph's exact
repository/session/global authority and authorization revision/engine, a fixed
trusted service actor, retention evaluator, original keys and bounded batch.
Leave `Cleanup.Clock` nil: the graph supplies its system clock. Construction
does not perform cleanup, install history or create a scheduler/HTTP route.

Apply selected forward expiry histories, then initialize and call
`features.Anonymous()` → `CleanupExpired`. Preserve the random run ID, returned
seek cursor and each original recovery query; `RecoverCleanup` reconciles
unknown outcomes without guest credentials or reexecution. Individual subjects,
not the batch, are atomic/idempotent commands. Held/deferred subjects remain in
observable backlog and are revisited by a later run from zero. Disabled,
uninitialized, foreign-tenant and closed-graph handles deny maintenance.
`TestReferencePostgresAnonymousCleanupWithoutDeletionOrHTTP` demonstrates
genuine guest issuance, expired/pruned history, cleanup and original recovery.
The upgrade-with-cleanup journey also exercises selected successor readiness.

The external-package integration journey is
`TestReferencePostgresAnonymousUpgradeHTTP`: real PostgreSQL bootstrap → target
registration/delivered verification/password signin → guest signin/read → fresh
target proof → guest upgrade → permanent session read/logout. The companion
`TestReferencePostgresAnonymousSigninReadDeleteHTTP` exercises self-deletion.
They supply only declared application policy and external sender/HIBP seams;
the graph supplies actual handlers, migrations, transactions and credentials.
The deletion journey selects no neighboring atomic-rate HTTP feature, and
`TestReferencePostgresAnonymousNativeWithoutHTTP` proves native initiation,
signin, recognition and deletion with no HTTP graph or server selected.
Run from this module with a task-owned PostgreSQL 18 fixture using the existing
`IDENTITY_REFERENCE_POSTGRES_PORT` test input:

```sh
go test -race -tags=integration -count=1 -run '^TestReferencePostgresAnonymous' .
```

Agent runs must also set task-owned disposable Go caches and remove the fixture
afterward. These journeys are selected-profile proof, not UI, provider delivery,
deployment or complete platform/release qualification.

## Explicit phone/password recovery

`StoreConfiguration.PhonePasswordReset` explicitly composes the native recovery
owner and original target-bound browser; `HTTPPhonePasswordReset` separately
selects its two POSTs and named `phone-reset` preauth method. Both native carrier-
risk acceptance flags are required. This reference profile requires
`DurableAdmission`, native password/session configuration, OTP custody, delivery
and the local keyring. It injects those real owners, independent confirmed-TOTP
verification and the same durable counter state—not application stores.
An optionally selected email reset must use that same session schema; conflicting
combined stores are rejected without changing the email migration history.

The original browser has recovery purpose and zero Remember. HTTP additionally
requires `HTTPPreAuth` with the same signed device/cookie/origin and shared strong
HTTP admission. Install/check every selected native migration through the
existing reference operator APIs before initialization. Nil selection exposes
neither routes nor metadata. A request202 is only an enumeration-safe public
acknowledgment; it is not evidence that a recipient exists or delivery committed.

The consuming native workflow owns canonical reset capability, purpose-bound
SMS, independent TOTP, distinct risk, HIBP/password replacement and atomic
all-session revocation. It never signs in or issues a cookie. Original recovery
remains native, code-free and outcome-only. See the [selected recovery journey](PHONE.md#independently-selected-phonepassword-recovery)
for concrete configuration, original retry and rollback semantics and the real
PostgreSQL/HTTPS consumer commands. Selected-profile acceptance does not imply
real-provider delivery, complete platform qualification or deployment.

## Optional existing-account phone verification

See [phone enrollment and consumer journey](PHONE.md) for native/HTTP selection,
fresh password-action proof, encrypted SMS delivery, counted verification and
code-free original recovery. Phone signup, signin, reset and replacement are not
enabled by this selection. The same guide describes independently selected
phone/password and phone SMS-code login, original target-bound initiation and
the resulting session read/logout journeys.

## Optional delivered email OTP signin

See [email OTP composition and consumer journey](EMAIL_OTP.md) for native/HTTP
selection, actual queued delivery, counted consumption, known-empty MFA fencing,
browser/persistent sessions and code-free original outcome recovery.

## Optional delivered magic-link authentication

See [magic-link composition and consumer journey](MAGICLINK.md) for native/HTTP
selection, signin-only and optional signup, real queued delivery, scanner-safe
explicit consumption, supersession and session/logout through public owners.

## Optional username authentication

See [username composition and consumer journey](USERNAME.md) for native/HTTP
selection, original registration confirmation, migration order, protected rename
and explicit unsupported profiles. This is backend composition, not a UI.

## Optional email-confirmation hooks

Independently select `Email.Change.Native.ChangeHooks` for managed change links
(including configured TOTP changes), `Email.OTPVerification.VerificationHooks`
for pending-address OTPs, or `Email.OTPChange.VerificationHooks` for new-address
OTP changes including selected first-primary establishment. Nil disables each
selection. The existing native transaction still owns identifier, proof,
notification and session effects. A success-observer error preserves commit and
original recovery while withholding the address; it is not rollback or a reason
to submit another logical attempt. Recovery never repeats observers. No route
or feature is implicitly enabled by supplying callbacks.

Set `PasswordSignup.Native.Verification.Hooks` or
`Email.Verification.Native.VerificationHooks` to an immutable
`email.NewVerificationHooks` selection. The graph passes it to the actual native
owner; no HTTP middleware, new route or implicit feature is added. Nil is
disabled. Change the enclosing native `ConfigurationID` when callback semantics
change and retain original configurations for recovery.

Callbacks receive read-only correlation, not addresses or credentials. Before
may reject before reservation. After observes a fresh known commit outside SQL;
an error retains verification/recovery but suppresses address projection and
following signin. Replay and recovery never retry callbacks. Unknown/rollback
do not invoke After. These existing verification fields do not select OTP or
email-change callbacks.

## Original-browser registration verification and signin

Set `PasswordSignup.VerificationSignin` to a native
`passwordpostgres.VerificationSigninConfig` with the existing session issuer/CSRF
and matching email-grant authority/audience. Keep the signup authorization
namespace and selected `Session` read/logout composition consistent. The graph
installs the native email-grant record predecessors and an independent forward
verification-signin suffix; existing history/checksums are preserved.

`FeatureSet.RegistrationVerificationSignin()` provides the guarded native port.
Independently set `HTTPRegistrationVerification.Signin = true` to select the
original-browser profile of the existing confirmation route. HTTP signup
initiation and signed browser-device custody must also be selected. This
registration-only selection rejects `ManagedAddresses`; default/shared managed
confirmation remains verification-only. No extra endpoint is implicitly exposed.

The complete journey is registration, captured delivery, verification, fresh
email-possession signin, primary session read and logout. Both original browser
and persistent remember choices are retained. Verification commits first; later
login denial/ambiguity conserves that known outcome. Replay and metadata recovery
never create replacement credentials. The default selection requires known-empty
MFA; it does not bypass enrolled factors.

### Optional verification-origin TOTP

Set `PasswordSignup.VerificationSignin.TOTP` to a native `MFAChallengeConfig`
with only `totp`, the actual capability issuer, encrypted preparation custody,
bounded lifetime and attempt budget. Also select
`PasswordSignup.VerificationTOTP` with the completion counter policy, independent
comparison key and retained envelope/risk keys. The graph supplies the actual
signup browser keys, verification primary and transaction/session owners.
Pin `PasswordSignup.VerificationSessionLineage` once: `VerificationBeforeMFA`
for a verification-only installation (or a fresh verification-first graph),
`MFABeforeVerification` for an installation that already applied native MFA
session migrations before verification signin. Keep that migration lineage when
selecting other MFA methods later. It describes installed history, not desired
factor policy. New verification-TOTP composition rejects an omitted lineage;
an incorrect lineage fails compatibility rather than rewriting applied history.

`FeatureSet.RegistrationVerificationSignin()` then returns `Challenge` rather
than an authenticated session for a genuinely enrolled factor. Preserve its
original proof and immutable deadline; complete through
`FeatureSet.VerificationTOTP()` with the original signup browser/pre-auth ID,
challenge ID, enrolled factor and actual code. The resulting email-possession
MFA session supports the ordinary session read/logout ports. Wrong codes share
the original budget; current parent/account/identifier/factor/policy changes
deny. A failed or ambiguous child cannot undo committed email verification.
Metadata recovery cannot replace lost credentials or restart their deadlines.

HTTP is separately opt-in: `HTTPRegistrationVerification.Signin` selects
confirmation, and `HTTPMFA.VerificationTOTPVerify` selects completion. Pending
confirmation returns `signin.challengeRequired`, its ID/method/expiry and
reveal-once `X-MFA-Token`, without an authenticated cookie or synchronizer. Send
the proof, challenge/factor/pre-auth IDs, code and original callback to
`POST /v1/mfa/totp-verify` with the original browser/device cookies and exactly
`X-MFA-Variant: verification`. Omitting that header never selects this owner.
Only successful completion delivers the session cookie and `X-CSRF-Token`.
Native selection alone exposes no route. Secondary OTP, recovery, WebAuthn and
trusted-device completion are not selected by this TOTP-only configuration.

## TOTP-protected primary-email change

Select `Email.TOTPChange`, `Email.Change` and
`MFAEnrollment.ActiveStepUp.EmailChange` with matching proof audience and
`email.RequirePrimaryAddress`. The account must have a genuine verified primary
and confirmed TOTP enrollment. The shared graph supplies the original factor
proof, session, authorization, transaction, delivery and forward migration owners.
Apply the selected migration plan before serving; populated rows are preserved.
The source may be a retained password session or a genuine password/TOTP or
password/recovery session. Both the source session's original factor and the
fresh action proof's factor remain subject to current-authority checks.

Obtain an active-TOTP proof for exactly `identity.email.change-request`; submit
it with the original session and CSRF custody to the keyed change request.
Deliver the new-address link through the ordinary sender, validate it without
consumption, then explicitly confirm. Promotion, old-address notice and required
session effects are atomic. No replacement session or auto-signin is issued.
The link cannot outlive original proof age/expiry/session validity; revocation,
enrollment or factor-generation changes deny, even with a newer valid login.
Exact retries and recovery disclose only original metadata, not fresh secrets.

HTTP is independent: select `HTTPMFAActiveStepUp.Purposes` containing that exact
purpose and `HTTPEmailRequests.ChangeRequest`/`ChangeConfirm`. Send the proof ID
returned by `/v1/mfa/totp-verify` with `X-MFA-Variant: step-up`, then use the email
endpoints with the original cookie, CSRF and idempotency key. Native selection
alone exposes no route. This profile does not select initial-primary change,
new-address OTP, other factor methods, privacy or login.

Administrative email removal is independently opt-in. Set
`Email.Removal.Primary.AdministrativeTargets` for the native owner, and separately
`HTTPEmailRequests.AdministrativeRemovalTargets` with `AddressRemove` for HTTP.
HTTP selection requires native selection. Supply an actual authorizer granting
the exact actor/action/tenant/target, not a role string or client override.
The actor retains their original fresh password/session/CSRF; both accounts must
have authoritative known-empty MFA for this selected profile. Target signin/reset
eligibility, token retirement, session invalidation and audited pending cascade
admission commit together without changing the actor's session. Empty target
preserves self behavior; native selection alone exposes no HTTP capability.

For the runnable PostgreSQL registration/verification/signin/session/logout
backend, see [BASELINE.md](BASELINE.md). It is an explicit local profile, not
a UI, production deployment or whole-platform release.

## Selected native email management

`StoreConfiguration.Email` independently selects `Verification`, `Change`,
`Addresses`, `Removal`, `OTPVerification` and `OTPChange`. `FeatureSet.EmailVerification()`, `EmailChange()` and
`EmailAddresses()` expose only their selected native workflows; none enables an
HTTP route. An empty selection or missing required authority fails construction.
Handles require initialized graph custody and an allowed tenant, and deny after
graph shutdown without taking ownership of the supplied PostgreSQL pool.

### Primary-email OTP replacement

Select `Email.OTPChange` with `EmailOTPChangeConfiguration` alongside actual
`Email.Change`/old-address notice and password-session composition. Its policy is
email-change, with its own request-key namespace, retained password-session keys,
existing comparison domain and code template. Apply selected migrations and
initialize the graph before `FeatureSet.EmailOTPChange()` calls.

The native journey is the existing keyed fresh-password change request, an
independent `EmailChangeRequest` naming that committed command/candidate, captured
code delivery and consuming `EmailChangeConfirm`. Success replaces one genuine
primary, notifies its original old address after confirmation, and invalidates
old identifier-bound sessions. `RecoverEmailChange` observes original metadata
under its distinct current disclosure permission without comparison or effects.
To establish a first primary for an account with exactly one verified email and
no primary, additionally set `Email.OTPChangeInitialPrimary = true` and select
`email.PrimaryOrSoleVerifiedAddress` on the original change owner. The old
verified mailbox and its identifier/verification history stay unchanged; the
new address becomes the sole primary with the same notice and session effects.
Neither setting alone enables this transition. Default selection remains
genuine-primary-only. Stronger-factor and auto-signin variants are not enabled.
This native selection alone exposes no HTTP capability. Independently set
`HTTPEmailOTPChange` with `HTTPEmailOTPChangeConfiguration` to select the three
[public OTP change routes](../http/otp/README.md). Supply exact HTTPS Origin,
the existing browser-device policy and policy revision. Native change/notice,
session and strong `HTTPRate` storage are required, not their other HTTP routes.
The graph owns limiter shutdown and selected rate migrations. Nil HTTP selection
advertises no route or OpenAPI capability. The documented handlers can also be
composed directly without the reference server.

### Pending-email OTP verification

Select `Email.OTPVerification` with `EmailOTPVerificationConfiguration` and call
`FeatureSet.EmailOTPVerification()`. The native graph supplies actual OTP,
session, factor-authority, risk, delivery, audit/lifecycle and migration owners.
Configure email-verification attempt policy, the existing comparison domain,
retained session keys matching the password issuer, explicit freshness,
`CurrentAttemptKeyVersion`, dedicated request-key namespace/intent keys and a
selected code template/locale. OTP signin and link HTTP routes are not required;
original known-empty factor authority must come from real account creation.
Apply the graph's selected migrations, then initialize custody before use.

The consumer journey is registration/verification/password signin, managed
pending address addition, independent delivered OTP Send, code completion and
verified-address projection. Addition retains its fresh password admission;
verification Send does not demand a second password proof. Success invalidates
old identifier-bound session authority and issues no replacement session.
Known-empty MFA, self-user and pending-nonprimary are explicit scope limits.

Independently select `HTTPEmailOTPVerificationConfiguration` for the three
[public OTP routes](../http/otp/README.md). Configure exact HTTPS Origin, actual
existing browser-device policy and current policy revision. Native email OTP,
session and `HTTPRate` storage are mandatory; their other HTTP routes are not.
Nil selection advertises no route/OpenAPI capability. Simultaneous
`HTTPEmailSignin` selects a conflicting Send profile and is rejected, not merged
or silently weakened. The selected migration source includes OTP consuming
custody even with `OTP.Signin=nil`; later selecting signin preserves installed
shared history. The graph owns limiter shutdown but borrows the primary pool.

Preserve original Send keys and completion recovery metadata. Recovery reports
committed/noncommitted/unknown original history under current authorization,
without comparing/debiting, returning an address or renewing executable authority.
Do not resubmit a completion to recover an uncertain commit.

Set `EmailManagementConfiguration.Keyed` explicitly for durable request
correlation. The corresponding handle's `VerificationSendKeyed`,
`VerificationResendKeyed` or `ChangeRequestKeyed` takes the native request plus
its original `identity.IdempotencyKey`. Add/change use empty command/address IDs;
resend keeps the exact pending address and leaves command ID empty. The kernel
chooses and retains the winning command, and the native owner retains original
encrypted authority/intent before execution. Matching retries return original
metadata without another message, even when the original proof is spent.
Unselected and wrong-profile calls deny; no call falls back to unkeyed work.
Request-key query policy uses the graph's policy revision. Existing selected
kernel histories already include request-key/preparation support. This native
selection does not create request HTTP routes.

The storage-neutral `FeatureSet.EmailVerificationRequests()` and
`EmailChangeRequests()` ports use the same selected keyed native owners. They
accept email-owned requests without a caller-selected command ID. Preserve the
original idempotency key, signed password proof, session cookie, synchronizer,
callback and candidate on retry; do not replace an uncertain request.

Explicitly select `HTTPEmailRequestsConfiguration.VerificationSend`,
`.ChangeRequest` and/or `.ChangeConfirm` for their canonical routes. Request
routes require native keyed management and cookie password-proof custody, not
the HTTP password-verification route. Configure the trusted HTTPS `Origin` and
current `PolicyRevision`; confirmation also requires the trusted service
`ActorID`. Change uses new-address possession plus required old-address notice.
The graph borrows existing strict rate owners, guards the entire request lifetime
including proof reads, and exposes no disabled route or OpenAPI operation.
For add/resend confirmation also select `ManagedAddresses` as described below.

Separately set `HTTPRegistrationVerificationConfiguration.ManagedAddresses`
to accept both signup and managed-add links on the single existing verification
route. It requires native `Email.Verification` and matching issuer audience,
signer/resolver, limits, skew, revocation and retained replay custody. Both
owners retain their bounded trusted clock policy and independently check current
authority. The graph authenticates the original signed profile before choosing
one owner; no source failure falls back to the other. False preserves signup-only
HTTP behavior. This flag selects no add/resend/read/change/removal route.

Select `HTTPEmailAddressesConfiguration.Get` and/or `.List` separately for native
reads. To enable administrative targets, select
`Email.Addresses.AdministrativeAudit` with a positive acknowledgement budget
within `Email.Addresses.Native.MaximumDuration`; the graph constructs the existing
PostgreSQL audit adapter using its borrowed pool and installed audit migrations.
Independently select `HTTPEmailAddressesConfiguration.AdministrativeTargets`
to accept and advertise `targetSubjectID`. Native-only selection opens no route,
and HTTP selection without auditing fails startup. The actual authorizer must
grant actor/action/tenant/target; configuration is not a permission. Required audit
failure withholds data; self reads remain unchanged. No new store, worker,
credential or mutation is introduced.

The default HTTP profile remains
cookie-authenticated self reads. Native `Email.Addresses` and session composition
are required, but HTTP session routes are not. Existing HTTP session/MFA-list safe
routes lend their actual limiter, including its emergency budget. Leave
`StandaloneRate` nil when borrowing; otherwise provide its explicit bounded
fallback recorder, namespace and capacity. Conflicting budgets fail construction.
Unselected reads have no route or OpenAPI capability. The selected read profile
has no administrative target override, bearer fallback, refresh or mutation.

Management requires selected password verification with its exact email action
and audience, known-empty MFA, original current session authority and encrypted
delivery. The graph supplies the actual proof, protected counter, risk, template
and delivery owners. The provider evaluator and protected counters must use the
same immutable risk policy, not independently constructed copies with matching
version numbers. Password screening must use that risk revision too. Cookie
management uses the existing password verification synchronizer keys; it has no
CSRF-free fallback. Address reads separately require explicit canonical-ID and
disclosure policy and use the graph's actual authorizer and primary repository.

Add/resend creates a pending address and delivered verification link, not a
session. Resend enforces the original committed cooldown and invalidates the
predecessor only on commit. Primary change verifies the selected new address,
applies the configured session effects and queues the original old-address
notice. Native typed recovery retains original metadata without repeating effects
or replaying credentials. Apply the selected forward histories with the existing
operator migration API before initialization; installed native prefixes are not
rewritten. Stronger-factor profiles remain separate unfinished work. Selected
local runtime proof does not imply whole-unit qualification.

For safe removal select `EmailRemovalConfiguration` and call
`FeatureSet.EmailRemoval()`. Actual `PasswordVerification`, `PasswordSignin`,
complete `PasswordReset`, session and known-empty MFA authority are required.
The graph supplies native proof, risk/counters and key owners. Native config
defines reuse, original request custody and complete pending cascade policy.
For explicit primary replacement, use the native request's
`ReplacePrimaryWithVerifiedEmail` disposition and `ReplacementPrimary` with the
exact surviving verified address ID and both versions. Promotion commits with
removal and does not renew verification age; HTTP exposes the same closed profile.
Authority scopes/material limits must be compatible. Retain signed targets on
new verification grants; unclassified live history denies removal.

Separately enable `HTTPEmailRequestsConfiguration.AddressRemove` with trusted
HTTPS Origin/current revision for its canonical route/OpenAPI; other request
flags may stay false. It borrows the keyed secret limiter and includes original
proof reads in graph cancellation/draining, with no authentication issuance.
Selected operator migrations install the native forward cascade suffix without
rewriting populated baseline history. See the
[wire example](../http/email/README.md#safe-self-removal). Pending cascade
correlation is not asynchronous consumer closure.

## Native password/secondary-OTP login

Select `PasswordSigninConfiguration.OTP` with `PasswordOTPConfiguration` and
explicitly include `"otp"` in `MFAChallengeConfig.AllowedMethods`. The graph
supplies the actual password primary, child issuer, original browser, session,
OTP codec/store and encrypted delivery owners. Call `FeatureSet.PasswordOTP()`
for native sending, verification and original-command recovery. Its retained
handle observes the same startup, tenant and shutdown admission as other
features; selecting TOTP alone never enables this handle.

`HTTPMFAConfiguration.PasswordOTPVerify` separately selects the native password-
origin `POST /v1/mfa/otp-verify` route and closed OpenAPI contract. Supply the
existing original-flow/device HTTP graph and verification-rate namespace/key;
missing native OTP dependencies fail construction, including recovery-only
graphs. It selects no OTP-send/enrollment route or TOTP fallback. The native
`OtpVerificationRateSource` authenticates exact retained input before mutable
state, preserves the original signed quota interval and exports zero metadata
on conflict, unavailable authority or cancellation. Rate metadata cannot grant
factor authority or issue a session. The selected email OTP consumer journey is
covered through actual native enrollment/delivery/confirmation, opt-in HTTP
send/verify, public session read, replay and factor-authority invalidation. This
does not qualify all MFA profiles or the complete reference backend for release.

Select `HTTPMFAConfiguration.PasswordOTPSend` independently for
`POST /v1/mfa/otp-send`; it borrows the graph's native password/OTP owner and
existing delivery-IP/destination limiter. It requires the same original
flow/device graph but no verification-rate configuration when sending alone is
selected. One unchanged initiating key maps through native request preparation;
HTTP never invents a command or chooses a recipient. HTTP 202 reports queued
metadata, not provider delivery or an authenticated session. Select verification
separately for delivered-code completion. Enrollment remains a distinct public
native workflow and is not implicitly exposed by either login route.

Configure a consuming `otp.PurposeMFA` policy, selected template/locale,
request-intent custody, original attempt-key version, protected counter/evidence
keys, and stable send/completion configuration IDs. Retained password-flow keys
must match the existing OTP store's browser-key versions/material. The OTP
issuer reuses that store's lockout/digest key identities rather than creating
another startup authority. Construction enables no HTTP route or enrollment.

The public migration plan/apply graph contributes independent OTP factor/send,
counter and session suffixes. Existing TOTP/recovery storage predecessors are
installed under their original namespaces without enabling those APIs; shared
MFA management allocations remain available. `FeatureSet.Initialize` registers
the actual OTP issuer before admitting calls. Real bootstrap/retry and later
TOTP selection are covered. The selected enrollment/login/HTTP acceptance below
uses supported native services and selected handlers; it is not proof of the
complete reference server's account/password/session operational baseline.

`NewPasswordOTPLoginSendService` composes a concrete `password/postgres`
`SigninService` selected with `MFAChallengeConfig.AllowedMethods = []string{"otp"}`
and a concrete `otp/postgres.MFALoginIssuer`. It requires a confirmed OTP factor;
pending enrollment, TOTP fallback and an unverified address cannot substitute.
Construct its intent custody with `NewPasswordOTPLoginSendConfig`, then select
the actual session/profile, cookie keys, issuer, coordinator, protected risk,
counter owner, keyring and exact origins. Change `ConfigurationID` whenever
borrowed policy callbacks or signing semantics change; retain original keys
and configuration for recovery.

Install the selected password-primary/continuation, browser, OTP/send-family/
issuance, request preparation, protected counter and delivery histories, including
`MFALoginSendCounterMigrationSource` and `OTPLoginSendMigrationSource`, and
initialize the native OTP issuer. The continuation records its exact committed
send/factor together with OTP/delivery effects, without renewing its scope,
version or shared attempt budget. Verification restores that source rather than
accepting a caller-selected recipient, factor or replacement challenge.
`OtpSend` accepts the actual issued child and original browser cookie, an enrolled
factor/channel and a request key. Its caller resource is `identity.mfa-continuation`
with the child ID. `RecoverOtpSend` instead requires the original command,
actor, anonymous browser flow and factor record, with an `identity.anonymous-flow`
caller resource. Recovery requires no proof/cookie and discloses no code.

The original OTP account/destination resend window spans enrollment and login:
confirmation or a new child does not refill it. Queue commitment is not provider
delivery or factor verification, and never issues a session. Run the actual
delivery worker with the configured bounded email/SMS sender. This standalone
native sending constructor alone does not select graph features or HTTP routes.
`NewPasswordOTPLoginCompletionService` adds actual verification and atomic
session/CSRF issuance. Unknown outcomes, matching replay and recovery withhold
credentials; original password freshness, remember policy and factor authority
remain bound. Use the selection above for graph-owned native composition;
OTP login sending/verification transport is selected as described above;
enrollment/confirmation use their supported native public APIs. No enrollment
HTTP route is implied. Full reference-server and remaining MFA qualification
are separate from this selected consumer proof.

The cross-owner journey is in `integration/password`. With the documented
disposable PostgreSQL fixture and candidate module wiring, run:

```sh
go test -race -tags=integration ./integration/password \
  -run '^TestSecondaryOTPPasswordLoginHTTPIntegration$/native-mfa-primary/public-enrollment/public-otp-enrollment$' -count=1
```

It uses the real password/factor/OTP/session/transaction owners and PostgreSQL
strict quotas. Only the declared external email sender captures generated codes;
no fixture supplies a fake domain store or issues an invented authentication grant.

## Selected native and HTTP disable

Set `MFAEnrollmentConfiguration.Disable` with `RecoveryPathEmail` and bounded
factor/primary maximum ages, alongside native `ActiveStepUp` and complete
`PasswordReset` request/completion/HIBP/delivery selection. Leave its Primary,
Sessions and Recovery unset: the graph supplies actual native owners and rejects
application substitutes. Obtain `FeatureSet.MFADisable()` after graph startup.
One/all targets and original disable-purpose proof require no private SQL query.
Fresh one-target results include safe unexpired pending siblings captured in the
protected transaction; those siblings and their recovery custody are untouched.
All-target retires them and returns an empty remaining set. Retained outcome
recovery/replay returns no fresh projections.

Set `HTTPMFADisable` separately for HTTP with exact native origins and explicit
shared-rate namespace/key. Native disable alone selects no route or metadata.
Authenticated TOTP HTTP may independently select `identity.mfa.disable`; neither
step-up HTTP nor factor-update HTTP is a mandatory disable dependency. Selected
histories append MFA v11 and session disposition v3 without rewriting prefixes.
Calls and retained handles obey graph startup/drain/shutdown and exact tenant.
Current scope is sole active TOTP plus bounded pending siblings/email recovery;
general multi-factor replacement, trusted devices and administrative recovery
remain unfinished. The reference acceptance crosses disable and actual emailed
password reset/delivery/completion into replacement-password login.

## Selected MFA inventory

Set `MFAEnrollmentConfiguration.Listing = true` for guarded native
`FeatureSet.MFAListing()`. It reuses this graph's actual session reader and policy
engine and the TOTP-only PostgreSQL metadata owner; graph startup/tenant/shutdown
guards remain effective. Other MFA methods/devices remain outside this profile.

For a graph selecting `MFAOTPEnrollment`, set its `Listing = true` to compose
the coherent native OTP/TOTP reader instead. The same public handle returns
unexpired pending, confirmed and retained revoked metadata plus unused recovery
counts. Recipient destinations and credentials are never returned. This remains
independent of OTP login, HTTP and factor mutation. If TOTP management is also
selected, its safe labels are included; unsupported factor authority fails
closed rather than returning a partial inventory.

Set `StoreConfiguration.HTTPMFAList = &HTTPMFAListConfiguration{}` to select
`GET /v1/mfa/list` when HTTP session routes already exist. Both borrow the exact
same safe limiter, including emergency capacity. Without HTTP session routes,
provide explicit `StandaloneRate` namespace, maximum keys and bounded degraded-
event callback. Native sessions remain required, HTTP session routes do not.
Conflicting simultaneous standalone/session rate ownership is rejected. Selecting
listing does not select enrollment, login, step-up or regeneration routes.

Real selected-reference journeys cover empty→enrolled inventory, actual code
consumption count10→9, missing-cookie/target-query denial, standalone route
selection, corrupt inventory, account blocking and post-read authority loss.
These are bounded slice results, not complete MFA/platform release qualification.

**Development checkpoint:** this module currently includes the
PostgreSQL-journaled, TLS Valkey velocity store graph and optional native OTP
Send/delivery composition with opt-in single-factor OTP sign-in. An IO-free
`NewServer` now exposes exact health/readiness probes and opt-in original-flow
HTTP initiation and selected email OTP Send/signin/recovery over that same graph.
Optional `PasswordReset` composes the native public request/completion/recovery
service with graph-owned risk and encrypted delivery; `HTTPPasswordReset`
selects its two routes using the existing signed-device and primary rate owners.
The selected PostgreSQL/TLS-Valkey integration journey proves reset delivery,
completion, predecessor-session revocation, old-password rejection and usable
replacement-password login. Full release and remaining reset failure-path
qualification are not complete.
Fresh dependency readiness is available for this selected graph; remaining
HTTP features and complete identity journeys remain unimplemented. Selected-module
migration Check/Plan/Apply and durable native command resume are available as
explicit store operations, not automatic startup behavior.

### Selected password TOTP completion

Select `PasswordSignin.MFA` for password-first challenges and
`PasswordSignin.TOTP` for native completion. `FeatureSet.PasswordTOTP()` returns
the composed completion service. Independently select
`HTTPMFA.PasswordTOTPVerify` for its HTTP route and `HTTPPasswordSignin` for
password signin. This does not select magic-link login.

Password signin delivers a pending challenge and reveal-once `X-MFA-Token`,
not a session. Complete it through `/v1/mfa/totp-verify` with
`X-MFA-Variant: password` and the original flow/device cookies. Successful
completion delivers a session cookie and CSRF token only once. Current password
and factor authority, original primary expiry and browser binding remain
mandatory; neither a challenge nor a replay grants a new session.

The selected real PostgreSQL/TLS-Valkey HTTP journey creates the account and
factor through public operations, completes password/TOTP, reads the resulting
MFA session and logs out. This is development evidence, not full platform or
release qualification.

### Selected password recovery-code completion

Select `PasswordSignin.MFA.AllowedMethods` as `[]string{"totp", "recovery-code"}`
and configure `PasswordSignin.Recovery` with `PasswordRecoveryConfiguration`.
Its retained `VerificationKeys` must match every live enrollment/recovery-set
digest key version; missing or corrupt custody denies. The graph supplies the
original password/browser/issuer owners and counted risk policy. No TOTP login
completion owner or magic-link login is required by this recovery profile.
Enrollment confirmation remains a separate explicit selection.

Apply the selected forward migrations, start the graph, and obtain
`FeatureSet.PasswordRecovery()`. Submit `mfa.RecoveryUseRequest` with the
original continuation proof, flow cookie and opaque recovery code. The native
owner shares the original attempt budget and independently compares again under
locks before atomically burning the code and creating the session. The existing
preparation contract charges abuse-rate quota before output generation; that
charge survives a final abort and is never repeated for the same command.
Factor/child/session/lifecycle changes roll back together on final failure.

Independently select `HTTPMFA.PasswordRecoveryUse` for
`POST /v1/mfa/recovery-use`. Its closed body is `commandID`, `preAuthID`,
`continuationID`, `token`, `recoveryCode` and `callbackURL`, with the original
flow/device cookies and exact Origin. Only fresh committed delivery emits
session/CSRF credentials. Retry and code-free `RecoverRecoveryUse` preserve the
outcome without credentials. This profile imposes no additional post-login
remediation (`recoveryRequired:false`); factor-sensitive changes still require
their own eligible fresh proof and cannot substitute a recovery login.

The real PostgreSQL/TLS-Valkey journey captures a public enrollment code,
completes password-first recovery, reads the session and logs out. It also
exercises wrong-code/browser denial, late lifecycle rollback, retained rate
quota, exact retry and lost-COMMIT-acknowledgement recovery. This is a local
development checkpoint, not full MFA or platform release qualification.

### Selected magic-link TOTP completion

Select primary continuation with `MagicLink.Request.MFAContinuation` and
`MagicLink.Consume.MFA`, then select native completion with `MagicLink.TOTP`.
`MagicLinkTOTPConfiguration` supplies bounded completion timing, versioned
comparison/envelope custody and durable counters in the graph's risk namespace.
Its counter policy must be the graph's exact immutable policy; its risk policy
version is independent of the authorization revision. The graph supplies the
actual original request issuer, browser keys, session profile and provider
evaluator. Apply the selected native migrations before startup; existing
histories remain unchanged, and readiness requires current MFA successors.

After graph startup, `FeatureSet.MagicLinkTOTP()` returns the public
`mfa.TOTPCompletionService`. Submit the original child proof, browser cookie,
challenge/factor IDs and opaque TOTP code to `TotpVerify`. Only a new committed
invocation returns reveal-once session/CSRF custody. Wrong codes spend the shared
budget once per command; authenticated missing/ineligible factor selections
use the same budget after a protected eligibility recheck. Retry and
`RecoverTotpVerify` preserve original outcome
without credentials. The original primary and completion policy IDs stay
distinct. Unsupported trusted-device requests deny rather than silently degrade.

The native PostgreSQL/TLS-Valkey journey exercises primary HTTP delivery,
advanced factor epochs, encrypted factor custody, foreign-browser denial,
wrong-code accounting, competing completion, replay/recovery and current MFA
session validation. Enrollment remains a pre-existing-authority fixture, not a
public enrollment claim. The graph's selected session reader and cookie signout
now retain current MFA authority, including CSRF denial, protected lifecycle
rollback and terminal recovery. Explicit `HTTPMFA.TOTPVerify` selection exposes
the concrete TOTP completion route with the same native owners. The real HTTP
journey proves credential delivery, metadata-only exact retry, session read and
logout. This is backend composition, not a UI or a complete platform release.

The selected native TOTP handle also implements
`TotpVerificationRateSource(context.Context, mfa.TotpVerifyRequest)
(identity.UserID, string, time.Duration, error)` for consumer-owned HTTP rate
composition. Use the existing challenge verification limiter: IP admission
first, then this owned source read, subject/challenge admission, and actual
`TotpVerify`. Subject and child come from verified original issuance, never
JSON-selected identity or the transport actor. The interval is the original
signed lifetime, not remaining expiry; this quota profile requires an integral
microsecond interval between one second and five minutes.

An exact authorized committed or denied retry reads original command history
before mutable continuation/factor state. Conflicting input, unavailable
history or a foreign browser returns no quota metadata. The source read performs
no factor decryption, code comparison, native debit, reservation or issuance.
It is not completion permission. Expired proofs remain denied; use the existing
proof/code-free `RecoverTotpVerify` for historical reconciliation.

Set `StoreConfiguration.HTTPMFA` to `HTTPMFAConfiguration{TOTPVerify: true, ...}`
to select `POST /v1/mfa/totp-verify`. Actor and policy revision match native
primary issuance. Select the same verification namespace/key as other flows
when sharing their IP/subject budgets. The native TOTP, original pre-auth/device
and strict rate graph are required; omitted configuration contributes no route
or OpenAPI operation. No enrollment or trusted-device route is implied.

Select native authenticated step-up with `MFAEnrollment.ActiveStepUp`; the graph
supplies the real current-session owner and factor-verification migration.
Select `StoreConfiguration.HTTPMFAActiveStepUp` separately with exact native
allowed `TrustedOrigins`, stable `VerificationNamespace` and `VerificationKey`
to expose only the `X-MFA-Variant: step-up` arm of `POST /v1/mfa/totp-verify`.
The body is `commandID`, `factorID`, `code`; the current cookie, Origin and
synchronizer are mandatory. Only fresh known commitment reveals `proofID` for
recovery regeneration. Replay/uncertainty never redeliver it. No session,
enrollment or login route is selected by this option. Both original session
observations and proof freshness remain exclusive, non-renewable deadlines.
Recovery regeneration remains separately selected through native
`MFAEnrollment.Regeneration` and `MFARecoveryRegeneration()`. Select
`HTTPMFARecoveryRegeneration` with exact native allowed `TrustedOrigins`, stable
shared `RateNamespace` and `RateKey` to expose `POST /v1/mfa/recovery-regenerate`.
The body is `commandID`, `proofID`; the original cookie, Origin and synchronizer
are required. Count and freshness come from the native replacement policy,
not the request. The graph supplies the committed-only original factor-proof
source, native whole-set replacement and atomic session revocation. Selecting
this endpoint does not implicitly select the step-up, enrollment or login routes.

Only fresh known commitment returns the complete replacement set. All subject
sessions are revoked, so sign in again using an enrolled factor or a new recovery
code. Further HTTP attempts with the revoked cookie deny without returning codes.
Ambiguous responses retain the original command/outcome without plaintext; use
the native `RecoverRecoveryRegenerate` operation under trusted caller policy to
reconcile history. Neither that recovery nor matching native retries redeliver
codes. A real PostgreSQL/TLS-Valkey journey proves HTTP step-up, lifecycle rollback,
replacement, old-code denial, new-code login/logout, competing requests and lost
commit acknowledgement. This is slice evidence, not full platform release proof.

Select pending enrollment separately with `StoreConfiguration.MFAEnrollment`
and `HTTPMFAEnrollment`. The latter requires the real session, password
verification and strict HTTP rate graph, an exact subset of native management
origins, and stable rate namespace/key. `RecoveryCodes` defaults to ten and is
bounded to 1..20. It selects only `POST /v1/mfa/enable`; login is not a dependency
of that HTTP selection. Submit the original session cookie, synchronizer,
Origin, verification proof ID and unchanged request key. Success creates a
pending factor, not a session or active factor. Recovery codes appear only on
the fresh known commit. Matching retries cannot retrieve them again.

Native keyed preparation conceals preliminary rejection details as unavailable;
a wrong synchronizer can therefore return 503 without creating a factor or
consuming the verification proof. Never treat that response as permission to
replace request custody or bypass CSRF. Separate URI/confirmation operations
remain required and independently selectable below. Password-first MFA login
is independently selected through `PasswordSignin.MFA` and `PasswordSignin.TOTP`.

Set `HTTPMFAEnrollment.ProvisioningURI` explicitly to also select
`POST /v1/mfa/totp-uri`. The graph supplies the actual native original-custody
quota source and shares secret-operation rate budgets. The source is read-only;
it cannot consume revelation, decrypt the factor secret or renew the retained
disclosure deadline. The real journey proves HTTP URI delivery and metadata-only
replay.

Set `HTTPMFAEnrollment.Confirmation` with stable `VerificationNamespace` and
`VerificationKey` to select authenticated activation on the shared
`POST /v1/mfa/totp-verify` route. Use the same verification identity as other
flows when sharing their quotas. JSON contains only `commandID`, `factorID` and
`code`; `X-MFA-Variant: enrollment`, the original session cookie, exact Origin
and synchronizer are mandatory. Missing/unselected variants never fall back to
login. Native source reads do not compare codes or activate; protected execution
owns both. Activation/retry returns historical metadata, no session or URI.
The real HTTP enrollment journey includes confirmation and retains the original
SFA session unchanged. Password-first MFA login is independently selected as
described above; activation does not promote the original SFA session.

Reset currently requires the selected OTP/delivery graph and uses one of its
configured session schemas. Supply `PasswordResetConfiguration.Native` with
the native password profile, HIBP/password policy, issuer custody, current
authorization and explicit bounded callbacks; leave its risk evaluation and
request delivery owner/renderer unset so composition supplies the existing
owners. After explicit initialization, `features.PasswordReset()` returns the
public workflow port. Calls before initialization, after closure or outside
configured tenants deny. HTTP remains independently opt-in and requires the
existing `HTTPPreAuth.Device` and `HTTPRate` selections. Disabled reset HTTP
exports neither routes nor operation metadata.

The native reset integration uses the owned observed HIBP checker and signal
provider with the native PostgreSQL audit adapter,
with only fixed-endpoint HTTPS response IO substituted by synthetic fixtures.
It proves prefix-only padded requests and denial before protected effects for
breaches, malformed responses, outages and redirects; a zero-count padding row
permits the clean replacement. Replay performs no additional provider request.
Select `Native.CollectReset` with `Native.Screening.Collect` nil for attributed
screening. Its original binding and authenticated issuer challenge supply audit
identity without transport reconstruction or a fabricated attempt. Required
query/match/rejection records are checked in native storage. Synthetic lost
acknowledgement denies even a clean candidate; unchanged records reconcile
idempotently without screening again. This is consumer integration evidence,
not live provider interoperability, real audit transport-disconnect qualification
or a durable audit-outage backlog. A host selecting a different failure policy
must retain original records through the existing audit protocol, not invent a
second identity journal or silently accept undelivered required events.

`PasswordSignin` independently selects the native password login/recovery port,
available as `features.PasswordSignin()`. Supply `PasswordSigninConfiguration.Native`
with the native verifier, signing/flow/session keys and exact password original-
flow profile; leave `Native.Risk.Evaluation` zero for graph-owned counted risk.
Query/admission policy and revision must match this graph's authorization owner.
The current composition requires OTP's selected consuming session storage base,
but does not authenticate using OTP or accept its different original-flow action.
Startup, tenant and shutdown guards apply equally to login and recovery. No
password signin route is implicitly enabled. Native password material has one
independent migration history shared with reset; selected signin additionally
installs the native session-issuance purpose extension without rewriting either
workflow's existing history. The native integration journey authenticates an
existing session before reset and denies that same bearer afterward, then proves
replacement-password login through real selected HTTP initiation and signin.
The preexisting account/factor fixture remains explicit; this does not prove
registration or full release qualification.

Select `PasswordSignin.PreAuth` to compose the native original password-flow
issuer, using an exact retained `Native.FlowKeys` index and the signin owner's
action, policy and revision. Its public port is `features.PasswordPreAuth()`;
it does not change OTP initiation or implicitly select HTTP. Select
`HTTPPasswordSignin` separately, with the matching service actor/revision and
the shared `HTTPPreAuth.Device`/`HTTPRate` selections. POST
`/v1/session/preauth-issue` with `{"method":"password"}` to receive an original
flow and secure cookie, then POST `/v1/password/signin` with `flowID`,
`identifier`, `password` and the exact `callbackURL`, carrying the original
flow and device cookies. Optional `remember` must match initiation. Omitted
method retains OTP; an OTP original flow cannot authenticate password login.
Both profiles share original-flow rate admission and secure cookie policy.
Successful signin delivers the session cookie and `X-CSRF-Token`, never JSON
credentials. Replay cannot reveal either again. Reset and signin coexist as
one canonical password-owner contribution. Disabled password HTTP exports
neither signin nor the password method in initiation metadata. The current
reference profile still requires OTP's storage/device graph; independent
password-only composition remains an end-state obligation.

`PasswordSignup` independently selects required-email-verification registration
and its native confirmation/recovery owner. Configure immutable native field,
address, registration, password/HIBP and authorization policies, then supply the
paired issuer/preparation configuration and protected counter configuration.
Leave native evaluator, issuer/codec/counters and delivery owner/renderer absent:
the graph constructs these actual owners together. `Native.AuthorizationNamespace`
must match OTP's consuming user-policy namespace; the new account acquires its
epoch in the registration transaction. Missing or mismatched selection fails
construction rather than creating an account that cannot log in. The graph
exports `features.PasswordSignup()` and `features.RegistrationVerification()`
only after explicit selection, with initialization, tenant and shutdown guards.

`Session` independently selects primary session reads, self-signout and command
recovery through `features.Sessions()`. Supply its native authority profile,
repository, explicit clock/policy/transaction bounds and retained lookup keys.
`Native.Validation.Clock` must be absent: the graph uses `Native.Execution.Clock`
for reads and protected revocation. The explicit verified profile, selected OTP
signin and optional magic-link consumption share one kind-dispatched primary
reader and the same transactional logout selection, without fallback. Every
selected consuming issuer must match deployment, policy namespace, audience,
repository and cookie deletion tuple. Retained lookup keys must contain each
issuer's exact current version and material; historical rotation keys may remain.
Nonempty `CSRFKeys` selects strict cookie logout and must include each selected
consuming issuer's exact current CSRF key;
an empty slice disables cookie logout rather than enabling a legacy bypass.
Request-only magic-link selection grants no session authority. This composition
does not enable anonymous or organization session authority. MFA requires its
explicit consuming issuer selection. `Session.Passkey` additionally opts the
configured native passkey issuer into the same common read/logout owner,
including independently selected HTTP session routes; it defaults to false.

`MagicLink` selects native request and optional explicit consumption. Supply
versioned issuer/custody keys, address normalization, exact trusted origins and
callbacks, original browser-flow keys, delivery template/endpoint and bounded
policy configuration. Leave request risk evaluation and delivery owner/renderer
unset: the graph injects its counted risk evaluator and encrypted delivery owner.
`PreAuth` selects original flow issuance; `HTTPMagicLink` independently opts into
request/consume routes and requires the shared HTTP rate/device graph. The
named `magic-link` method on `/v1/session/preauth-issue` creates original intent.
Email delivery carries the bearer in a URL fragment; the landing page belongs
to the consumer, not this backend. Only explicit POST consumption can log in.

The current reference journey uses a publicly registered, verified account
without enrolled MFA. It proves request, encrypted delivery, scanner/foreign-
browser denial, one-use login, session read and transactional cookie logout,
including rollback/recovery. Retry cannot disclose credentials again. Resend,
supersession and optional signup/MFA continuation are still under development;
do not treat this existing-account journey as complete magic-link parity.

Native TOTP completion is being composed with protected provider custody and
the real command-owned counter adapter, not Authentication-lane admission or a
fabricated session. Submitted code/browser intent remains the journal identity;
counter preparation is separate. Provider facts enter the existing encrypted
session preparation output and retain original expiry on restore. This path is
not selected by the graph or HTTP yet: primary MFA challenge branching and a
positive public-path PostgreSQL journey remain required before enablement.

`PasswordVerification` selects native reauthentication through
`features.PasswordVerification()` and, when retained `CSRFKeys` are supplied,
`features.CookiePasswordVerification()`. It requires selected password signin
and primary sessions with matching authority, repository and current issuer
keys. Leave native risk evaluation and verifier clock absent: the graph supplies
its counted risk owner and the selected session authority clock. Configure exact
purpose/action/audience targets and native signing-key retention explicitly.
Verification issues only the native bounded proof; it does not extend sessions
or consume that proof. Historical recovery does not redeliver it.

`PasswordChange` selects the native keyed replacement and recovery ports through
`features.PasswordChange()` and, with verification's retained CSRF keys,
`features.CookiePasswordChange()`. Supply native screening/session-disposition
policy, the kernel-constructed keyed profile and protected counter configuration
in the graph's risk namespace; leave `Native.Counters` and screening clock absent.
The graph requires the native local envelope keyring and constructs the existing
protected owner, never an unkeyed fallback. Native defaults revoke all sessions;
preservation requires explicit policy. Original proof consumption, credential
replacement and session effects stay in the sole native transaction. Existing
reset and signin migrations remain unchanged; change adds native counter
preparation and session-effect/continuation suffixes. Provider screening defers
only command-owned velocity to those mandatory protected counters. These native
selections do not implicitly expose routes.

Select `HTTPPasswordVerification` and `HTTPPasswordChange` independently to
expose POST `/v1/password/verify` and `/v1/password/change`. Each uses an explicit
cookie or bearer transport, stable rate namespace and dedicated rate key.
Cookie selection requires exact HTTPS trusted origins and native CSRF custody;
bearer selection forbids origins and never borrows cookies. Verification also
requires the selected original browser-device owner. Verification returns a
bounded original proof; change accepts its `proofID`, `newPassword` and required
`Idempotency-Key`. Neither route returns password hashes or replacement session
credentials. Required graph authority and shutdown/drain guards cover primary
readers as well as the protected mutation. Revocation denies HTTP retries using
the old session; authorized native recovery can disclose the original outcome
without reauthenticating that session or redelivering credentials.

The real PostgreSQL/TLS-Valkey reference journey exercises registration,
delivered email proof, confirmation, login, reauthentication, protected change,
downstream rollback, original-session revocation and old/new-password login.
Provider network responses remain controlled fixtures; release qualification
and the remaining identity-platform workflows are outstanding.

Select `HTTPSession` separately to expose GET `/v1/session/get` and POST
`/v1/session/signout`. Configure one explicit cookie or bearer transport; cookie
mode requires exact HTTPS trusted origins, while bearer mode forbids them and
never uses ambient cookies. Supply a deployment-scoped rate namespace, bounded
emergency capacity and a synchronous bounded degradation recorder. Both routes
share one native safe-rate budget. Cookie logout sends strict JSON `{}` and the
signin-delivered `X-CSRF-Token` under the trusted Origin. Only confirmed success
clears transport; failed or ambiguous mutation does not retry automatically.
An inactive/absent session yields neutral logout. Selected session routes and
original-flow initiation form one contribution, preserving device custody and
named signup/password methods. Disabled session HTTP contributes no read/logout
routes or metadata. Native and HTTP work deny after graph closure; in-flight
native HTTP calls join cancellation and drain.

Select `PasswordSignup.PreAuth`, `HTTPPasswordSignup`, shared `HTTPPreAuth` and
`HTTPRate` to expose signup initiation. POST `/v1/session/preauth-issue` with
`{"method":"signup"}`, then `/v1/password/signup` with `flowID`, `email`,
`password` and the original exact `callbackURL`, carrying the returned cookies
and an `Idempotency-Key`. Signup returns a neutral verification acknowledgement,
not an account ID or session. The configured worker sends the encrypted native
verification delivery. Identical keyed retry retains original effects; changing
the original input conflicts. Occupied-address acknowledgement does not replace
credentials, issue another grant or reset authorization authority.

Select `HTTPRegistrationVerification` separately for
`/v1/email/verification-confirm`. Supply the delivered `token`, original exact
`callback` and a stable canonical `commandID` under the configured HTTPS Origin.
Confirmation atomically verifies the original address and consumes its proof;
it issues no session. Exact replay returns metadata, not the address again.
Failed protected attempts remain charged, while domain changes roll back; proven
abort terminally retires the grant rather than resetting it for reuse. Typed
recovery is available through the public native ports; no HTTP recovery route
is implicitly added. After confirmation, use the independently selected password
initiation/signin route described above.

Apply selected-owner migrations for registration, verification and protected
counter extensions alongside the shared kernel, password, factor, capability,
delivery and authorization histories. Existing history bytes remain unchanged.
The native integration journey creates accounts and original flows through
public HTTP and actual migrations, then proves captured delivery, confirmation,
login, denial and rollback. Historical velocity warmup remains an explicit test
fixture, not proof of fresh velocity bootstrap or full release qualification.

Use selected-owner Check/Plan/Apply for reset installation, rather than only
the legacy shared `MigrationSource()`. Independent native histories install
kernel replacement/reset effects, password material, factor authority,
capability provenance and session reset effects without changing the installed
shared prefix. HTTP completion additionally selects native atomic rate receipts.
Pending kernel prerequisites must be explicitly selected; installed compatible
prerequisites are reused. Existing accounts are not implicitly assigned empty
factor authority: unreconciled authority continues to fail closed.

## Quick start

Supply a caller-owned `go-postgres` pool and one
`VelocityStoreConfiguration`, then construct the sealed graph:

```go
func compose(pool *postgres.Pool, velocity reference.VelocityStoreConfiguration) (reference.StoreSet, error) {
    return reference.ComposeStores(
        reference.StoreConfiguration{Velocity: velocity},
        reference.ReferenceDependencies{PostgreSQL: pool},
    )
}
```

The named modules are `github.com/faustbrian/go-postgres` and
`github.com/faustbrian/go-identity/reference`. Configuration selects the schema,
unique tenant allowlist, positive primary/recovery timeouts, a lease at most one
minute, batch (1–1000; reference 100) and maximum records (1–100000). Recovery
timeout must be less than the lease. `Native` selects the deployment namespace,
stable replay secret, risk policy, complete retained digest-key history,
canonical `rediss://DNS:port` endpoint, TLS name/preferences, explicit PEM trust,
opaque copied credential, bounded native timeout/pool and `standalone` topology.
The primary receives those exact namespace/secret/policy/key values internally.

Construction performs no network IO or migration. Explicitly install the
returned `MigrationSource()` using the existing `go-migrations/v3` PostgreSQL
backend and runner before recovery. No private SQL runner or copied migration
history is provided. Kernel versions remain 1–9; reference velocity uses the
permanent allocation 1000–1011. Do not silently adopt a differently allocated
existing ledger. Prefer the explicit Check/Plan/Apply operations below for
complete selected-owner migration coordination.

Call `stores.RecoverVelocity(ctx, tenant)` explicitly. It returns no counter
store until the actual primary journal has a full hour of coverage, all original
terminal records are restored and acknowledged, and the exact native publication
is confirmed and activated by the primary. A fresh empty journal is **not**
healthy. After genuine warmup, another explicit recovery can establish the
covered cut. There is no automatic polling, health renewal or hidden retry.

Use the returned `risk.CounterStore` with `risk.NewCounterCoordinator`; the
owned store records durable intent before its single native mutation and
retains the original outcome through that exact primary receipt. Retain a known
committed result even if a later error denies positive admission. Pending or
unknown outcomes never permit redispatch.

Call `stores.Close(ctx)` to cancel and join recovery and close owned native
connections. Close the caller-owned primary pool separately, after its users
have finished. No handler, health/readiness endpoint or background worker is
created by this development slice.

Successful recovery also retains that exact counter owner for the forthcoming
feature-composition path. Its internal deferred connection rejects requests
before recovery, during a new recovery generation and after shutdown. A failed
new generation cannot fall back to the previous activation. Routing adds no
retry or renewal and preserves the native owner's original outcome declaration.
The optional OTP profile uses this connection internally; it does not accept a
caller-written risk evaluator or counter store.

## Optional OTP Send composition

### Optional HTTP rate storage

`StoreConfiguration.HTTPRate` selects one native strict PostgreSQL backend and
the HTTP owner's fixed authentication/delivery policies. Supply a namespace,
nonzero 32-byte identifier key and explicit duration bounds: each of maximum
duration, timeout, lock timeout and rollback timeout is 1ms–2s; timeout must not
exceed maximum duration, and lock/rollback must not exceed timeout. Configure
the caller pool with `search_path=public`: the native adapter owns unqualified
SQL and cannot safely share an ambiguous search path. Callbacks that change
connection search paths violate this deployment requirement.

Construction freezes configuration without database IO or schema installation.
Check/Plan/Apply includes the native version-one migration in the independent
`identity_http_rate` history; `MigrationSource()`'s existing shared prefix is
unchanged. Nil selects neither the backend nor its migration. Graph shutdown
permanently denies later admission but leaves the caller pool owned by the
caller. This prerequisite does not by itself prove HTTP readiness or a complete
browser-login journey.

### Selected server construction

After `ComposeStores`, `ComposeProviders`, `ComposeWorkers` and
`ComposeFeatures`, call `NewServer(config, dependencies, features)` with the
same caller-owned PostgreSQL pool. Construction performs no IO, callbacks,
migrations, startup or goroutine creation. Supply the exact complete upstream
`identity.PolicySet`: authorization must be the same comparable service handle
bound into the graph, and all four identity callbacks are required. No member
is replaced or defaulted. For noncomparable service implementations, supply a
pointer handle consistently to both configuration stages.

The current profile accepts only `PostgresWithValkey`, explicit transport
limits/hosts, a non-nil bounded tenant resolver, and disabled bootstrap and
startup migration application. Migration lock timeout is 1ms–5m and command
retention 1h–87600h; worker concurrency is 1–1024, lease/drain bounds 1s–1h.
Enabled provider entries are rejected until their native selection is composed,
rather than silently omitted. The required PostgreSQL-only deployment profile
and complete worker/server lifecycle remain future implementation work.

`StoreConfiguration.HTTPPreAuth` opts into `/v1/session/preauth-issue` and its
OpenAPI operation. It requires selected OTP original-flow issuance and
`HTTPRate`; nil contributes neither route nor metadata. Supply the shared
eventual-session lifetime policy; optional browser-device configuration selects
the existing non-authenticating correlation codec. Native issuer configuration
owns origin, cookie, callback, action and policy. No application handler, rate
backend or domain-store override is accepted.
Selected HTTP initiation requires the canonical five-minute `OTP.PreAuth.FlowTTL`;
other lifetimes are rejected during composition, before rate admission or native
preparation. Direct native issuance retains its existing 1–10-minute profile.

`StoreConfiguration.HTTPEmailSignin` selects `/v1/otp/send`, `/v1/otp/signin`
and `/v1/otp/signin/recover` with their native OpenAPI operations. Nil exposes
none of these routes or metadata. Selection requires `OTP.Signin`,
`HTTPPreAuth` with its dedicated browser-device profile, and `HTTPRate`.
Supply email-owned address normalization plus trusted actor, policy revision
and target. Send and signin query policies must share the same authorization
handle and revision; the native issuer owns session cookie and audience.
Network JSON limits must admit at least 44 fields, including digest array
elements in the recovery envelope, and nesting depth at least 3; smaller limits
fail construction. Use explicit bounded body and decoded sizes.
No application handlers, stores or workflow callbacks supply these operations.
Recovery returns the historical committed outcome, never another session
cookie or CSRF credential. The selected HTTPS integration exercises initiation,
Send/replay, native delivery, consuming signin and recovery against PostgreSQL
and TLS Valkey; it is not full-platform or positive-readiness evidence.

The tenant resolver runs synchronously with a bounded request context after
trusted network resolution and before a workflow. Its nonempty result must
equal the tenant bound to the exact configured host; errors, panics,
cancellation, missing tenants and conflicts deny without credentials or raw
callback errors. Resolvers must honor cancellation and be concurrency-safe.
The router freezes host policy and OpenAPI metadata at construction.

`Handler()` returns the owned standard-library handler. `OpenAPI()` exposes
detached native document snapshots. Only `GET /healthz` and `GET /readyz` are
probes; no `/v1` aliases exist. Health is process liveness, not store readiness.
Readiness denies before initialization, during recovery and after closure. Each
bounded observation checks every selected native migration owner and the current
original PostgreSQL journal/TLS Valkey custody for every configured tenant.
Missing or incompatible schema, unavailable stores and expired ownership deny.
Probes do not debit counters, repair state, renew leases or refresh evidence.
A successful probe is a momentary observation of this selected graph, not
permission to bypass credential checks or proof of full-platform readiness.
Healthy velocity recovery requires historical coverage of the maximum configured
window; a fresh journal cannot skip that warmup. Recovery remains explicit when
original ownership expires. Readiness does not run it automatically.
Initialize features and deploy migrations explicitly; graph closure prevents
later workflow admission without taking ownership of the caller pool.
This constructor is not a completed login/reference-server milestone.

### OTP and delivery selection

Select both `StoreConfiguration.OTP` and `StoreConfiguration.Delivery`, with
deployment envelope keys and a bounded sender in `ReferenceDependencies`.
The delivery profile must enable state tracking and use production policies.
Risk uses the velocity graph's exact policy and retained keys. This checkpoint
supports velocity-only admission: required unsupported signals fail composition
rather than receiving permissive stand-ins.

Compose in order with `ComposeProviders(stores)`,
`ComposeWorkers(stores, providers, workerConfigs...)`, then
`ComposeFeatures(stores, providers, workers)`. These stages perform no network
IO and start no goroutines. Every selected tenant needs a real delivery worker
for the selected OTP provider version. All handles share the store lifetime;
foreign, reused or incomplete graphs are rejected.
All workers share the strictest retained sender-concurrency ceiling before
claiming. Dedicate the sender instance to this graph; unrelated graphs or direct
callers require their own shared capacity control.

Select `OTP.Signin` with the native `otp/postgres.SigninConfig` to enable
`features.OTPSignin()`. Nil leaves the handle unavailable and contributes no
consuming migrations. Sign-in uses the existing Send owner, selected tenant
allowlist and store lifetime; it is unavailable before `features.Initialize`
and after store shutdown. No route, worker or listener is started implicitly.
The sign-in profile must use the same global authority and user policy namespace
as Send and requires its pre-auth session configuration. Its bounded policy
must authoritatively deny single-factor issuance when MFA is required; this
profile does not implement MFA continuation.

Use the public `otp.SigninService` with original Send possession and challenge
code. Successful new commitment returns the session credential and CSRF token
once. Preserve its recovery handle for `RecoverSignin`, including ambiguous
outcomes; recovery returns original history without redelivering credentials.
The native adapter owns atomic challenge/pre-auth consumption, session issuance,
audit and lifecycle effects. Consumers supply configuration and bounded policy,
not domain workflow callbacks or stores.

Selected OTP signin also exposes `features.OTPSigninSource()` for code-free
original identifier discovery through that same native owner. Supply original
Send/pre-auth possession and trusted caller; current primary policy and recipient
are checked without an attempt debit or session effect. Use the sensitive
projection only for trusted transport rate admission, never client output or
login authority. Startup, tenant and shutdown guards apply to retained readers.

Select `OTP.PreAuth` to obtain `features.PreAuth()` for original flow initiation.
Its fixed deployment origin/callback/service actor and retained cookie key
version are explicit configuration; action, policy and native namespace are
derived from the same OTP owner. Resolve the shared `session.RememberPolicy`
before `Prepare(ctx, input)`, retain the preparation's unchanged `Command`, then
call `Issue`. Only a fresh successful commitment delivers a reveal-once token
and credential-free secure cookie metadata. Recovery returns historical outcome,
never another token or renewed lifetime. The graph must be initialized; unknown
tenants and closed graphs deny. No SQL, workflow callback or HTTP route is
consumer-owned. Nil leaves initiation absent. Compose transport separately.

The integration suite composes this selected handle with the public
`http/session.NewPreAuthFeature` and `http.NewRouter` over real HTTPS. It checks
original committed PostgreSQL flow identity/timestamps, secure cookie custody,
startup/shutdown denial, and independently constructed HTTP owners sharing a
strict PostgreSQL IP budget. Its rate-schema installation and owner selector
are test fixtures, not a production reference constructor or migration
contributor. Final `NewServer` composition and the complete OTP browser login
journey remain pending.

Initiation adds the owner-produced version 1420 to the permanently named native
`identity_preauth` ledger, not the shared `MigrationSource`. Install through
the existing reference Check/Plan/Apply APIs selecting `identity/session/postgres`
after its shared prerequisites. The existing native global command/lock owner
coordinates both histories. This permits later sign-in selection without an
earlier pending gap. Module numeric versions summarize maxima; only compatible
status proves every participating history is complete. Plan step `FromVersion`
belongs to its `SourceDigest` history. Existing deployment histories are unchanged.

`StoreSet.MigrationSource()` preserves kernel 1–9 and risk 1000–1011 exactly.
Selecting OTP/delivery appends owner-produced kernel 1012–1018, OTP 1100–1103,
pre-auth session 1200–1201, distinct authenticated session 1210, delivery
1250–1254 and authorization authority 1300. Selected delivery cancellation uses
1255, receipt metadata uses 1256, authenticated receipt commands use 1257, and
reconciliation uses 1258–1260. Receipt metadata is included whenever receipt
tracking, authenticated receipts or reconciliation needs it; unselected
extensions remain absent. Consuming sign-in appends OTP 1400 and session
1411–1416, with 1410 only for a distinct sign-in session schema. Existing Send-only histories
remain unchanged. Shared session schemas reuse one base; OTP, session
and risk owners must otherwise use distinct schemas. Unselected profiles
contribute no schema. These are
new permanent reference allocations, not changes to applied history. Keep the
selected schemas, global authority and `OTP.BootstrapTenantIDs` unchanged after
apply; later tenant onboarding uses owned lifecycle APIs. Bootstrap tenants are
copied explicitly and are not inferred from velocity scopes. An empty set grants
no bootstrap tenant authority.

`stores.ReferenceMigrationCheck(ctx, ReferenceMigrationCheckRequest{Modules:
[]ModuleID{"identity/postgres", "identity/risk/postgres"}})` performs bounded
read-only discovery. It never prepares a ledger or acquires apply ownership.
Statuses contain current/required versions and compatible, required, dirty or
incompatible state. Only selected canonical IDs are accepted; caller current
versions are forbidden. Each requested owner's complete physical history is
validated. Missing records with owned objects, including empty schemas, are
unmanaged/incompatible rather than permission to baseline them.

Selected OTP/delivery also includes `identity/otp/postgres`,
`identity/session/postgres`, `identity/delivery/postgres`,
`authorization/postgres`, `audit/postgres`, `outbox/postgres` and
`outbox/postgres/identity`. The last three retain their original independent
histories in native namespaces `audit`, `outbox` and `identity_outbox`
(`public.golib_migrations_<namespace>`). Audit fresh-role preflight must share
its history's native `InstallFresh` transaction; existing role collisions are
not ownership proof or permission for adoption.

`stores.ReferenceMigrationPlan(ctx, ReferenceMigrationPlanRequest{Modules:
[]ModuleID{"identity/postgres", "identity/risk/postgres"}})` returns a detached
canonical plan without writes or apply locks. Modules contain sorted current
versions; steps retain native order and owner-local previous versions. A valid
zero-step plan has a nonzero digest; any error returns no usable plan. Pending
prerequisites must be explicitly selected, while completed prerequisites need
not be selected. In particular, the interleaved shared kernel/risk history
cannot be reordered or filtered into an invalid suffix. Lifecycle outbox
planning also discovers the root outbox prerequisite and rejects an unselected
pending root. Independent histories follow shared, audit, outbox, lifecycle
order; later unselected shared owners are not implicitly appended.

Plans bind whole participating native sources, ownership guards, audit fresh
preflight and persisted ledger metadata. V1 uses domain-separated SHA-256 with
big-endian uint64 numbers/counts, length-prefixed strings and fixed 32-byte
digests. No SQL, process identity or observation time is exposed. Returned
collections belong to the caller; mutation invalidates the digest and never
changes future results. Different ledgers are separately discovered snapshots,
not a global atomic snapshot. Apply rediscovers under ownership and
validate the complete value before writing, including no-op plans.

### Explicit operator Apply and recovery

Set `StoreConfiguration.Migrations` to a `MigrationApplyPolicy` containing
trusted deployment `TenantID`/`ActorID`, a stable nonzero 32-byte `LookupKey`,
and a positive `CleanupTimeout` at most one minute. `LockTimeout` defaults to
30 seconds, with explicit values from one second to five minutes. The velocity
profile's `PrimaryTimeout` also bounds the entire operation, including lock
acquisition; a longer lock budget cannot extend that outer deadline. Nil policy
keeps Apply disabled without affecting read-only Check/Plan. Do not expose the
operator policy or operation as an unauthenticated HTTP endpoint.

Supply the complete unchanged plan, globally unique command ID (16–128 ASCII
letters/digits/underscore/hyphen) and an owned `identity.IdempotencyKey`:

```go
result, err := stores.ReferenceMigrationApply(ctx,
    reference.ReferenceMigrationApplyRequest{
        CommandID: commandID, Plan: planned.Plan, IdempotencyKey: retryKey,
    })
```

One native advisory ownership interval and physical connection cover every
participating namespace. Before any command, ledger or schema write, Apply
checks all participating native histories, unowned-object guards and the exact
rebuilt plan, including self-consistent but truncated/reordered submissions.
Each native batch commits SQL, its original ledger rows and command attribution
together. Fresh audit preflight and its whole history share one transaction.
No migration SQL is copied or executed by a reference-owned runner.

Inspect `result.Result.State()` and the safe typed `MigrationError`; dirty,
incompatible, locked, pending and unknown are not success. Only `MigrationApplied`
proves complete current command attribution. `Receipts()` returns a detached
sorted contributor prefix; a no-op has no applied-step receipts. A later failure
does not erase earlier durable work, and a partial result is not a usable
readiness claim.

Persist the **original complete plan**, command ID and retry key in the operator
deployment workflow. Retry exactly those values to resume through a newly
constructed StoreSet. Native receipts—not matching schema or a clean external
suffix—are the sole progress authority. An ambiguous commit returns
`identity.UnknownCommitError` with that original command ID. An exact retry
reconciles authoritative native evidence under ownership before continuing;
an unavailable authority cannot prove success or rollback. Do not generate a
replacement command, infer completion from schema, advance the plan base or
delete unresolved command records. Records have no automatic expiration and
must be retained throughout the reconciliation window. Changing operator scope,
key or policy cannot rebind an old command. Retain the original policy during
recovery. Caller retry keys are never stored in plaintext.

Close cancels and drains active migration operations with finite independent
cleanup, without closing the borrowed PostgreSQL pool. Startup/readiness and
the complete ReferenceService/server facade remain unimplemented. These
operations alone do not make the reference profile deployable.

Once selected schemas exist, `features.Initialize(ctx)` registers native
metadata without warming risk or sending messages. Obtain the public Send
interface with `features.OTP()`. Calls before initialization, before valid risk
activation, for unselected tenants or after closure deny. Exact committed
receipts can replay through a reconstructed initialized graph without a fresh
counter debit; fresh requests still require activation. `workers.ProcessDeliveryOne`
performs one explicit bounded native step; callers supply scheduling, not a
replacement delivery workflow. Queue acceptance does not prove provider delivery.

Audit delivery fails closed. A lost decision gets one idempotent retry of its
original immutable event; durable audit-outage handoff remains unimplemented.
Authenticated-session parity, joint unknown-outcome recovery, complete operator
APIs and full reference acceptance remain outstanding.

## API reference

- `StoreConfiguration`: one immutable selected configuration input; copied at
  composition and never retained as caller-owned TLS/secret slices.
- `VelocityStoreConfiguration`: explicit transport, custody, scopes and
  traversal bounds. Zero does not select defaults.
- `ReferenceDependencies`: borrowed PostgreSQL and selected envelope/sender resources.
- `OTPSendConfiguration`, `DeliveryConfiguration`: explicit native workflow profiles.
- `ComposeStores`: the sole store construction entry point; validates without IO.
- `StoreSet`: sealed shared-lifetime result, not caller-constructible.
- `StoreSet.MigrationSource`: pure upstream-owned migration contributions.
- `StoreSet.ReferenceMigrationCheck`: authoritative read-only selected-owner
  compatibility, bounded by the store lifetime; no partial statuses on failure.
- `StoreSet.ReferenceMigrationPlan`: deterministic read-only plan with complete
  participating source/history binding; no usable plan on failure.
- `MigrationApplyPolicy`: explicit copied operator scope, keyed retry binding
  and finite ownership/cleanup policy. Nil disables Apply.
- `StoreSet.ReferenceMigrationApply`: exact original plan execution and native
  same-command reconciliation/resume, with immutable bounded receipts.
- `StoreSet.RecoverVelocity`: one bounded, fail-closed recovery/activation.
- `StoreSet.Close`: permanent cancellation and bounded joining; repeated calls
  are safe, and a deadline does not reopen ownership.
- `ComposeProviders`, `ComposeWorkers`, `ComposeFeatures`: one sealed selected graph.
- `FeatureSet.Initialize`, `FeatureSet.OTP`: explicit startup and public Send access.
- `WorkerSet.ProcessDeliveryOne`: one explicit native delivery step, without polling.

Formatting is redacted and JSON/text serialization is denied for composition
inputs and handles. See Go documentation for exact errors and lifetime semantics.

## Security and adoption tradeoffs

PostgreSQL is authoritative; Valkey is an ephemeral projection. Recovery never
debits a counter or creates mutation intents. It restores original values,
observations and absolute expiry, not refreshed windows. Live primary ownership,
unknown history, corruption, missing native custody, lost acknowledgements,
incomplete coverage or exhausted bounds grant no store. Later counter calls
recheck the exact original primary/native chain without resetting its expiry.
No SQL transaction spans native IO.

Tenant scopes are selected at deployment, not accepted dynamically from requests.
Only one in-flight recovery per selected tenant is permitted; different selected
tenants can proceed concurrently. The primary owns cross-process exclusion.
Local configuration and copied handles do not grant takeover authority.

This slice deliberately does not renew healthy leases or reconcile a foreign
owner's opaque live marker. Existing handles become unavailable at their
original activation expiry. Cross-process recovery, continuous workers and
additional deployment topologies remain release work. Do not treat this module
as a production-ready login service.

## FAQ

**Why doesn't an empty deployment immediately accept traffic?** It cannot prove
the previous maximum window contained no unresolved work. The authoritative
journal lifetime starts at real insertion time, never one hour in the past.

**Can I inject a journal, health checker or effect callback?** No. The concrete
owned adapters are constructed once with paired opaque authorities. Dependencies
contain deployment resources, not a consumer-written identity workflow.

**Does the historical-origin integration fixture prove fresh bootstrap?** No.
It tests joint mechanics conditioned on established coverage. Only the separate
actual one-hour lane can prove genuine fresh warmup.

## Verification and release notes

### Selected magic-link signup

Configure `MagicLink.Request.Signup` with the same identifier comparison and
retirement key history used by other creation methods, plus its matching
versioned email-possession policy. Request/delivery retains prospective signed
creation without creating a user; consumption creates account, verified email,
empty factor authority, policy authority and session atomically. Existing
verified recipients sign in normally. The selected migration catalog includes
the owner registration and factor-provenance extensions without requiring the
password signup workflow or modifying installed history prefixes. HTTP
consumption receives the actual native issuer's proof limits.

The corrected prospective supersession family is keyed by original mailbox,
browser and policy rather than newly prepared IDs. When adopting it from an
experimental deployment, drain issuing workers and retained preparations and
expire outstanding old prospective grants before enabling the new profile;
mixed-version prospective issuance/rollback is not supported. Existing-recipient
families are unchanged. Neither this profile nor selected TOTP completion implies
public MFA enrollment or complete platform release qualification.

Integration tests require isolated loopback PostgreSQL and explicit native TLS
configuration. Apply/Plan/Check do not connect to Valkey; risk/OTP runtime tests
additionally require authenticated TLS Valkey. Missing fixture inputs fail.
The actual warmup test requires
`IDENTITY_REFERENCE_REAL_WARMUP=1` and a timeout exceeding one hour. No tests
contact existing application services. Exact coverage, mutation, interoperability,
clean-consumer and complete reference acceptance gates remain release requirements.
See [CHANGELOG.md](CHANGELOG.md).

## Selected factor management composition

For email-OTP factors, independently select
`MFAOTPEnrollmentConfiguration.ActiveStepUp`, with a consuming `PurposeStepUp`
policy and native origins/signing configuration. Leave its native `Primary` and
`Issuance` absent: the graph supplies actual current-session and OTP/delivery
owners. Password/OTP login must also be selected. The native
`FeatureSet.MFAOTPActiveStepUp` handle accepts action-bound `OtpSend`/`OtpVerify`;
the verification input names the original send and returns one factor-update
proof, not a session. Delivery uses the existing selected worker/sender.

Set optional `ActiveStepUp.FactorManagement` with explicit proof/primary maximum
ages, leaving owner overrides and replacement selections absent.
`FeatureSet.MFAOTPFactorManagement` then supports optimistic rename with atomic
proof consumption and session revocation. Select `MFAOTPEnrollment.Listing` to
read safe labels after a fresh password/OTP signin. Selected migrations append
OTP proof/management and existing session-disposition histories; apply them
before initialization. No new HTTP routes are enabled. Native acceptance lives
in `TestReferencePostgresOTPAuthenticatedFactorRename` and
`TestReferencePostgresOTPFactorRenameCommitRecovery`; these do not qualify the
full MFA unit or remaining management variants.

For sole-active email-OTP removal, additionally set
`ActiveStepUp.FactorManagement.RemovalRecoveryPath` to
`authentication.RecoveryPathEmail` and select the full native `PasswordReset`
request/completion workflow. Leave `RemovalRecovery` absent: composition supplies
that actual owner and rejects incomplete selection. Apply the appended OTP
removal history before serving. An original fresh OTP action proof authorizes
`FactorUpdate(Remove)` with an empty name and current version. Recipient-reference
erasure, recovery-set retirement, proof consumption, factor generation, session
revocation and events commit atomically. Native removal, competing commands and
original COMMIT recovery are exercised by `TestReferencePostgresOTPFactorRemoval*`;
the removed-factor session cannot continue, and delivered email reset remains
usable. This selects no HTTP route, disable, replacement or weaker-factor
fallback.

For native OTP disable, select `ActiveStepUp.Disable` with positive proof/primary
maximum ages and `RecoveryPath: authentication.RecoveryPathEmail`. Leave its
`Primary`, `Sessions` and `Recovery` absent. Select complete `PasswordReset`
and include `identity.mfa.disable` in `ActiveStepUp.Native.AllowedPurposes`.
The graph supplies actual session/CSRF, OTP/delivery, recovery and effect owners.
Use `FeatureSet.MFAOTPActiveStepUp()` to send and verify a fresh challenge with
`StepUp.Purpose: "identity.mfa.disable"`, then pass that proof to the owner
returned by `FeatureSet.MFAOTPDisable()`. `OneFactor` requires the factor ID and
preserves unconfirmed OTP siblings; `AllFactors` requires an empty factor ID
and erases those siblings too. Both require the sole active OTP factor and
current usable email recovery. Apply the appended OTP disable and shared
session-disable histories before use. Original retries/recovery expose outcome
metadata only; they never redeliver proof or repeat erasure. Factor management
and HTTP are independent selections. Native one/all, competing commands and
actual COMMIT recovery are exercised by `TestReferencePostgresOTPDisable*`.
All-target has the native bound of 63 retained pending siblings, including
expired pending rows. Overflow rolls back the complete operation without
partial erasure; one-target preserves untargeted pending history.

Set `MFAEnrollmentConfiguration.ActiveStepUp`, then optional
`FactorManagement` with explicit primary/factor maximum ages. The graph supplies
the actual native primary and session-effect owners; caller-written overrides
are rejected. `FeatureSet.MFAFactorManagement` enables native rename without
requiring any management, step-up, regeneration or session HTTP route.

For transport, separately set `HTTPMFAFactorUpdate` with trusted origins and
the shared keyed rate namespace/key. Set `HTTPMFAActiveStepUp.Purposes` to include
`identity.mfa.factor-update` if HTTP should produce the proof. Selected origins
must be a subset of native step-up origins. Unselected routes and metadata are
absent; incomplete selected dependencies fail composition. Graph drain/close
guards apply to native and HTTP calls. Real-adapter journeys exercise fresh
TOTP proof, optimistic rename, rollback, session invalidation and original
outcome recovery; this is not complete MFA or platform release qualification.

For the single-active-TOTP removal profile, additionally select
`FactorManagement.RemovalRecoveryPath = authentication.RecoveryPathEmail` and
the real `PasswordResetConfiguration` request/completion owner with required
HIBP and delivery dependencies. Leave `RemovalRecovery` absent: the graph
supplies that native owner, rejecting caller substitutions. Selected migrations
append optional MFA v10 after v9; rename-only histories stay unchanged. Removal
erases factor material, retires its recovery-code sets and revokes all subject
sessions only while verified email and unambiguous usable password authority
remain current. Native removal does not select HTTP reset or management routes.
Select `HTTPMFAFactorUpdate.Actions` explicitly for removal and independently
select `HTTPPasswordReset` when HTTP recovery is wanted. Real native and HTTP
journeys prove removal → emailed reset → completion → new-password login without
resurrecting factors or reusing the revoked session. Other recovery paths and
general multi-factor management remain unfinished; explicit disable is described
above.

For same-profile pending TOTP replacement, additionally set
`FactorManagement.Replacement = &mfapostgres.TOTPReplacementConfig{RecoveryCodes: 10}`.
The graph supplies authentic URI/confirmation parent custody, current-session
authority and the session-owned atomic revocation effect; caller substitutions
are rejected. Selected migration history appends MFA v12 and disposition v4.
Native-only selection exposes no management HTTP route. Separately include
`mfa.Replace` in `HTTPMFAFactorUpdate.Actions` and select provisioning/confirmation
HTTP when desired; the graph freezes the transport code count from native policy.

Use the original session and CSRF for pending URI reveal and confirmation.
The predecessor and its recovery codes remain usable while the successor's codes
are non-authenticating. A later real authority read does not extend original
proof, primary or ceremony expiry. After confirmation, all prior subject sessions
are revoked; the new TOTP/recovery set supports ordinary password-first signin.
General multi-factor, other-method, trusted-device and administrative replacement
remain unfinished. Local slice behavior is not whole-unit release qualification.

## Independently selected verified-phone replacement

`StoreConfiguration.PhoneChange` selects the actual native replacement owner.
Supply its number policy, distinct send/update `ActionPrimaryConfig` audiences,
`PhoneChangeConfig` and `PhoneIssuanceConfiguration`; leave injected issuer,
risk evaluator/keys and notice delivery/templates zero. For cookie primaries,
leave their CSRF keys zero for injection from `PasswordVerification`. Select
real password verification, session, OTP, delivery and independent email/password
signin/reset owners. Register both action targets in password verification and
the selected SMS provider worker. No application-owned domain stores are needed.

`HTTPPhoneChange` independently selects cookie send/update/original recovery,
with trusted Origin, the existing signed browser-device profile and policy
revision. It requires shared durable HTTP rate storage. Do not also select
`HTTPPhoneVerification`: those profiles intentionally share one canonical send
path and conflicting selection denies. Native enrollment, removal and phone
login selections remain independent. Disabled HTTP contributes no route or
OpenAPI metadata.

Apply the selected reference migration plan before initialization/serving.
Replacement appends native kernel version1901 and password version26 after
their required removal predecessors, retaining all installed checksums and
operator history. Installing those predecessors does not enable removal routes.

Consumer journey: sign in through retained email/password, read the session ID,
obtain an action-bound send proof, submit exact old identifier versions and the
new number, capture the provider's SMS, obtain a distinct `identity.phone.update`
proof, and submit that proof with the original SMS command/code and a new retry
key. A committed response queues old-number notification and cascade cleanup;
it does not issue a replacement session or claim downstream cleanup finished.
Old identifier-bound sessions and the retired phone deny; new-phone and retained
email signin remain usable. Retry with the original key or use code-free
recovery; never interpret unknown as rollback.

The executable `TestReferencePostgresPhoneChangeHTTPS` consumer in
`phone_change_integration_test.go` supplies complete configuration and exercises
public composition with genuine PostgreSQL, populated migration/reconstruction,
HTTPS and captured sender IO. From this module, run:

```sh
go test -race -tags=integration \
  -run '^TestReferencePostgresPhoneChangeHTTPS$' .
```

Use a task-owned PostgreSQL database at `IDENTITY_REFERENCE_POSTGRES_PORT` (loopback,
user `postgres`, database `identity_test`, disposable trust authentication).
The test creates and removes its own database. Never point it at existing data.
Complete phone/reset/MFA variants and full release qualification remain pending.
