# OTP PostgreSQL

## Optional email-confirmation hooks

Set `EmailVerificationConfig.VerificationHooks` or independently
`EmailChangeConfig.VerificationHooks` to an immutable `email.VerificationHooks`.
Nil preserves existing behavior. Select bounded cooperative callbacks; retain
original versioned send policy/configuration for dependent command history.
Before runs outside SQL before durable wrong-code metering or reservation;
rejection/error leaves the code and protected identity untouched. Final current
session, factor, directory and expiry checks remain mandatory. After runs only
after a fresh known commit and before address projection. Observer error
preserves committed outcome and code-free recovery without disclosing the
address. Wrong codes, rollback, unknown acknowledgement and historical recovery
never run success observers. These callbacks do not provide durable external
delivery; use the existing coordinated outbox for that purpose. Change hooks
also cover explicitly selected first-primary establishment, with the same
atomic notification and session effects. Configuring link hooks selects none
of these OTP callbacks implicitly.

## Authenticated primary-email change

`NewEmailChangeService` independently selects a purpose-bound new-address code
for an actual committed password-native change request. `EmailChangeConfig.Source`
is that original native `EmailManagementService`, including its required
old-address notice owner/policy. `Send` selects email-change purpose, actual
password-session admission and independent request keys; `Domain` and
`CurrentAttemptKeyVersion` retain the comparison and attempt owners. Use reference
composition for selected migrations and startup custody.

Call `EmailChangeRequest` with original change command/candidate, actual current
session possession and a stable issuance key. The original request already owns
fresh-password admission; sending a code neither repeats that proof nor renews
its validity. `EmailChangeConfirm` consumes the independently delivered code and
atomically promotes one new primary, demotes the original primary, stages the
original-old-address notice and advances session authority with audit/lifecycle.
`RecoverEmailChange` uses original code-free correlation and current disclosure
permission; it never compares, debits, returns an address or repeats effects.
Link and OTP may contend, but only one replacement can commit. Generic added
pending addresses, stronger factors and automatic signin are not this profile.
Native selection alone enables no HTTP route.

First-primary establishment is separately selected with
`EmailChangeConfig.AllowInitialPrimary = true`. The source must implement
`EmailInitialPrimaryChangeSource` and the committed original change must select
`email.PrimaryOrSoleVerifiedAddress`. Before comparing any code, the protected
transaction checks that there is still no primary and exactly one verified old
mailbox. Success preserves that mailbox's identifier and verification versions,
promotes only the candidate and commits the same notice/session effects. Zero
configuration retains replacement-only behavior. Disabling initial execution
does not erase original metadata-only recovery.

A later signin supplies additional current session possession, not replacement
authority for the initiating session. Its exact original session/family remains
locked and active through issuance and consuming commit, and original idle and
absolute expiry cap the challenge without renewing activity or password proof.
Revocation or expiry denies new issuance/comparison/debit/replacement; original
authorized recovery remains code-free historical observation.

## Authenticated pending-email verification

`NewEmailVerificationService` selects the self-user, password-session,
known-empty-MFA, pending-nonprimary profile independently of OTP signin or email
links. Supply `EmailVerificationConfig.Send` with email-verification purpose,
actual session admission, original token keys, risk/delivery/template/codec and
request-key owners, plus the existing email comparison domain and an explicit
`CurrentAttemptKeyVersion` retained by the codec. Constructors perform no IO.
Install selected kernel/session/MFA-authority/OTP consuming/delivery/audit/outbox
migrations, then call `Initialize`; use reference composition to own this wiring.
Missing factor authority is not initialized or treated as known-empty.

Call `SendEmailVerification` with the pending address ID/version and original
session possession. Preserve the same key and input on issuance retry. First
preparation freezes the recipient and factor generation; a matching committed
retry restores the original receipt without re-reading a now-verified address.
Accepted issuance is not message delivery or verified ownership.

Submit the captured opaque code with `EmailVerify`. Current session, target and
factor fences precede comparison; counted wrong codes and successful consumption
use the existing OTP transaction. The exact pending verification, protected audit
selector `email_verification_otp`, lifecycle and identifier-authority increment
commit together. Original sessions fail their old authority after success. The
profile grants no primary swap, login, auto-signin, phone or MFA fallback.

Retain original recovery metadata on ambiguous outcomes and use
`RecoverEmailVerify`. Validated terminal noncommit is a successful metadata
observation even when the original command aborted; current authorization,
cancellation and unavailable/unresolved history still deny or remain unknown.
No historical response returns an address or retries the mutation. Transport
source methods authenticate original token possession and preserve original
budget bindings, but are not current-session validation or reusable clearance.

## Native MFA login issuance

`PrepareLoginSend` freezes the existing native code/bearer-free input with this
issuer's complete configuration identity. Keep it only inside the original
native request-key encrypted preparation. `ReadLoginSend`, `GenerateLoginSend`
and `RestoreLoginSend` restore that same input/generation after restart; they
never select a new recipient, renew original time or run another sender.
`RecoverLoginSend` lends only the existing issuance tombstone vote, never proof
or delivery. Current primary/child/browser/factor/risk admission is still the
registered MFA owner's responsibility; these APIs alone are not public login.

`NewMFALoginIssuer` selects a disjoint consumed-primary profile with actual
pre-auth cookie keys, MFA-only consuming policy, native encrypted delivery and
templates. It requires no authenticated-session admission. The MFA service must
authenticate the signed child, original browser/password primary, confirmed
factor, verified recipient and current policy/risk, then retain code-free input
in its existing keyed preparation before invoking generation. `Restore` preserves
original output; `PreparedMFALoginSend.Persist` uses only the registered MFA
owner's Work. It never reopens the primary or consumes the child. Profile identity
includes complete retained key, policy, store and template configuration.

This issuer is not the public login send/completion service. The reference module
supplies the selected native password-origin email-OTP sender and completion,
with separately opt-in HTTP routes. Other profiles and full qualification remain
pending. Do not substitute ordinary OTP signin or application-written
verification/delivery glue; see `../../reference/README.md` for the native path.

## Native MFA pending-enrollment issuance

`NewMFAEnrollmentIssuer` implements MFA PostgreSQL's narrow
`OTPEnrollmentIssuanceOwner`. Provide the actual attempt codec/store, authenticated
session profile, encrypted delivery contributor, consuming-only MFA purpose
policy and email/SMS templates. `Initialize(ctx, pool)` registers the same stable
lockout binding and retained digest-key metadata as ordinary Send; it does not
install schemas or start a business transaction.

Compose it through `mfa/postgres.NewOTPEnrollmentSendService`, not by calling
ordinary `SendService` from another command. MFA owns original parent/session/
synchronizer, pending factor/recipient and protected risk admission; OTP owns
generation, comparison material and shared abuse state. Both use the existing
coordinator Work. MFA is a consumer-owned port, preserving the acyclic graph
`otp/postgres -> session/postgres -> mfa/postgres`.

Generated output retains one challenge and its matching encrypted delivery.
Restoration cannot regenerate, change parent/configuration/generation or acquire
live permission. `Persist` requires the actual registered MFA owner/root in its
borrowed Work; standalone calls deny. Applications configure native owners and
bounded sender callbacks, not missing OTP workflow stores. This issuer does not
confirm enrollment, authenticate a login child or issue a session.

The same issuer also implements MFA's `OTPEnrollmentConfirmationOwner`.
`RestoreEnrollmentConfirmation` authenticates the exact original send root,
input, generation, bearer and encrypted output without generation or comparison.
The opaque result exposes the real consuming contributor. `Prepare` reads only
the exact challenge version and maps a server-generated attempt onto the already
frozen MFA confirmation root after acknowledged original preparation.
`RestorePrepared` conserves authenticated code-free metadata, verifies original
static intent and submitted code/bearer binding, and does not remap or renew it.
Install `ConsumingMigrationSource` before selecting MFA's public confirmation
service. MFA retains original preparation and owns current parent/factor/CSRF/
risk admission and activation; OTP still owns every comparison, budget,
reservation, finalization and consuming-recovery effect. This port is not an
application callback clearance or an independent factor/session issuer.

## Secondary MFA attempt custody under development

The bounded v6 attempt record preserves OTP's explicit MFA-continuation arm:
original tokenless pre-auth snapshot, primary command, child identity/scope and
subject, with unchanged remember policy. The existing server-issued attempt MAC
authenticates this code-free record before use. Original v1/v2/v4/v5 record bytes
remain unchanged; no second journal or continuation store is introduced.

Serialization is not native admission. The current generic pre-auth/session
profiles do not accept this arm as pending or authenticated authority. MFA must
authenticate its child/enrolled method/current policy/shared budget, session must
authenticate consumed-primary provenance, and the sole coordinator must commit
OTP/capability/MFA/session effects together. The selected native MFA/reference
owners and opt-in HTTP handlers implement that password-origin email-OTP path.
The real PostgreSQL reference acceptance covers its delivery and completion;
other profiles and full qualification remain pending. Do not bypass those
checks or reconstruct a pending flow from this projection.

## Original sign-in source for rate admission

The selected `SigninService` also implements
`otp.SigninSourceService.ResolveSigninSource`. Supply original Send command,
same pre-auth possession and trusted caller with no submitted code or replacement
identifier. It authenticates retained encrypted custody and current flow,
directory, proposed single-factor policy and original recipient before returning
the exact original canonical destination for trusted transport rate composition.
Never expose that sensitive projection as an HTTP discovery endpoint.

Discovery compares no code, creates no command/session and debits no attempts.
Its result is not clearance: the later Signin independently enforces current
authority and atomic consumption. Caller/sender deadlines bound all reads;
suppressed, replaced, inactive and foreign selections deny. Existing Send/Signin
APIs, stores and migrations are unchanged. HTTP integration remains pending.

## Public consuming Signin

Opt into `NewSigninService(sender, SigninConfig{...})` over an initialized
native Send service configured for `otp.PurposeSignin` and pre-auth transactions.
Existing Send-only and Check composition is unchanged. The service borrows the
sender's primary pool, keys and deployment configuration; it starts no goroutine,
installs no route and performs no automatic migration.

Supply the coordinator's bounded current `QueryPolicy` and `AdmissionPolicy`
(the latter defaults to QueryPolicy), a retained `CurrentAttemptKeyVersion`,
session PostgreSQL `Session` configuration, `Profile` with the sender's exact
global authority and authorization namespace plus the selected audience, and
session-owned `Issuer` configuration and a dedicated `CSRFKey`. Install consuming
OTP, session revocation/issuance, pre-auth release, CSRF, OTP-record and OTP-issuance
migrations after their respective bases. Permanently allocate composition-wide
migration versions; do not rewrite already installed history.

Pass `otp.SigninRequest` with the original public Send command ID, same explicit
pre-auth flow/bearer, trusted tenant/user/caller and actual submitted code.
The service restores original issuance and recipient custody. It chooses the
attempt/command/session/family IDs and current challenge version itself. The
caller cannot replace the identifier, recipient, remember policy or expiry.
Anonymous command scope remains anonymous; the actual selected user's authority
is checked independently and does not replace the initiating actor.

The existing authorization engine evaluates that actual user with service-owned
`identity.authentication.method=otp`, `profile=single-factor`, `phase=proposed`
and `factor-count=1` attributes. Reserved authentication attributes from caller
subject/environment/request maps are removed. **The admission policy must
authoritatively deny this proposed profile when additional factors are required.**
This is a single-factor composition, not MFA continuation issuance; the required
MFA continuation profile remains separate implementation work. Permissive policy
does not discover or satisfy a user's factor requirements automatically.

Correct sign-in consumes OTP and pre-auth atomically with session/family/CSRF,
current authority, audit, lifecycle and receipt through the sole native kernel
coordinator. Wrong-code denial charges exactly once with its retained result.
The original browser/persistent remember policy and earliest challenge/pre-auth
validity deadline remain unchanged. Authority changes and expiry during policy
IO cannot be adopted as fresh authorization. Competing correct submissions
produce at most one credential-bearing winner; provisional SQL failures roll
back protected effects.

Only a newly committed successful result carries reveal-once bearer and CSRF
custody. `Issuance.Cookie.Value` is empty: trusted transport explicitly reveals
the bearer and applies the session owner's cookie metadata. Error, replay,
unknown and recovery paths never deliver credentials. `SessionID` describes the
original committed identity, not current authentication or session validity.

Retain `result.Recovery` after submission, especially Unknown/InProgress, and
call `RecoverSignin` with original pre-auth possession and fresh trusted caller,
**without the code**. Do not resubmit Signin to retry an unresolved attempt.
Recovery matches the original consuming correlation through the same journal,
uses current QueryPolicy independently of login admission, and never compares,
charges, generates or delivers credentials. Consumed/expired pre-auth and erased
live session payloads do not erase authorized historical outcomes. Retained
session identity remains available without fabricating a partial session object.
Preserve original wrapping, digest, attempt, request-namespace and deployment
configuration throughout retained history.

Real PostgreSQL tests exercise user/anonymous and browser/persistent flows,
actual delivered codes and reconstructed session validation, concurrent winners,
MFA denial, wrong-code metering/recovery, rollback, authority/expiry interleaving,
hostile history correlation and lost commit acknowledgments. Provider delivery,
durable risk counters, MFA continuation, HTTP/reference composition and complete
package release gates remain pending; these tests do not certify them.

## Public non-consuming Check

After constructing and initializing the native Send service, opt into
`NewCheckService(sender, CheckConfig{Coordinator: ..., CurrentAttemptKeyVersion: ...})`.
Select a retained attempt key from the sender's codec. The coordinator must
enable a bounded current `QueryPolicy`; this authorizes original Send custody
and historical Check disclosure. `AdmissionPolicy` separately authorizes new
Check submissions; when omitted it uses the supplied query policy. Allowing
the Send read alone does not authorize Check. Preserve original fingerprint,
wrapping, digest, request-namespace and deployment configuration across restart.
Construction performs no IO and installs no route, store or migration.

Pass the original `SendResult.CommandID`, actual submitted code, same explicit
session/pre-auth flow and fresh trusted caller through `otp.CheckRequest`.
The service restores authenticated original issuance; suppression never becomes
a challenge. It selects the current challenge version itself and allocates the
new unpredictable command/attempt. Concurrent stale-version submissions fail
closed rather than comparing against adopted state; callers must not use a new
submission to recover an unresolved original one.

Correct and wrong admitted comparisons consume both Check and total attempt
budgets. A Check-only cap does not consume remaining total allowance. Check
never reserves/consumes OTP or pre-auth, finalizes a workflow, changes a session,
or produces a proof. Its retained audit and result share the kernel transaction.
The existing Send-only `otp.Service` and native Send registry remain unchanged.

On Unknown/InProgress retain `result.Recovery` and call `RecoverCheck` with the
original bearer and current caller, **without a code**. The exact original plan
is checked against retained history. Recovery checks current directory, user,
identifier, credential and authorization epochs, actual primary flow state and
original time bounds, before and after lookup. It does not recompare, charge,
renew validity or take over. Challenge revocation does not rewrite a historical
Check result; that result still grants no current authority. Revoked/expired
flows, blocked users, stale epochs, missing keys and denied current policy deny
disclosure. All work is uncached, bounded by the sender timeout and caller deadline.

HTTP exposure, remaining consuming workflow profiles, Check-specific ambiguous
acknowledgment qualification and package release gates remain pending obligations.

## Public Send

Construct `NewSendService(primaryPool, SendConfig, envelopeService)` once. It
owns the native registry, coordinator, directory/session/authorization readers,
mandatory audit/lifecycle participants and encrypted delivery contributor.
Construction is pure and starts no goroutine; the borrowed owners remain yours.
Supply deployment/key/policy configuration, versioned templates and an existing
counted/audited `risk.Evaluator`, not workflow stores or private participants.
The evaluator's source/counter/audit dependencies must honor bounded contexts
and support concurrency. A source-only or unaudited evaluator is rejected.

Install the kernel base, status, credential and directory authority migrations;
request-key plus retained-input preparation; generation preparation plus
admission preparation; all audit and root/identity-outbox migrations; OTP
challenge, lockout, send-family and issuance migrations; delivery migration;
and the selected session/pre-auth migrations. Use their public migration sources
and deployment-owned version/tenant settings. Construction never migrates or
registers schema. Then call `service.Initialize(ctx)` to bind the stable lockout
key and register retained digest versions. Retry identical startup after unknown
registration; changing installed key bytes fails closed. Preserve custody and
configuration throughout retained command history.

`SendConfig.Store.Codec` must be nil: `Codec` builds copied owned custody. Select
pre-auth through `Store.PreAuth` and its dedicated retained cookie keys, session
through `Session`, or both. `Policy`, template ID/version, source templates and
locale chain fix one purpose's generation policy. Recipient eligibility and
canonical identifier abuse digests come from the native owner. Direct caller
tenant/actor context and network/device provenance are trusted inputs; never
derive them from unverified body fields or forwarding headers.

Call `Send(ctx, otp.SendRequest{...})` with one explicit submitted bearer flow
and an opaque client idempotency key. The kernel allocates the sole original
command. Matching retries restore original inputs and terminal outcomes without
recounting or generating another OTP. Changed input conflicts. Suppression is
challenge-free and durable; it cannot later become issuance. Both branches
atomically charge the same native destination/purpose send-family cooldown and
maximum-send policy, so fresh-key retry results cannot reveal recipient existence.
Public command audits use `identity.otp.request` and standard retention; unknown
recipients retain the original opaque pre-auth subject. Older private contributor
audit profiles remain unchanged. All accepted requests
expose the same bounded result shape, without challenge or recipient metadata.
Unknown/in-progress results authorize no redispatch or replacement generation:
retry the exact original request through this same public method. Accepted never
means delivered, authenticated, pre-auth consumed or session created.

Public PostgreSQL tests cover both bearer variants, issuance/suppression, actual
audit/lifecycle/encrypted delivery and reconstructed-owner terminal replay.
Their counter/source seams are explicit doubles. Durable counter/Valkey, provider
interoperability, nonterminal crash/acknowledgement cases, public login/reference
composition and complete package release gates remain pending.

Private opt-in Send composition now consumes the original initiating request's
network, device and keyed identifier dimensions through counted, audited
Authentication evaluation before generation. Only a genuine Allow can create
invocation-local admission. The existing kernel preparation journal retains
signed original risk facts inside encrypted output, not a second risk journal.
Remapping reuses the original initiation ciphertext and its authenticated
provenance, preserving the canonical command across separately constructed owners.
Restoration performs no provider, counter or decision-audit work and cannot
renew original validity. The kernel rechecks the same admission after SQL waits
and immediately before committing the atomic domain effects. Suppressed input
cannot become ordinary issuance. Legacy contributor interface behavior and
retained profiles remain unchanged. This opt-in owner requires the kernel's
`AdmissionPreparationMigrationSource` after `PreparationMigrationSource`.
The public Send service owns this private seam; complete durable risk/provider
and consuming-login composition remain unfinished. Applications must use the
public service rather than assemble these private phases.

Private native request-key preparation now composes primary kernel, session and
authorization readers. A closed initiating request binds explicit user/flow,
purpose, channel, canonical destination, workflow target, network/device input,
dedicated keyed bearer commitment and immutable configuration. It retains the
original full flow, authority epochs, recipient/suppression decision and
database-owned issue/expiry times in the kernel's existing request-key mapping.
Matching restart skips preparation reads, competing candidates return the same
persisted winner, and a later recipient cannot replace original suppression.
Install `RequestKeyPreparationMigrationSource` after `RequestKeyMigrationSource`
and register the exact native owner pointer. Preparation performs no risk
assessment, OTP generation, counter charge, reservation, delivery or journal
execution. It cannot prove bearer possession or current permission.

The private Send initiation envelope authenticates the kernel's complete
`RequestKeyPreparationBinding` and immutable native configuration. It retains
the original flow, recipient or suppression branch, authority, times and
authentication-lane identifier/network/device dimensions. Its attempt identity
is the original server-issued command ID. Restoration requires separate bearer
possession and never renews authority, freshness or expiry. Suppressed originals
cannot become ordinary issuance commands. The codec is distinct from native
primary preparation and grants no current risk admission or public Send service.
The public Send service above owns this private initiation seam. Consuming
login workflows remain implementation work. Existing custody profiles are unchanged.

Native Send can retain an identity-owned recipient snapshot separately from
the original authenticated subject or anonymous flow. Its new request profile
and authenticated issuance wrapper preserve the original identifier,
verification, security versions and observation time through restart. Primary
recipient locks and comparisons run before generation and again in the sole
issuance transaction. The legacy no-recipient profiles remain readable;
anonymous discovery never grants a user subject to the command. Public Send
composes this with owned recipient resolution and Authentication-lane risk
admission through the public Send service above.

The private pre-generation Send input now preserves the original complete
session/pre-auth continuation, attempt policy, primary expectations and initial
times without a fabricated challenge or digest. Mapping is deterministic and
checks separately supplied original bearer possession. Its bounded closed
request frame is distinct from generated issuance and submitted-attempt frames;
existing retained issuance bytes are unchanged. This is an invocation-memory
input, not an authority proof or a public Send endpoint.

Private native composition now enables prepared Send on one immutable registered
OTP contributor, preserving its existing check/consume behavior. The existing
coordinator admits original primary authority before its durable generation
marker; the owned core generates one code for the digest and versioned template,
then the adapter retains authenticated encrypted challenge/delivery custody.
Restoration conserves original request, configuration, bearer variant, times and
output generation. It rejects changed same-version template contents as well as
changed bindings. Final execution restores invocation-local delivery through the
stable owner's Work identity and atomically stages challenge, send count,
replacement, encrypted delivery, audit and lifecycle. Failed effects roll back
together; terminal replay does not generate again. Install the kernel's optional
`PreparationMigrationSource` and every retained digest-key metadata version.

These phases remain private platform composition, not caller-supplied
recipient/risk clearance seams. The public Send service above owns their
identifier/IP/device risk admission and enumeration-safe suppression. Do not
activate private phases from application request handlers. Full release and
consuming-login composition gates remain pending.

## Native issuance command custody

`AttemptCodec.MapIssuancePreAuth` and `MapIssuanceSession` bind an initial
digest-only `otp.Challenge`, original server command and `AttemptAuthority`
expectations into a separate versioned encrypted issuance profile. The complete
original session/pre-auth record, purpose, destination, workflow target, policy,
remember choice and initial times survive restart. No submitted code is invented;
code and cookie/token bytes have no field in the closed frame. The submitted
bearer remains separately held by the root command. Keep this custody private.

The native send descriptor is owner `identity/otp`, operation `identity.otp.send`,
version 1 and required record target equal to the new challenge ID. Its schema
is `identity-otp-send` for a user target or `identity-otp-send-preauth` for an
explicit anonymous-flow target. Both use code-free command construction. The
anonymous namespace must equal the original pre-auth transaction ID. These
descriptors are enabled only by the private prepared-Send composition; ordinary
contributor constructors continue to expose only the existing check schemas.

Map once per logical server request and retain the original immutable command
through retries or ambiguity. Re-encryption changes command intent. Retain exact
named wrapping/code/session keys until dependent history retires; key rotation
never substitutes a newer key or changes an earlier policy/time. Invalid input
returns a zero command and redacted error, preserving caller cancellation.
The encrypted issuance frame retains its original keyed scope commitment;
changing code-key bytes under the same version is rejected, not silently
reinterpreted. The root dependency is pinned to the committed code-free bearer
constructor baseline. Publication and standalone release evidence remain pending.

The adapter's private possession check compares the separately submitted bearer
against the exact original commitment under the retained named session key. It
does not adopt a current row or authenticate from a supplied digest. Wrong,
absent or cross-variant bearers deny. This proves possession only: current
primary authority, flow state, operation permission, risk and after-lock time
checks must still precede issuance in the owning transaction. Mapping and local
custody restoration do not generate codes, persist a challenge, consume a flow
or enqueue delivery. Native Send/delivery composition remains under development.

## Native issuance storage

Install `IssuanceMigrationSource` after `SendFamilyMigrationSource`, using the
same dedicated schema and a separately allocated forward migration version.
It preserves populated challenge custody and adds an immutable keyed family
binding plus bounded active-family lookup indexes. Older unbound issuance
writes fail closed after installation; existing consumption and recovery
remain compatible. Do not activate the new writer before installing both
extensions across its selected database.

The private writer commits a proposed send-history append, replace-policy
revocation and a new digest-only challenge in its caller's original transaction.
Retain-policy predecessors keep their original times, versions and counters.
Reserved predecessors cannot be replaced; unknown reservations require their
existing owning-command recovery. A duplicate command/challenge or failed
insert requires rollback of the whole proposal, preserving predecessors and
allowances. Stored issuance fingerprints come from the sole kernel claim,
not caller-selected bytes. Replacement is represented by terminal `revoked`.

Legacy populated challenges have no reversible destination/family identity.
Migration does not guess or attach one. A live unbound challenge blocks new
issuance for its subject/purpose until its existing owner terminalizes it.
Already terminal legacy custody remains unchanged. New family bindings cannot
be detached or rewritten, including during an otherwise valid attempt update.
Expired unreserved challenges, including legacy rows, retain their tombstones
without occupying the live predecessor bound. Unresolved reserved challenges
remain exclusions even after expiry. Separate bounded indexed live/reserved
candidate lanes prevent old retained history from becoming a lifetime quota.

This is native storage, not a public Send endpoint or a complete workflow.
The owning adapter must still enforce original-flow/current authority and
risk, generate/render once, stage encrypted delivery and commit audit/journal
through the existing coordinator. No application-written store, separate
transaction or guessed unknown outcome is supported.

The private native execution phase now admits the original user or anonymous
flow, locks shared abuse and send-family state, and stages the frozen challenge
and encrypted delivery in the same kernel Work. User security epochs, optional
credential authority, directory and authorization authority remain original;
expiry is rechecked after lock waits. Delivery or audit failure rolls back
challenge, send allowance, replacement and protected effects together. Retained
challenge tombstones prevent a negative recovery vote; recovery never generates
a replacement code or guesses that missing delivery payload means rollback.

This phase is deliberately not a public constructor or usable Send workflow.
Owned risk admission, recipient resolution, same-code generation/rendering,
cleanup and complete login remain in progress. Consumers must not supply their
own orchestration to bypass those pending platform responsibilities.

## Original authenticated-session custody

The opt-in private v4 attempt frame retains the complete session-owned original
record inside the existing encrypted envelope. Session/family IDs and versions,
all authority dimensions and optional-presence flags, lookup digest, resolved
remember policy and original authentication timeline survive a fresh codec
instance. The existing authority-envelope v3 may wrap this frame; legacy v1
and pre-auth v2 bytes are unchanged. Parsing rejects unknown/mixed profiles,
truncation, trailing bytes, noncanonical times and invalid owner projections.
No raw session token or OTP code enters this record; mapping/restoration grants
no current validity or authenticated-session admission.

Structural custody alone is not a current lookup, credential-possession proof
or operation permission. Native admission is explicitly enabled separately.

CSRF-bearing originals select attempt v5, issuance v2, and Send v3 (without
recipient) or v4 (with recipient). Each carries the original named CSRF key
version and digest, with tenant/session/version derived from the exact retained
session tuple. Tokenless profiles retain their original bytes. Upgrade readers
before enabling these continuations: older binaries reject the new profiles.
Restoration never looks up a replacement original or renews freshness. Custody
does not enforce browser Origin, submission channel or synchronizer-token
possession; the transport and native admission still own those checks.

## Native authenticated-session execution

Use `NewContributorWithSession` with a separate `SessionAdmissionConfig` to
enable authenticated-session denial and consumption. The existing
`ContributorConfig` and pre-auth-only `NewContributor` remain compatible.
A session-only installation may omit pre-auth configuration; installations
supporting both contexts must configure both retained-key profiles.

Configure the session owner's identifier admission profile, retained token
keys and a positive freshness limit. The participant authenticates the separate
bearer against complete original custody, checks current primary directory,
credential, authorization, session and family authority, and denies unsupported
optional authority dimensions. It rechecks original freshness and credential
expiry after lock waits; retries cannot renew either deadline.

Reservation, exact generation takeover and protected finalization consume OTP
atomically with domain, audit and lifecycle effects. An authenticated session
is not itself a one-time reservation and remains unchanged. Sealed rollback
and restart recovery use retained OTP predecessor evidence without recovering
the bearer; ambiguous evidence retains the reservation. This is not an
operation-permission decision, risk grant or complete login workflow.

`MapSession` and `MapSessionWithAuthority` freeze the separately submitted
session token in root's opaque command branch beside the code. The latter also
retains original primary expectations. Neither stores raw token/code in its
encrypted original-session record, renews original authentication time, performs
SQL or grants live admission. A session token cannot become a pre-auth cookie;
the coordinator fingerprints its intent under a distinct retained-key domain.

## Native counted denial

`NewContributor(ContributorConfig)` now supplies the exact
`identity.otp.store` participant for the coordinator's
`PrepareOTPAttemptPlan` / `RecordOTPAttemptDenial` path. Enlist the returned
pointer alongside the real domain, audit, lifecycle and owning-feature
contributors. Configuration supplies installed OTP/session schemas, the owned
attempt codec, explicit deployment and user-policy namespace, dedicated stable
lockout key and exact retained pre-auth cookie keys. Construction copies keys,
performs no IO and creates no independent transaction or replay owner.

Use `MapPreAuthWithAuthority` once for the original submission. The participant
requires complete original pre-auth custody and the separately submitted cookie;
legacy records do not acquire fresh authority. It checks locked deployment,
tenant and applicable user/credential/authorization authority, then the original
session-owned flow, shared abuse exclusions and scoped challenge. Database time
is sampled after challenge locking; original flow and applicable credential
expiry are checked again after downstream waits. Wrong-code charging, expiry/exhaustion,
shared lockout extension, required denial audit and stable aborted receipt commit
atomically. Exact retry reads that receipt without comparing or charging again;
changed intent conflicts. Callback errors and failed audit persistence roll back
all provisional writes. Reconstruct immutable configuration on restart, retaining
the original named key material; never replace an ambiguous command by remapping.

The separate `PrepareOTPReservationPlan` / `ReserveOTPCommand` entry point now
reserves correct pre-auth submissions. `Begin`, protected feature application
and `Commit` consume OTP and pre-auth atomically with the domain, audit, outbox
and command receipt. Live replay does not charge again; exact takeover preserves
original custody and timing and rejects the previous owner. Install
`ConsumingMigrationSource` after OTP storage and session's
`PreAuthReleaseMigrationSource` before enabling this profile. The forward OTP
migration retains only the bounded encrypted code/cookie-free original envelope
inside existing challenge storage; historical reservations receive no invented
authority. Rollback releases exact predecessors only through the coordinator's
sealed noncommit phase. Restart recovery uses retained original custody, not the
submitted command/code/cookie; divergent evidence leaves reservations pending.

The denial entry point still returns unchanged for correct codes. Successful
metered checks and issuance remain pending.
Do not enable a public login workflow or supply an application-written store to
fill those gaps. Existing command journaling owns denial recovery; unresolved
participant history without exact retained evidence remains unknown. Module source pins and clean-consumer,
coverage/mutation and release verification remain pending.

`MapWithAuthority` and `MapPreAuthWithAuthority` bind original primary authority
expectations to the same encrypted original-attempt command. `AttemptAuthority`
requires deployment/tenant epochs and, for user commands, the effective user's
authorization namespace/epoch and independent user/identifier/credential epochs,
also for passwordless login. Include the credential reference whenever the
workflow uses an existing credential. Anonymous commands cannot carry user
authority. Capture these
expectations through their primary owners once; never update them on retries.
The authenticated v3 plaintext embeds the unchanged v1/v2 attempt projection
and bounded authority projection. No raw bearer/code or authority lease is
stored; existing `Map`/`MapPreAuth` framing is unchanged. Old records remain
readable but do not acquire invented authority. Restoration validates original
envelope and core MAC before returning expectations. This is structural custody,
not a permission decision or live primary check. Counted denial now dispatches
through the native contributor alongside pre-auth consuming phases. End-to-end
login and successful metered-check profiles are pending.
Enable authority-aware mapping only after every command reader supports v3;
older binaries reject this new opt-in profile, while new readers retain v1/v2.

Private native pre-auth admission now recomputes the separately submitted cookie
under its exact retained named key and authenticated original flow, then borrows
the session adapter's locked issued/reserved primary checks. Wrong, absent or
retired-key cookies cannot substitute the stored commitment. Reserved admission
requires exact command, fingerprint and current generation; primary time after
the lock owns exclusive expiry. Admission does not charge an attempt, write a
result or renew the flow. Counted-denial dispatch composes this admission with
current authority and lockout/challenge ordering. The native consuming path
composes protected execution and retained-original recovery through the same
coordinator. No public raw store is exposed.

`AttemptCodec.MapPreAuth` explicitly maps a complete bound-flow attempt and its
separate submitted `authentication.BearerCredential`. The bearer is retained
only by opaque root command custody; `Feature()` and encrypted attempt fields
never contain it. ID-only legacy continuation or malformed token syntax deny.
The original code and attempt remain unchanged. A syntactically valid wrong
cookie is still submitted intent, not proof: the native owner must derive its
commitment under the named retained pre-auth key, then compare the complete
canonical primary flow and current authority in the sealed phase. Map once and
retain the command through ambiguity; credential-free recovery cannot recreate
the bearer. Native pre-auth consumption is available; usable OTP login remains
pending until issuance and full owning-feature/session composition are complete.

## Complete original pre-auth custody

Mapping an attempt prepared with `otp.NewBoundPreAuthAuthorization` retains
the complete immutable session-owned flow inside the authenticated encrypted
command envelope. The code-free plaintext has explicit
`identity-otp-attempt-custody-v2` + NUL framing, appending the bounded full-flow
projection before the existing core command-record MAC. Legacy contexts retain
exact v1 framing, bounds and bytes. No schema migration, raw bearer, new flow
store, journal or transaction owner is introduced.

Restoration preserves canonical nanosecond UTC times, original nonce, exact
intent/policy, resolved remember choice, named cookie commitment and version;
mixed IDs, invalid fields, truncation, trailing data or changed core MAC deny.
The v2 plaintext limit is 8192 bytes; the existing encrypted wire limit remains
8192. Old v1 plaintext remains limited to 4096 bytes. Inputs are bounded before
allocation and parsing; decoding itself is structural, not MAC verification.
`restoreRecord` verifies the original core MAC and `restoreAttempt` requires
the original opaque submitted code—custody cannot reconstruct it from storage.

This profile alone is not active-flow or cookie-possession evidence. The native
participant requires it and rechecks the canonical session-owned primary
record, submitted cookie and current policy during active consuming phases.
Recovery/release instead require exact original reserved predecessors and
coordinator-proven noncommit. Legacy ID-only records may be read for compatibility
but cannot stand in for complete-flow consuming admission. Successful metered
checks and authenticated-session profiles remain under development.

Go 1.27 native storage for purpose-bound OTPs, sharing the identity coordinator's
PostgreSQL transaction domain. Experimental and incomplete: this initial batch
implements challenge storage/migrations, **not** a usable issuance or verification
service, plus encrypted original-attempt command custody. Installing it never
proves a code, grants a reservation or authorizes a
workflow. Do not implement a consumer-written store to fill the remaining gaps.

## Quick start and API

```go
source := otppostgres.MigrationSource{Schema: "otp_store", Version: 100}
history, err := source.Load(ctx)
```

Import `github.com/faustbrian/go-identity/otp/postgres`. Compose the source with
the owned `go-migrations/v3` runner and its PostgreSQL backend, after the identity
kernel migrations. Allocate `Version` permanently in the single composition
history. The example is compiled in tests. `Load` is pure, cancellation-aware,
concurrent-safe and returns independently owned history. It accepts a dedicated
lowercase SQL namespace of at most 63 bytes; reserved schemas and zero versions
are invalid. The migration is atomic and forward-only; occupied namespaces fail
instead of being silently adopted. Reuse installed history via the migration
runner, never by executing installation SQL again.

## Storage and security

Native private primary reads now lock the exact keyed scope from committed
issuance and reconstruct the original core profile, counters and full-width
version. Denial/check/expiry writes use optimistic CAS plus a final database-time
expiry fence. Correct consumption is rejected by that separate counter writer.
These helpers are not exposed as a raw store or online verification API. Current
flow/lockout authority, command replay/result/audit and consuming participant
composition remain mandatory before a public attempt workflow is enabled.

`NewAttemptCodec` copies trusted local wrapping, attempt-issuer and code-digest
keyrings. `Map(ctx, attempt, retainedDigestVersion, featureSpec)` returns the
owning feature command and exact coordinator OTP plan. It requires the original
core `AttemptIssuer.PrepareForCommand` submission and matching structural scope.
The `otp.*` field namespace is reserved. Mapping performs no SQL or challenge
comparison; native restoration is private, not an online verification oracle.

Map once and keep the returned command/plan for retries. Encryption is randomized;
remapping changes command intent and cannot replace an ambiguous original attempt.
Retain original wrapping, issuer and digest-key versions while dependent command
history remains. Changing bytes under an existing version is not key rotation.
All keys are copied and concurrent codec use is safe. Configuration formatting
is redacted and serialization is denied. No provider callback is injectable.

Private destination and explicit flow/remember policy are encrypted and bound to
the exact command structure and selected digest version. The raw submitted code
remains only in opaque command custody, never in the encrypted record. Decrypted
byte buffers are cleared; Go cannot guarantee erasure of immutable reconstructed
strings. Cancellation/deadlines are checked before and after local cryptography;
OS entropy and crypto calls cannot be interrupted mid-call. No late success is
returned. Mapping is not proof of current session, challenge or account authority.

- Only versioned keyed code/scope digests are stored, never codes, destinations,
  key bytes or flow/session bearers. Key metadata has no secret material.
- Scoped identity, original expiry, issued policy and issuance linkage cannot
  be reset. Counters and row versions are monotone. Full `uint64` generations
  and versions are preserved without fractional rounding.
- Pre-account challenges preserve an explicitly empty, non-null subject; no
  invented account identifier substitutes for the original continuation.
- Stored states are issued, reserved, finalized, released, expired, revoked and
  exhausted. Successful checks share the total counter, but cannot reserve.
  Reservation custody is complete or absent, never partially nullable.
  Terminal release stores unchanged rollback ownership or the exact recovery
  successor, with no code comparison or interim reservation needed.
- Primary journal FKs preserve issuance and consumer lineage. Unresolved
  reservations cannot expire into clean release. Terminal rows cannot resurrect.
  No deletion path exists yet; retention/key retirement cleanup is pending.
- Database constraints reject impossible storage transitions; they **do not**
  establish cryptographic verification, current authority, counted replay,
  correct reservation generation, or a proof of non-commit. Those belong to the
  forthcoming native participant APIs in the sole coordinator transaction.
- All original policy fields are frozen. Full alphabet/entropy validation still
  belongs to `otp.NewCodeProfile`; SQL bounds are storage defenses, not another
  policy engine. Only trusted native adapter projections will write this store.

## Adoption, tradeoffs and FAQ

`LockoutMigrationSource` installs a separately versioned forward-only extension
after challenge custody. Private shared lockout identities use a dedicated HMAC
key over tenant/subject and tenant/channel/canonical destination, never plaintext
PII. Purpose, challenge, flow and rotating code-key versions cannot reset them.
Pre-account flows retain destination exclusion without inventing a subject.
The dedicated lockout key is pinned by an immutable digest binding; absent or
changed key configuration fails closed. Its future explicit migration must
preserve live lockouts, not initialize another empty namespace.

Future issuance must precreate these unique scope rows before exposing a
challenge. Native verification locks destination then subject before challenge
comparison, samples primary time after lock waits and denies active lockouts.
Only newly counted wrong exhaustion may extend them in the same coordinator
denial transaction as counters, audit and stable result; correct checks cannot.
The private SQL primitives do not yet activate these public workflows or replace
current session/pre-auth authority. No caller-owned lockout store is supported.

Private consuming persistence now projects one provisional correct comparison
into the coordinator-owned transaction, preserving exact original command,
attempt and generation custody. Exact successor takeover does not compare again,
renew times or charge another attempt. Finalization can commit atomically with a
protected domain effect; rollback removes both. Finalization and takeover enforce
exclusive primary database expiry even if the sampled decision time was earlier.
Reservation/takeover preserve a row-version increment for eventual terminalization.

Release persistence accepts unchanged rollback ownership or one exact recovery
successor, including after original expiry, without decrypting submitted codes.
These private helpers are not admission or noncommit proof: public sealed native
participant callbacks compose current flow/lockout checks and command replay/audit
under the coordinator's authoritative recovery. No public raw
transaction or binding-to-release shortcut is exposed.

**Can I use this for login?** Not yet. Native issuance/send windows and bounded
cleanup remain in development. Native original pre-auth/authenticated-session
checks and consuming composition are not complete login. There
is intentionally no public raw SQL/pool/store workaround.

**Does a successful check authenticate?** No. Register the native contributor
and explicitly select `Coordinator.RecordOTPMeteredCheck` with its exact
record-free `identity.otp.check` declaration and original check-mode command.
The original separately submitted cookie/session bearer, frozen authority and
current primary admission are required before comparison. Each new admitted
check charges both the separate check allowance and shared total allowance,
including correct checks; disabled or exhausted allowances do not charge.
Wrong final exhaustion may extend shared lockouts; correct final exhaustion
cannot. Counters, required audit and the existing journal receipt commit
atomically, without reservations, session changes, domain application or
lifecycle delivery. An audit failure rolls back the charge.

Exact retries preserve the result without another comparison. A correct check's
`CommitOutcomeCommitted` means only that its metering receipt committed, never
proof or permission to perform a protected action. Wrong checks return retained
`CommitOutcomeNotCommitted`; the first submission reports denial, while ordinary
exact replay returns the retained receipt. `RecoverOTPMeteredCheck` requires
current query authorization and the original scalar attempt plan, not the code
or bearer; it recovers historical classification without renewing authority.
`ApplyFeature` always denies: generic domain execution cannot run this operation.


**Can I rotate a digest in place?** No. Existing rows keep their original retained
key version and digest. Future issuance selects the modern active profile;
retirement must preserve referenced replay tombstones.

**Does expiry release a reserved OTP?** No. Only the coordinator's authoritative
non-commit protocol can do that. A terminal release requires a newly issued OTP.

**Which checks exist?** Real isolated PostgreSQL tests exercise installed storage,
counter CAS races, expiry, immutable terminal states, full-width custody and
transaction rollback. These are not end-to-end code verification, delivery,
recovery, complete adapter coverage/mutation or release evidence.

## Release notes

`SendFamilyMigrationSource` installs rolling-hour send history after challenge
and lockout storage using a separately allocated migration version. It leaves
existing challenges untouched. Histories contain at most ten database-time
instants and a keyed family digest, never a destination, code or flow bearer.
The stable pinned abuse key has a separate send-family HMAC domain over tenant,
purpose, subject and channel/destination. A new challenge, target, flow, policy
version or rotating code key cannot refill the allowance.

Private issuance persistence requires original-flow admission, shared abuse
locks, then a family lock and a new primary-time sample. The rolling window is
`(now - one hour, now]`; resend equality is allowed. Schema guards reject
history erasure, deletion, identity changes, backward/future time and omitted
live sends. Counters must commit with challenge/replacement, required audit,
encrypted delivery and the existing command journal, or roll back together.
The extension does not yet expose public Send, perform generation/delivery,
resolve enumeration-safe account lookup or implement challenge replacement.
Existing consuming/check APIs are unchanged.

See [CHANGELOG.md](CHANGELOG.md). No stable release or production-readiness claim
is made for this development checkpoint.
