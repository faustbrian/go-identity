# Identity risk policy

This Go 1.27 module implements the first risk-core behavior: immutable canonical
operation admission, deterministic scoped assessment, bounded server-source
orchestration and phase-bound counter dispatch.
It is **not yet the complete risk service**. Durable counters, audit/journal
ownership, CAPTCHA/HIBP orchestration, overrides, lockout/recovery and one-use
RiskEvidence/CaptchaEvidence issuance remain required implementation work.

## Adoption and API

### Anonymous upgrade counters

`identity.anonymous.upgrade` selects protected CredentialMutation counters,
reserved and finalized with the original native upgrade command. The risk plan
binds its exact tenant, subject, session, network and attempt and preserves its
original exclusive expiry. This classification grants neither guest possession
nor permanent-account authority. The anonymous owner must independently require
both, consume its one-use transition, fence current factors and commit merge,
disposal and session rotation atomically. Native upgrade remains in development;
unselected action aliases are still denied.

### Organization-owned domain evidence

`identity.organization.domain.evidence.apply` and
`identity.organization.domain.evidence.revoke` use the same protected Privileged
class as organization domain reservation and withdrawal. This explicit native
split implements organization's sole proof-authority contract: publication and
revocation mutate domain authority, so they require the configured mandatory
signals plus exact transaction-owned tenant/actor/resource/network counters.
Neither operation verifies DNS/HTTPS, authenticates a member or grants permission
to publish a proof. The organization owner must independently enforce those
requirements and original evidence expiry in its atomic command. Unlisted aliases
and the separate unfinished SSO challenge/verify operations remain denied.

### Anonymous MFA OTP login-send counters

`CommandCounterPolicy.PrepareMFALoginSend` selects only
`identity.mfa.otp-send`, retaining the canonical protected-operation policy.
The native MFA workflow supplies the authenticated original browser-flow ID,
resolved account and trusted network. It never fabricates a session. The four
keyed targets are tenant, account, original browser flow and network; a new
child or command in the same browser does not get a fresh browser budget.
`ValidateMFALoginSend` preserves original exclusive evidence expiry and exact
policy/scope ownership. Pure preparation is not proof validation or allowance.
The PostgreSQL participant and public sender must still authenticate the
original source and reserve/check these counters transactionally; this core
profile alone is not a working OTP login service.

### Original Authentication admission across restart

`NewAuthenticationAdmissionCustody` selects an existing counted, audited
evaluator, retained `EvidenceKey` versions and an explicit startup
`ConfigurationID`. All source versions must be pinned. Change the identity
whenever callback, counter-store or audit-delivery semantics change; function
identity cannot be inferred. Actual policy values, source versions/budgets,
counter keys and audit policy also bind the retained configuration. A change
denies existing admission rather than silently renewing or reinterpreting it.
Adding a new integrity key retains old-key restoration; retiring the original
key denies. A counter-key/configuration rotation requires fresh admission.

`Prepare` accepts only genuine original counted/audited Authentication Allow
from that exact evaluator and trusted scope/dimensions. Its opaque result's
`Prepared` method returns an owned signed native projection. The native workflow
must encode it only inside its existing authenticated encrypted preparation
output, binding the original request and generation; never expose it as a public
operation result or persist another admission table. Generic JSON/text
serialization is rejected. Native adapters encode the bounded typed fields.

`Restore` can use a newly constructed evaluator with the same configuration and
retained key. It authenticates original normalized facts, factor state, counted
scope and audit provenance before returning opaque current admission. `Check`
uses the trusted clock and original signal intervals, including the earliest
exclusive expiry; copies, retries, caller clocks and restoration cannot renew
them. Both avoid source, counter and audit IO. Original counter/audit identity
is retained in a keyed digest, not replayed as a new mutation.

An owning native transaction may use `admission.CheckAt(ctx, primaryTime)` to
validate the same opaque admission against its trusted database observation.
It invokes no configured callbacks and retains every original interval and
exclusive expiry. Never pass transport/request-controlled time. `Check(ctx)`
continues to use the evaluator clock for checks outside that transaction;
neither method supplies current account authority or consumes one-use evidence.

This is non-issuing abuse admission, **not** phone/CAPTCHA one-use evidence,
caller authentication, current account/flow/recipient authority, native store
health or a public OTP Send service. The owning workflow must still recheck its
applicable primary authority and commit effects through its existing atomic
journal. Native OTP composition and full release proof remain unfinished.

### Protected credential-mutation preparation

`Policy.AssessProtectedProviders` checks required provider observations before
password hashing and rechecks their original freshness without provider IO.
It supports the command-reserved credential-mutation profile and rejects
caller-supplied velocity. Its distinct result is **not** complete risk admission:
the native mutation owner must reserve and recheck the exact matching counter
policy in the protected transaction. HIBP and every other mandatory provider
remain fail-closed. Ordinary `Policy.Assess` still requires velocity.

The pure assessment additionally supports the exact HIBP-enabled
`identity.phone.password-reset-complete` profile with mandatory velocity.
That workflow's existing native RiskEvidence owner must authenticate the
original counted attempt and recheck current durable allowance during atomic
evidence use. Provider-only hashing must not recharge or synthesize velocity.
This exception enables no other authentication action and does not broaden
the evaluator or protected-admission custody profiles below. It is preparation,
not an enabled phone reset service or permission to persist a password.

`PhoneEvidenceIssuer.PrepareUse(ctx, original, consuming)` resolves the exact
original issuance through the configured native executor and produces only
opaque `EvidenceUse` after matching committed intent, original scope, presented
reference and exclusive expiry. Supply the retained complete original command,
actor and subject correlation, not reconstructed current facts. Native records
remain private. Resolution never evaluates providers, charges counters or issues
replacement evidence; it cannot renew source expiry or grant reservation,
current-counter allowance or protected-domain authority.

`Evaluator.EvaluateProtectedProviders` collects those facts through the same
configured bounded readers and failure handling as ordinary evaluation. It
does not call velocity or the standalone audit sink: native counters and audit
belong to the protected transaction. `RequireProtectedProviderAdmission`
rechecks the owned result's original scope and exclusive expiry without
provider redispatch. Neither method grants authentication, factor proof or
mutation permission; public MFA composition is still incomplete.

`ProtectedProviderAdmissionCustody` retains the provider-only result through
the existing native admission integrity codec and encrypted preparation output.
It has a distinct profile from Authentication custody and requires pinned
source/configuration versions. Restore never reruns providers or renews facts;
`CheckAt` uses trusted primary time without callbacks under native locks.
`ValidateCounterPolicy` requires the same immutable policy for native counters.
No additional store, replay journal or evidence issuer is introduced.

### Owned velocity recovery custody

The private `risk/internal/velocity` connection orders owned adapter calls:
acknowledged original intent precedes a single native invocation, and the
original result is retained through that receipt. Matching retries use terminal
primary readback, never redispatch unresolved attempts. An error accompanying a
known commit denies admission without erasing the outcome. The connection adds
no journal, health cache, epoch or authority graph. Only owned adapters can bind
its functions; application holders of opaque adapter outputs cannot invoke a
bare native effect. Concrete factories and real primary/native composition are
still unfinished, so this private connection does not enable public traffic.

The private connection can retain the original activated chain and read-only
journal verifier. Native binding authenticates its configured graph against
that retained chain and rechecks current primary state without replay callbacks.
The composite rejects a separately substituted journal connection even when
namespace and graph match. No issuer is returned and no application may extract
the chain or supply binding callbacks. Concrete factories must originate chain
and journal functions in the same primary owner; that factory wiring and live
composition remain unfinished. Unbound internal sequencing handles are not a
public traffic profile.

`VelocityJournalIssuer.AcknowledgeEligibility` retains an already acknowledged
primary activation of the exact native-confirmed chain with its bounded current
primary checker. `VelocityNativeVerifier.Eligibility` authenticates that chain
and invokes the current checker, never invalidated replay callbacks. Copies and
reads preserve original expiry and cannot cache an allowance. The concrete
PostgreSQL owner must supply its actual `CheckHealthy`, not consumer-written
health assertions. Native continuity, exact-marker enforcement and journaled
intent/result conservation still must be composed before public traffic.

`NewVelocityRecoveryAuthorities` creates an isolated journal issuer/verifier and
native issuer/verifier pair. This is a trusted composition primitive, not a
counter store or a public application recovery workflow. The owned reference
composition must retain the journal issuer only in PostgreSQL and the native
issuer only in the concrete Valkey adapter. Neither issuance capability may be
returned in `StoreSet`, accepted as an ordinary application override, or exposed
through operational handles. Verification views have no issuance methods.

`VelocityNativeIssuer.Verifier` derives the configured native owner's read-only
view directly. Its recovery implementation can check exact primary confirmation
without accepting a separately supplied, unchecked native verifier. Zero owner
denies derivation. The returned view cannot be promoted back into issuance and
does not perform native IO or establish healthy admission.

The journal issues `VelocityLease` only after primary acquisition, with a bounded
checker for that exact original receipt. It issues `VelocityHistory` only after
authenticating original journal facts under the current lease. The native owner
checks configured journal custody, reconstructs original aliases and windows,
executes the fenced effect, and calls its private issuer's `Acknowledge` only
after an exact attributable response. A genuine lease/history holder cannot
recover that native issuer; a separately constructed graph remains foreign.
The types deliberately prohibit Go struct conversion between capability roles.

`VelocityNativeVerifier.Applied` verifies the configured native issuer and
rechecks original primary ownership before returning copied facts. PostgreSQL
must still independently authenticate current journal facts and persist ordered
progress atomically. Pending/unknown cannot be acknowledged as noncommit, and
neither acknowledgement nor applied progress publishes health or permits debit.
Cancellation/deadlines survive; other authority-check errors are redacted.

These capabilities are immutable, safe to copy/read concurrently, and reject
automatic formatting/serialization disclosure. Original counts, observation
times, expiry and nested aliases are copied without renewal. The primary
checker must itself be concurrent-safe and bounded by context; no SQL locks may
span native IO. A configurator deliberately retaining the native issuer can
misdeclare effects, just as it can replace deployment resources: this API is not
attestation of malicious configuration. Production composition must own that
trust boundary. Concrete recovery wiring and complete healthy activation remain
under development; constructors alone confer no usable counter authority.

`VelocityJournalIssuer.Closure` records only an already acknowledged **covered**
primary cut. It retains the stable keyed cut ID, applied position (including
zero for covered empty history), original replay origin/through, journal start
and one-hour maximum window. The original traversal origin may precede journal
provenance; that does not claim coverage before the journal start. Both must
reach the full final window. The concrete primary checker must verify that
exact retained covered cut and original lease; ordinary stable closure is not
eligible. Issuance is pure and cannot itself prove storage or historical facts.

After exact fenced native publication IO, the privately retained native issuer
calls `AcknowledgePublication`. Its distinct `VelocityPublication` binds the
exact closure object and configured owner, rechecking primary custody without
renewing any timestamp. `VelocityNativeVerifier.Publication` returns original
facts only for that exact acknowledgement/closure/lease. Equal projected fields,
reconstructed foreign graphs and replacement lease handles cannot substitute.
These APIs perform no native IO or primary health mutation. PostgreSQL must
independently authenticate and atomically confirm publication; subsequent debit
must also require the exact current native marker. Complete concrete healthy
activation remains under development.

After its publication confirmation is durably acknowledged or authoritatively
reconciled, PostgreSQL may call `VelocityJournalIssuer.AcknowledgeConfirmation`
with a bounded checker of that exact persisted confirmation. The resulting
`VelocityConfirmation` retains the original publication object, not just its
projected identity. `VelocityNativeVerifier.Confirmation` independently checks
original lease, covered cut and primary confirmation; it returns unchanged cut
facts only for the exact chain. Neither checking nor copying renews any time.
The retained recovery checks remain recovery-only, not healthy-state admission.
Concrete adapter export, native confirmation and present continuity are still
required before traffic can be admitted. A publication acknowledgement or an
ordinary covered cut cannot substitute for recorded primary confirmation.

After exact native confirmation IO, the configured native owner calls
`AcknowledgeNativeConfirmation` under the same bounded deadline. The resulting
`VelocityNativeConfirmation` binds that exact confirmation chain and exposes no
issuer. `NativeConfirmation` is deliberately a pure historical identity read:
it does not run replaying-only checkers or establish current validity. This lets
the primary independently recheck and reconcile its own eventual healthy
transition after replay custody has become invalid. Expired or superseded
history may still match identity; it cannot authorize mutation, renew expiry,
prove native continuity or permit traffic. The primary's locked state/expiry
checks and the native effect boundary remain mandatory and unfinished here.

### Stable velocity replay identity

`NewVelocityReplayIdentity(namespace, key)` owns the immutable shared lookup
profile for the durable velocity journal and ephemeral adapter. `Namespace()`
and `Attempt(command)` return copied 32-byte keyed digests preserving the
existing PostgreSQL domains and eight-byte length framing. Both adapters must
select the same stable namespace/key, independent of rotating dimension keys.
Changing policy, aliases, preparation time or fingerprint does not create a new
attempt lookup: storage must compare the original fingerprint to reject changed
intent. Zero and protected-transaction commands fail closed.

These restricted adapter projections grant no debit, retry, journal authenticity
or health authority and reject automatic custody serialization. Adapters must
still validate exact command configuration and authenticate retained history.
Native adapter consumption, restart reconstruction and safe public activation
remain unfinished; this contract alone is not a usable counter store.

### CAPTCHA evidence admission and custody

`CaptchaEvidenceIssuer.PrecheckUse(ctx, originalIssue, request, nativeRecord)`
authenticates the original signed issuance, presented reference and exact trusted
flow, while binding a distinct consuming command and actor. It invokes only the
configured clock, never providers, executors or stores. `Prepared()` returns
owned signed native custody without the bearer; `EvidenceKey.RestoreCaptchaUse`
authenticates it and `CaptchaEvidenceIssuer.RecheckUse` additionally checks the
current immutable verifier configuration at supplied primary UTC time. All
native adapters can use callback-free `CaptchaEvidenceCustody.RecheckUse`
instead, avoiding an executable issuer/store construction cycle. All
copies preserve original expiry and reject exact expiry. These methods prove
local integrity only: durable issuance, current authorization, target versions,
reservation, finalization and primary recovery remain the protected coordinator
and adapter's responsibility. The consuming command fingerprint must cover this
custody and its complete target/version fields. Protected CAPTCHA consumption
is still unimplemented; this bridge must not be used as a stand-alone gate.

`NewCaptchaEvidenceCustody(config)` gives the owned native adapter the same
immutable verifier/policy/key configuration without runtime wiring. It does not
require or retain `Clock`, `Verify` or `Executor`; all static issuer bounds stay
mandatory. `ValidateConfiguration` checks the adapter's complete retained
evidence-key set and policy version, order-independently. `RestoreCaptchaIssue`
authenticates both original signed custody and the exact selected configuration,
including retained replay-key versions, without callbacks or renewed expiry.
Construct custody first, then the native repository/executor, then the runtime
issuer. No dummy executor or mutable registration loop is needed. Custody has no
prepare/verify/issue methods and never proves commitment or current authority.

`NewCaptchaEvidenceIssuer` composes the replay owner, exact configured
API/version/tier capabilities, canonical hostname/origin/action bindings,
optional score threshold, original validity limits, retained independent
integrity/linkage keys and bounded verification/execution callbacks. The
official verifier must establish the declared provider capabilities; selecting
them here does not prove that an external provider supports them. The core
accepts only its bounded normalized projection, not arbitrary provider payloads.
Present-empty, unavailable and unsupported facts remain distinct and cannot
become a successful binding. Hostnames are lowercase ASCII DNS names, origins
are canonical HTTPS authorities, and matching is exact, never wildcard-based.

`Prepare(request, token)` derives immutable command/replay custody without
retaining the token. `Issue(ctx, intent, token)` checks that custody and resolves
the same command before verification. Only proven absence allows one bounded
provider verification. The core rejects foreign flow/profile facts, mismatched
bindings, unsupported fabricated fields, invalid/below-threshold scores and
expired observations. Evidence expiry also cannot exceed the core verification
invocation time plus the configured lifetime, even if a callback reports its
completion as the observation time. Any earlier provider or challenge expiry
still wins. Preparation is not authentication, authorization or full
risk evaluation: the protected workflow still owns every other mandatory risk
signal and independently configured low-risk step-up policy.

Successful facts produce only an opaque provisional `CaptchaEvidenceIssue`.
Its `Materialize(primaryTime)` creates a signed native candidate with the
original exclusive expiry; it does not establish a durable row. Only a validated
committed executor outcome reveals `CaptchaEvidence` and safe original times.
The native record may retain the configured hostname, but never score, provider
payloads, raw token or remote address. A separate scoped token commitment binds
the command intent while prescribed replay aliases retain their independent
rotation semantics. Changing a token cannot reuse the old command result.

`Recover(ctx, intent)` needs no raw token and cannot verify or issue. Unknown
and late/failed acknowledgements return no bearer; recover the original command,
never create a replacement. Retained keys preserve the exact historical result
even after expiry without renewing it or implying present-use authority. An
unexpected concurrent winner must be reconciled as that exact original record.
Configuration, intent projections and bearer custody reject automatic
serialization and redact diagnostics; only `Reference.Reveal()` transfers it.

`CaptchaEvidenceIssue.Prepared()` returns a copied, signed native command
projection. `EvidenceKey.RestoreCaptchaIssue` authenticates the complete flow,
original replay aliases, configuration/intent commitments, proof, nonce,
hostname and interval without raw token, callbacks, clocks or new randomness.
At the same primary time it reproduces the exact original candidate. It grants
no commit or consumption authority. The official adapter must still enforce
current policy, authorization, rotation history and exact shared-Work scope.
`CaptchaEvidenceIssuer.RestoreCaptchaIssue` additionally checks the current
immutable verifier configuration/policy and retained key versions, returning an
intent for `Recover` only. `Issue` rejects restored intents even with a token;
Missing recovery is never permission to reverify or resubmit. Historical
committed results retain the original exclusive expiry. Removing a referenced
key or changing the verifier configuration rejects restoration; retain original
startup profiles for their required recovery/tombstone lifetime. Newer retained
keys coexist without rewriting original aliases or signed custody.

This is development composition, not an application-provided store contract.
The actual provider-neutral closed native-evidence union, official provider
adapters, PostgreSQL command mapping and single-winner issuance,
reserve/apply/finalize, canonical audit/failure attribution and full Service
composition are still required. The boundary doubles prove core result
conservation, not provider truth, database atomicity or durable one-use behavior.

### CAPTCHA replay preparation

`NewFlowContext(FlowContextInput)` freezes one trusted pre-auth, authenticated
subject/session or administrator context with its tenant, canonical operation,
subject or anonymous flow, challenge and canonical request fingerprint. Supply
only server-resolved facts. Structural construction does not authenticate an
actor or authorize evidence issuance.

`FlowContext.Bindings()` returns a value copy of those original trusted fields
for provider transport binding, rejecting zero contexts. It grants no authority
and exposes no keyed token replay identity. Its request fingerprint is the
original command-intent commitment, not the replay HMAC. Automatic diagnostics
remain redacted and serialization is forbidden.

`NewCaptchaReplayPolicy(CaptchaReplayPolicyConfig)` selects the existing risk
policy, one closed provider ID, exact site/API-profile/configuration identity,
explicit token byte ceiling and newest-first retained `CaptchaReplayKey` values.
`Prepare(flow, token)` accepts only an operation whose selected policy requires
CAPTCHA. Token length and UTF-8 are checked before bounded cryptographic work;
bytes are neither normalized nor retained.

Replay HMAC uses exactly `identity-captcha-replay-v1`, NUL, four unsigned 32-bit
big-endian length-prefixed UTF-8 fields (provider, site, API/profile, configuration
version), then the unsigned 64-bit big-endian raw-token byte length and bytes.
Tenant belongs to the outer durable namespace. Flow, operation, logical command
and key version are intentionally not in those MAC bytes: changing them must
not turn the same provider token into another issuance opportunity.

The opaque result separately retains exact preparing-policy and flow provenance.
`Validate` rejects substitution; `Bindings` returns an independently owned
native-only projection with every retained digest version. This is not public
HTTP metadata. Automatic formatting redacts custody; serialization rejects.
Applications must not use these digests as authorization or supply reconstructed
strings as core provenance.

The PostgreSQL contributor must validate authoritative retained-key history and
atomically acquire a single winner across all aliases before issuing evidence.
Do not retire a key referenced by unresolved issuance or retained replay
tombstones. Provider verification, safe normalized facts, durable issuance/use,
reconciliation and canonical Service remain required implementation work;
hash equality alone does not prove one-use behavior.

### Administrative lockout intent

Registration-link confirmation has no authenticated session. Use
`CommandCounterPolicy.PrepareVerification` and `ValidateVerification` with
the original cryptographically authenticated grant ID and subject, plus the
trusted canonical network. Only `identity.email.verification-confirm` selects
this closed lane. It preserves the configured CredentialMutation bounds but
uses `tenant + subject + capability + canonical_network`, never a fictitious
session. Grant IDs are not bearer bytes; only domain-separated keyed digests
leave preparation. Tenant and subject limits continue across separate links.
Ordinary `Prepare`/`Validate` and other operations keep their existing session
requirements. These methods neither authenticate a proof nor authorize a
mutation; the native participant must reserve, recheck and recover counters
in the same owning coordinator as the protected email mutation. Concrete
adapter adoption and composed confirmation remain under development.

Anonymous TOTP login completion separately selects `PrepareMFACompletion` and
`ValidateMFACompletion` for `identity.mfa.totp-verify`. Authenticate the original
continuation's subject and child capability at the native MFA owner first.
This lane retains the same protected limits, phase and failure policy and uses
the same four dimension kinds; it does not reclassify enrollment or step-up
as authentication. Wrong-code attempts need command-owned risk charging as
well as the MFA budget, not a success-only charge. These pure APIs grant no
allowance or factor authority. Native adapter integration remains unfinished;
do not enable public completion by substituting Authentication admission.

`NewLockoutPolicy(LockoutPolicyConfig)` composes an existing
`CommandCounterPolicy` with an explicit positive microsecond-exact
`MaximumDuration`. There is no default duration or automatic velocity trigger.
`Prepare(LockoutRequest, primaryTime)` freezes StartLockout or EndLockout,
the independently authenticated administrator, the exact expected restriction
version, and a trusted credential-mutation subject. Start selects a positive
duration at or below the configured ceiling; End requires a positive expected
version and zero duration. Version overflow rejects. Primary time is UTC at
microsecond precision; out-of-range resulting dates reject.

Only the operation-specific keyed subject is a restriction target. Tenant,
network, session, unauthenticated identifier hints, privileged resources and
authentication/recovery operations are not targets in this profile. Thus a
password-change restriction does not imply an account-wide recovery ban.
Factor-proof, recovery-code and administrative factor-recovery operations are
also excluded even where the canonical risk matrix classifies them as credential
mutations. Their existing counters and risk assessments remain unchanged.
Other lockout profiles remain required platform work, not implicit fallback.
`Context.Now` and `IndependentFactor` are rejected, not treated as bypass flags.

`Validate` requires the exact original policy and request and the existing
counter policy's exclusive preparation TTL. It never resets freshness.
`Bindings` supplies an owned adapter-only keyed projection; automatic formatting
redacts it and serialization rejects. Neither construction nor validation checks
current administrator permissions, durable CAS state or commitment. The native
PostgreSQL participant must implement those checks, mutations, canonical audit
and same-command recovery through the existing identity coordinator. That
participant integration is unfinished; consumers must not supply mutation SQL.

Construct `Policy` with `NewPolicy(PolicyConfig)` using the selected reference
configuration authority, a positive policy version, explicit velocity limits
and all four class profiles. No numeric defaults are applied. Class phases,
dimensions, failure policies and selected-profile ceilings are checked at
construction. Required source names form the complete mandatory signal set.

`Admit` selects an exact canonical operation and returns an owned profile copy.
Unlisted actions, aliases and malformed IDs fail before signal access. The
closed sensitive-operation fallback denies before signal work; the closed
public-neutral-read fallback still requires its owning audit before execution.

`Assess` accepts one trusted server `Context` and normalized source results.
Scope/attempt mismatches, duplicates, extra signals and expired original
intervals reject the whole assessment. Omitted or spoofable mandatory facts are
unavailable, not clean. Summaries remain in configured mandatory-source order;
the decision is order-independent: deny, step-up, throttle, allow. Deliberate
skipping is retained only beside another verified irreversible deny. Unknown
results never invent retry-after metadata. Cancellation returns no assessment.

### Neutral password observations

Select `PolicyConfig.HIBP` explicitly with the provider's immutable CacheTTL
(1 hour..7 days) and the supported canonical password-creating Operations. The
zero configuration retains existing policies. Selected operations add mandatory
`hibp` without removing any other source; unrelated signin/read operations do
not inherit screening. Reference composition must select every supported password
create/set/change/reset operation. A subset is development/non-reference scope.
Neither callers nor observations select the operation list or failure policy.
`HIBPConfiguration` returns an owned sorted snapshot for adapter startup checks;
disabled or zero policies reject. It grants no assessment or mutation authority.

`PasswordSignal` normalizes a trusted `PasswordObservation`, not a decision.
Zero-count/no-match becomes `SignalClean`; a bounded positive count becomes the
new `SignalPositive` fact. Existing state numbers are preserved. `Assess` owns
the consequent denial, even when another factor exists. Provider failures remain
unavailable with closed safe classifications retained in internal summaries.
Raw provider errors, suffixes and hashes have no representation in these facts.

Provider ObservedAt and ValidUntil remain original. CheckedAt records the local
candidate comparison, not a provider reread. Assessment expiry cannot exceed
either CheckedAt plus the consuming profile's EvidenceTTL or original provider
ValidUntil. The original provider interval must equal the configured cache TTL;
expired/future/inconsistent observations reject. This scoped long-lived provider
fact contract never exempts counter/carrier or credential-authority evidence
from their original freshness limits. Generic source errors cannot turn apparent
positive output into clean facts; only validated unavailable classifications
survive. Phone evidence still requires its independent all-clean two-minute
observation interval and cannot be minted from a positive breach fact.

The HIBP checker-to-signal adapter and password workflow custody remain separate
implementation work; pure signals/assessments grant no protected effect.

### Server-source evaluation

`NewEvaluator(EvaluatorConfig)` binds the policy to exactly one configured
`Source` for every mandatory name, except the owned `velocity` slot when
`EvaluatorConfig.Counters` is configured. Sources are server-owned, transport-neutral
readers; requests cannot inject facts, replace readers, select failure policy,
set the decision clock or assert independent-factor availability. Configuration
is copied and validated before any reader runs. The caller binds the operation,
tenant and attempt using its owned workflow, not raw transport fields.

`Evaluate` currently supports only the explicit `none` phase and returns a safe
decision/version. Both phone-reset issuing phases reject before source work
until real durable contributors and command recovery are implemented. There is
no caller purpose field and no fabricated evidence reference.

Evaluation has one explicit total deadline (positive, at most one minute) and
per-source deadlines bounded by it. Readers must honor cancellation and close
their resources; no background goroutine is used to pretend a blocked reader
was cancelled. Errors and late results normalize to unavailable. Every mandatory
source is evaluated unless it is configured expensive and a separately verified
deny already exists; skipped summaries remain internally retained. All original
positive fact intervals are rechecked at the final clock sample. A failed server
factor resolver cannot enable step-up. Reader implementations must be concurrency
safe; the evaluator owns neither their external resources nor their shutdown.

Without `Counters`, this source runner performs no counter mutation. Without
`DecisionAudit`, it remains explicitly unaudited. Neither configuration adds
decision-journal persistence or evidence issuance. It must not be used as complete middleware
or as permission to execute the selected operation. The later official adapter
composition must implement those owners; consumers must not supply private
domain stores or replacement workflow orchestration.

### Authentication workflow admission

After an owned workflow calls `Evaluate`, it may call
`Evaluator.RequireAuthenticationAdmission(ctx, result, scope, subject)` before
credential work. This accepts only this exact evaluator's counted, audited
Authentication-lane Allow with the original trusted operation, tenant, attempt
and canonical subject dimensions. Literal or JSON-restored decisions do not
qualify. Source-only and unaudited development modes never qualify.

The check uses the configured clock and original facts, denying at the earliest
exclusive expiry or on a backward clock. It performs no IO, counter mutation,
retry, audit delivery or expiry renewal. It is abuse admission only, not a
current account/session check, native-health assertion, authorization grant or
one-use artifact. The platform-owned workflow must retain those authorities and
its existing atomic transaction/replay protocol. Public OTP Send composition
is still under development; consumers must not build replacement workflows.

### Required non-issuing decision audit

Select `EvaluatorConfig.DecisionAudit` at startup with an immutable canonical
policy ID, explicit timeout, existing `audit.RecorderConfig` and bounded `OnLoss`
operational handoff. Supply trusted `EvaluateRequest.Attribution` per operation;
attempt subjects must match the evaluation attempt. Invalid attribution rejects
before sources or counters. Policy version, decision and event time are owned by
the evaluator, not the caller. Caller redactors cannot remove required fields.

The shared root profile emits protected `identity.risk.decide` records for all
four classifications and closed defaults. Clean primary or durable-buffer
acknowledgment permits returning the non-issuing decision; alert-only success
does not. Failure suppresses Allow and private issuing provenance, preserves
restrictive decisions and already-known counter/audit outcomes, and exposes only
redacted errors. Original source validity and throttle windows are rechecked
after audit acknowledgment without another counter mutation or freshness reset.

`EvaluateResult.Audit` retains the exact canonical record, command and append
classification. Recovery must resubmit that original record, not rebuild it or
repeat evaluation. `OnLoss` receives a bounded cancellation-independent context;
success is an operational handoff, not proof of durable reconciliation. Official
durable recovery and full risk-service composition remain unfinished. Sink,
buffer and observer owners must obey context and be concurrency-safe.

`PhoneEvidenceIssuer` rejects an audited evaluator because its native transaction
already owns the risk-decision event. Keep its existing evaluator configuration;
this opt-in non-issuing delivery must not duplicate or replace native events.

### Phase-bound counter dispatch

`NewCounterCoordinator` binds one owned ephemeral `CounterStore`, the policy,
a server clock, a bounded timeout and one to four newest-first versioned HMAC
keys. `Prepare` freezes exactly the selected operation's dimensions and phase
without storage access. Full IPv4/IPv6 addresses are canonicalized before
derivation; mapped IPv4 representations converge. Raw addresses, identifiers,
devices and secret keys are not included in storage keys. Returned bindings
are independent adapter projections, not dispatch or credential authority.

`Mutate` dispatches once. Only a complete same-command post-mutation snapshot
can produce a usable velocity signal. N permits N attempts; N+1 applies the
selected threshold. Noncommit, ambiguity, storage errors and foreign results
are unavailable; no automatic retry occurs. A known commit remains committed
after cancellation, timeout or stale evidence but yields no usable facts.
Original authoritative observation times and window boundaries survive replay;
the earliest observation expiry or window expiry bounds the returned signal.
Authoritative observation begins at the store's read/effect boundary (Valkey
script `TIME`), not the client's transport start. Even when that timestamp
follows the first local start, later replay cannot change the absolute horizon.
The local deadline still bounds execution, and preparation TTL still limits
whether a command may be dispatched; neither becomes new source freshness.

`CounterResult.Declaration(command)` supplies the configured journal with the
original declared outcome and a cloned snapshot for the matching logical
fingerprint. Zero/mismatched values return no facts. A later preparation cannot
replace the original timestamps, and historical expiry does not erase commit
truth. The accessor is pure and does not authenticate the store, validate
primary/native health, permit retries or grant positive admission. The durable
owner must still validate its acknowledged original intent/configuration before
recording; public journal/native composition remains unfinished.

Retained digest versions are aliases for one logical counter, not independent
windows. The adapter must prove rotation/epoch continuity and reject unsafe
retirement; supplying aliases is not that proof. This coordinator does not
implement a rate algorithm, cardinality eviction, durable lockout, journal
recovery, audit, evidence issuance or an administrative override. Protected
`reserve_with_owning_command` phases deliberately reject in the ephemeral
coordinator until shared
transaction participation is implemented. No current workflow consumer uses
this partial path. Official PostgreSQL/Valkey adapters remain required; consumers
must not implement replacement domain stores to fill those gaps.

### Protected command counters

`NewCommandCounterPolicy` takes an existing `Policy` and 1..4 retained,
newest-first `CounterDigestKey` values, with no store or clock. Its `Prepare`
accepts only the credential-mutation and privileged operation profiles, their
exact trusted dimensions, and supplied primary UTC microsecond time. Limits,
windows and evidence lifetime remain explicit deployment policy; no lockout
algorithm or duration is inferred from the velocity profile.

`Validate` reconstructs every target under that exact policy instance and
checks the original exclusive evidence interval without refreshing preparation
time. Durable keys use `rc1` and separate HMAC domains; ephemeral `rv1` state
cannot become the same authority even with the same retained keys. Returned
bindings own their slices, contain no raw dimensions, and confer no permission.
Every ephemeral coordinator rejects command-owned values before clock/store
access. `ExampleNewCommandCounterPolicy` demonstrates this pure API.

The native PostgreSQL reservation participant must still prove its exact
coordinator command scope, current rows, rotation continuity and outcome. It
must persist each logical attempt once, including a threshold-denied attempt,
through the existing owning-command transaction; it cannot let domain rollback
silently erase those attempts. SQL in open Work is provisional, not
`CounterCommitted`. Native mutation/reconciliation and current durable lockout
checks are still being implemented; this preparation API does not enable
protected evaluation or phone recovery by itself.

### Counted source evaluation

Set `EvaluatorConfig.Counters` to an existing `CounterCoordinator` using the
exact same `Policy` value. Every class profile must include `velocity` in its
mandatory set, and `Sources` must not declare another owner for that name.
The evaluator copies the coordinator value; changing the configuration pointer
later cannot replace its frozen owner. Each counted `EvaluateRequest.Subject`
contains exactly that operation's trusted dimensions, with no extra fields.
Source-only evaluation and closed defaults require an empty Subject.

Authentication attempts mutate once before any factor/provider work. Neutral
reads mutate once after the readers and before returning. The mandatory velocity
slot uses only the coordinator's complete post-state; it cannot be supplied by
a provider callback or skipped as expensive. Protected-command profiles reject
before provider/store work until their shared-transaction participant exists.

Ambiguous/noncommitted/failed mutations produce unavailable facts under the
selected policy, never allowance or automatic retries. Later provider errors,
cancellation or expiry do not undo an already committed attempt. The owning
risk implementation privately retains that outcome; public non-issuing output
does not expose counter records or correlated scope. All source and counter
intervals are rechecked at the final assessment, without renewed freshness.
Counter retry-after uses the original exceeded windows' remaining time at the
final decision, with the configured cap; provider time cannot extend a delay.
This closes core counter/source orchestration, not durable decision recording,
one-use issuance, recovery or real-adapter interoperability.

## Security and ownership

Ephemeral counter adapters authenticate an opaque command with
`CounterCommand.ValidateConfiguration(policy, retainedKeys)` before inspecting
its storage projection. Construct the adapter and coordinator with the same
immutable `Policy`; an independently reconstructed equivalent value is not the
same authority. The complete newest-first key list must match every version and
secret, including older aliases. `CounterDigestKey.Version()` exposes only
non-secret rotation metadata. Neither version equality nor this pure comparison
establishes epoch health, mutation, commitment or current-counter freshness.
Protected command-owned counters remain disjoint and fail this comparison.

### Phone evidence issuer

`NewPhoneEvidenceIssuer(PhoneEvidenceIssuerConfig)` composes the complete counted
`Evaluator`, an enabled `CarrierEvaluator` under the same policy version,
version-pinned generic sources, explicit total timeout and the native
`EvidenceExecutor`. `Evaluate(PhoneEvidenceRequest)` first resolves the exact
authorized command/actor/phone-flow intent on primary. A proven missing command
alone runs the parent phone-reset operation's risk profile and mandatory carrier
readers; it never exempts `identity.risk.evaluate` from the closed risk matrix.
The request has no purpose, decision or provider-fact override. Unknown state
cannot restart evaluation, increment counters or issue a replacement.

The native adapter maps `EvidenceIssue.Prepared()` into the existing typed
coordinator command. `EvidenceKey.RestoreIssue` verifies the signed bounded
projection from copied startup keys, so adapter construction needs no back-link
to a not-yet-constructed issuer. The issuer-level variant additionally checks
its configured policy version; the adapter must check that same version and its
exact Work binding during apply. Native execution needs no consumer glue, raw phone/network storage, private
unit of work or second command ledger. `Materialize` is core-owned construction
at authoritative database UTC microsecond time inside that shared Work. Source
expiry is never renewed: the earliest original source/carrier expiry and
two-minute observation cap win. Prepared time rounds up and expiry rounds down,
so database precision cannot expand validity. Native record/reference custody
must be envelope-encrypted atomically with the issued row and command receipt.

Only a proven committed native outcome releases `RiskEvidence` with opaque
reference, purpose, original timestamps and `MaxUses=1`. Failed, denied, unknown,
late and cancelled outcomes release nothing. `Recover` only resolves primary
state, including when missing; it never runs providers or counters. Exact replay
may return an already expired historical artifact without extending its times.
If another exact submission wins after the initial absence read, a response
that differs from this call's fresh preparation requires another authorized
primary resolution of the identical retained record. Missing, denied, failed,
unknown or inconsistent resolution releases nothing and never restarts providers.
Possession, structural parsing, MAC success and provisional materialization grant
**no recovery authority**: the durable issued row, one-use reservation and atomic
protected-command consumption remain mandatory.

`PrecheckUse(ctx, original, request, record)` locally authenticates the presented
reference against the original issuance request and current configured versions.
`EvidenceUseRequest` binds a separate consuming command and actor and must match
the original recovery scope. The native record is trusted adapter input, not
transport input. No executor/provider/counter runs; original exclusive expiry
and clock monotonicity are checked without renewal. The immutable opaque
`EvidenceUse.Validate` rejects rebinding or stale time. Multiple consumers may
precheck the same artifact: **this is not reservation or authority**. Journal
existence/state, primary-time rechecking, current counters, exclusive reservation
and atomic finalization still require the forthcoming coordinator participant.

`EvidenceUse.Prepared()` produces a signed scalar-only native projection, not
an operation result or bearer payload. `EvidenceKey.RestoreUse` authenticates it
under copied startup keys and returns an immutable `EvidenceUseClaim`; its
`Validate(now)` checks the original exclusive interval. Restoration alone is
integrity-only, so an expired historical projection may restore but cannot
validate at expiry. The projection preserves original issuance identity,
keyed intent/proof/bearer linkage and distinct proposed consumer identity.
It cannot reconstruct omitted raw recovery facts or replace full
`EvidenceUse.Validate` equality/current-policy checks. The native adapter must
match its exact coordinator command and current policy, lock the authoritative
journal and counters, and perform atomic reservation/consumption; these phases
remain unfinished. Projecting or restoring never runs callbacks or renews time.

`PhoneEvidenceIssuer.PrepareUseCounters(original, prepared, primaryTime)`
authenticates the original evidence and derives its existing counter command
without dispatch, clock sampling or a new charge. Its attempt, policy and keyed
targets remain those of issuance. A native durable counter owner must require
the matching authenticated committed attempt and then check current windows/key
history in the coordinator transaction. The returned command is not a current
allowance; deriving it never renews signed evidence or original observations.

`PhoneEvidenceIssuer.RecheckUse(original, prepared, primaryTime)` reconstructs
the complete original recovery and subject intent using the current immutable
policy/provider configuration, then authenticates the signed consumer projection
with its retained key pair. Supply authoritative primary UTC microsecond time
from the shared transaction; the issuer invokes no clocks, providers, counters
or executor. Changed raw scope/configuration, retired keys, backward time and
exclusive expiry deny. The returned claim preserves every original field;
it does not prove current counters, command authorization or reserved journal
state. The native participant must establish those separately and finalize
atomically with the protected mutation. This method does not enable domain use.

Native use integrity signs the ordered bounded fields with the existing
length-prefixed HMAC profile. A linkage HMAC under the retained digest key uses
`identity-risk-evidence-use-linkage-v1`; the integrity HMAC under the paired
signing key uses `identity-risk-evidence-use-v1` and includes that linkage MAC.
Thus substituting either retained key lane fails restoration. No raw bearer,
phone, network or pre-authentication data is serialized in this projection.

The fixed core cryptographic profile uses independent 32-byte HMAC-SHA-256
integrity/linkage keys and a 32-byte cryptographic random nonce. Version is a
nonzero uint32; newest configured version issues and all retained versions verify.
The opaque wire form is `re1.<version>.<base64url-nonce>.<base64url-MAC>` with no
embedded claim payload. Integrity binds exact keyed intent/proof and original
issued/expiry instants. Domain-separated linkage/proof/prepared/bearer MACs use
an ASCII domain plus NUL and uint64-big-endian length-prefixed fields, preventing
ambiguous concatenation. Domains are `identity-risk-evidence-intent-v1`,
`identity-risk-evidence-proof-v1`, `identity-risk-evidence-prepared-v1`,
`identity-risk-evidence-bearer-v1` and `identity-risk-evidence-lookup-v1`.
Phone/network/preauth/attempt values enter scoped keyed intent only, not journal
columns. Key retirement requires the future adapter's retained tombstone and
pending-command checks; removing keys early is not supported rotation.

**Development boundary:** core execution/outcome tests use a native boundary
double, not PostgreSQL proof. The real `risk/postgres` executor, complete canonical
Service/catalog reconciliation, provider interoperability, audit/retention and
durable reservation/consumption are still unfinished. Do not deploy this partial
module or supply an application-written executor as a substitute.

### Native CAPTCHA replay-key continuity

`CaptchaEvidenceCustody.ReplayKeyCustody()` supplies bounded, copied native
provider-scope key commitments, never secrets or issuance authority. The durable
adapter must serialize scope retention and compare both version and commitment;
neither a new fingerprint nor a key-version label proves safe key rotation.
New native configuration commitments bind the originally referenced replay-key
secrets. Adding retained keys preserves original signed aliases and validity.
Historical v1 signed configuration remains readable without rewriting its bytes;
the adapter's populated-state upgrade requires the original reviewed retained
key configuration, which cannot be inferred from token-free history. Early
retirement or replacing a retained secret under its old version is unsupported.
Automatic formatting redacts both projections and serialization is denied.

### Phone-recovery carrier subset

`NewCarrierEvaluator` is disabled with zero startup configuration. Explicit
enablement requires one version-pinned owner for each of SIM-swap, number
recycling and carrier checks, a trusted clock, a positive policy version,
bounded deadlines and a selected lifetime of at most two minutes. Construction
does not read providers. Request input contains no carrier facts or purpose.

`Assess` checks complete trusted tenant/subject/number/preauth/attempt/policy
scope and the exact issuing-phase/parent-operation pair before any reader.
`PhoneRecoveryScope` and `CarrierObservation` are preparatory helper contracts,
not replacements for the canonical Service's `PhoneRecoveryBinding` and
aggregate `CarrierFact`. The carrier owner uses the canonical `carrier-risk`
tag; SIM-swap and number recycling retain distinct mandatory owner tags.
Initiation derives `phone-password-reset-initiate`; completion derives
`phone-password-reset-complete`. It evaluates all three readers once and denies
positive, unknown, unavailable, malformed, foreign or failed results. Every
original interval is rechecked after the last reader. Earliest original expiry
wins, and metadata copies cannot extend it. Provider configuration versions
must match the configured owners; refresh/replay cannot restart observation.

The opaque assessment must be validated against the issuer's expected evaluator
and exact binding, with exclusive expiry. It is **only the carrier subset**:
no durable row, bearer or RiskEvidence is issued, and it cannot replace full
risk/counter policy, OTP/capability, independent factors or transactional one-use
consumption. Official carrier readers and provider interoperability remain
required; this API is not an application-written recovery workflow. Stored
evidence/journal mappings must derive bounded keyed phone linkage rather than
persisting the raw trusted number in this in-memory input.

Native adapters installing the pure `PhoneEvidenceIssuer.RecheckUse` must first
use `ValidateUseConfiguration` at setup to match the issuer's policy and entire
retained key set, including both independent secret lanes. Key order is
irrelevant; missing, duplicate, changed or foreign lanes deny with
`ErrInvalidPolicy`. This comparison performs no IO, callback or time sampling,
retains no input slice, and grants no evidence-use or domain authority. Native
current-state, journal/counter and atomic-finalization checks remain required.

Neither `ServerVerified`, `IndependentFactor`, timestamps nor these structural
values prove provenance. They may only be supplied by owned trusted server
orchestration, not request fields. No assessment grants authentication,
authorization, current authority freshness, proof consumption or permission to
execute an effect. This partial module must not be installed as the complete
security middleware; real configured sources, durable journal/counter owners
and protected transaction phases must be completed first.

Inputs/results contain no raw network/provider/credential material. Context and
signal formatting redacts correlation data. All errors are stable and omit
input; callers own their original values and must not log or retain them.
Policy owns independent copies of configuration slices, needs no shutdown,
starts no goroutine and supports concurrent immutable use. Assessment input must
not be concurrently modified. Standard Go memory-erasure guarantees apply.

## Catalog provenance and updates

`catalog_generated.go` records SHA-256 identities for the owned MIT-licensed
`PUBLIC_CONTRACTS.json` and `REFERENCE_CONFIGURATION.md` planning sources.
The pinned canonical operations and explicit native classifications in
`native_operations.json` are each assigned exactly one explicit profile or
closed fallback. Compiled numeric values are validation ceilings, not deployment
defaults. Public GET fallbacks are neutral discovery/availability reads; SSO
discovery remains an authentication fallback and denies. All sensitive reads
and unclassified mutations conservatively deny.

OAuth consent continuation (`identity.oauth-server.continue`) uses the existing
Privileged profile, like authorization, token exchange and revocation. It
requires actor/resource/network-bound counters in the owning transaction; clean
provider facts alone are not consent or issuance authority. Native entries may
fill an omitted matrix classification, never override an explicit pinned class.

Explicit invitation expiry (`identity.organization.invitation.expire`) uses the
same Privileged reservation profile as invitation cancellation. It requires
complete current provider signals and transaction-owned tenant, actor,
invitation-resource and network counters. Assessment and preparation confer no
organization permission or durable expiry; the native organization owner must
still prove current administrator authority and atomically finalize the effect.

Organization domain reservation and withdrawal use that same Privileged
transaction profile, scoped to the exact organization resource. They do not
verify a domain, authorize its ownership or permit SSO routing. Domain reads,
verification and unlisted aliases do not acquire this mutation admission.

Regenerate from the selected current planning snapshot, then format the output:

Authenticated `identity.passkey.list` explicitly uses the StateNeutralRead
tenant/subject counter profile, matching API_OPERATIONS.md's safe/read contract.
It is not public discovery: the passkey owner separately authenticates the
session and authorizes the exact self-user before reading safe metadata.

```sh
ruby ../scripts/generate-risk-catalog.rb PUBLIC_CONTRACTS.json REFERENCE_CONFIGURATION.md
```

The script emits Go source to stdout; installing output is a reviewed source
change. Review every new operation's fallback, authorization and mutation
semantics and the source-profile ceilings; HTTP method alone is not an enduring
authentication/security classifier. Changing policy never renews signal times.

The distinct `identity.email.verification-signin` native command uses counted,
audited Authentication admission. Its earlier verification command and managed
address confirmations remain CredentialMutation operations. The generator binds
the native additions' source checksum as well as both historical source inputs;
adding this signin profile does not change unrelated classifications.

## Verification and tradeoffs

Use `go test ./...` and `go test -race ./...`; adversarial seeds cover exact
operation admission and scoped signal assessment. Provider interoperability,
durable integration, mutation and complete release gates are not proven by
these pure tests. The API is experimental and not released.

### FAQ

- Can an application supply a policy result instead of durable risk evidence?
No. Results are data and cannot substitute for the platform's one-use record.
- Does a deny revoke sessions? No; authorized response coordination owns that.
- Does this implement an ML engine or authorization service? No.
