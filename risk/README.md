# Identity risk policy

This Go 1.27 module implements the first risk-core behavior: immutable canonical
operation admission, deterministic scoped assessment, bounded server-source
orchestration and phase-bound counter dispatch.
It is **not yet the complete risk service**. Durable counters, audit/journal
ownership, CAPTCHA/HIBP orchestration, overrides, lockout/recovery and one-use
RiskEvidence/CaptchaEvidence issuance remain required implementation work.

## Adoption and API

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
The 329 canonical operations are each assigned exactly one explicit profile or
closed fallback. Compiled numeric values are validation ceilings, not deployment
defaults. Public GET fallbacks are neutral discovery/availability reads; SSO
discovery remains an authentication fallback and denies. All sensitive reads
and unclassified mutations conservatively deny.

Regenerate from the selected current planning snapshot, then format the output:

```sh
ruby ../scripts/generate-risk-catalog.rb PUBLIC_CONTRACTS.json REFERENCE_CONFIGURATION.md
```

The script emits Go source to stdout; installing output is a reviewed source
change. Review every new operation's fallback, authorization and mutation
semantics and the source-profile ceilings; HTTP method alone is not an enduring
authentication/security classifier. Changing policy never renews signal times.

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
