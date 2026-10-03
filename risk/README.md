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

Without `Counters`, this source runner performs no counter mutation. It performs
no decision-journal persistence, required audit or evidence issuance in either
mode. It must not be used as complete middleware
or as permission to execute the selected operation. The later official adapter
composition must implement those owners; consumers must not supply private
domain stores or replacement workflow orchestration.

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
`reserve_with_owning_command` phases deliberately reject here until shared
transaction participation is implemented. No current workflow consumer uses
this partial path. Official PostgreSQL/Valkey adapters remain required; consumers
must not implement replacement domain stores to fill those gaps.

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
