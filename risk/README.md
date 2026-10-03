# Identity risk policy

This Go 1.27 module implements the first risk-core behavior: immutable canonical
operation admission and deterministic, scoped mandatory-signal assessment.
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

## Security and ownership

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
