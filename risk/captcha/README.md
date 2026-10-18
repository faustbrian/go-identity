# CAPTCHA verification facts

Experimental, Go 1.27. This module supplies a stateless neutral verifier and the
exact callback consumed by the existing identity/risk CAPTCHA-evidence issuer.
Selected profiles are Turnstile Siteverify v0/free and reCAPTCHA classic
Siteverify v3/standard; transport adapters are independent nested modules.
Reserved hCaptcha and CaptchaFox members do not implement those providers.

`OutcomeSolved` is a provider fact, not permission to perform an operation.
The risk owner derives keyed replay identity, authenticates the original command
and flow, decides policy, and coordinates durable one-use issuance through its
official PostgreSQL adapter. This module owns none of those stores or transitions.
It accepts no caller-selected replay fingerprint and returns no evidence bearer.

## Public composition

- `New(Config, Verifier)` copies an explicit selected profile and borrows the
  bounded concurrent provider and clock. Invalid and typed-nil dependencies fail.
- `Client.Verify(ctx, VerifyRequest)` returns caller-bound native and normalized
  facts, including explicit availability, binding matches and transport failures.
- `Client.Observe` is directly assignable to
  `risk.CaptchaEvidenceIssuerConfig.Verify`. It projects only the upstream
  `CaptchaObservation` fields; native cdata/metadata stay in the neutral result.
- `Config.Capabilities()` reports the supported configured profile, or zero
  capabilities for an invalid configuration. Turnstile supports hostname,
  action, challenge time and provider transport idempotency, not origin or score.
  reCAPTCHA v3 adds score but has no provider idempotency or origin evidence;
  this module never compares scores to a policy threshold.

The [public consumer tests](verifier_test.go) construct the actual opaque
`risk.FlowContext`, preserve it and its canonical command ID unchanged, and assign
the callback to the committed issuer configuration. They do not replace durable
issuance or claim production-provider interoperability. The separate provider
adapter owns its POST/response/neutral/risk-callback tests.

## Configuration and ownership

The Turnstile selection is provider `turnstile`, API `siteverify`, version
`v0`, tier `free`, API profile `siteverify/v0`, plus an explicit public site key,
configuration version, canonical hostname set and expected action. Origins must
be empty and remote-IP disclosure must be false. Optional expected cdata binds
only when explicitly available. There are no inferred endpoints or defaults.

The additive reCAPTCHA selection is provider `recaptcha`, API
`classic_siteverify`, version `v3`, tier `standard`, API profile
`classic_siteverify/v3`. It requires hostname/action/challenge time and finite
score in [0,1] for solved evidence. A score of zero is still a provider fact;
only identity/risk owns score policy. Expected action is 1..64 alphanumeric,
slash or underscore bytes (Google's documented alphabet, within the reference
64-byte budget). Expected cdata, origins and remote-IP disclosure are forbidden.
V2 and Enterprise are not implemented. Its original challenge expires after at
most two minutes; the selected configured age may shorten that bound.

Timeout is 1..15 seconds, evidence lifetime 1 second..2 minutes, challenge age
1 second..5 minutes, token byte limit 1..8192, and concurrent calls 1..256. The
Turnstile adapter additionally bounds tokens to the provider's 2048-character
limit. Hostnames are exact canonical lowercase ASCII DNS names, never suffixes,
wildcards, ports or Unicode strings silently normalized by this module.

Tokens are borrowed only during the synchronous call and must not be mutated
concurrently. Provider callbacks and clocks are trusted, bounded, concurrent-safe
dependencies; they must not retain tokens or block beyond their contexts. The
neutral client owns no goroutines, provider shutdown, replay table, token cache,
audit queue or retry loop. Saturation rejects without queuing. The host stops
callers before shutting down borrowed provider resources.

Successful evidence retains original provider read time and exclusive expiry.
Expiry is capped by both configured lifetime and original challenge time. A
future or expired challenge fails; no positive clock-skew allowance is selected,
matching the risk issuer's existing challenge-time contract. Deadline expiry
during response cleanup or normalization cannot produce solved evidence.

## Failure and privacy contract

Typed `VerifyError` and stable `errors.Is` causes distinguish rejected token,
binding mismatch, unavailable, malformed, throttled, cancelled, ambiguous,
unsupported and overloaded outcomes. Every failure has zero usable expiry.
Bounded native facts remain attributable on supported failure paths, but raw
provider errors, unknown fields and response bodies never become diagnostics.
Provider-claimed match flags are replaced by local configured comparisons.

Absent optional fields stay unavailable; present-empty remains distinct. The
native union is closed, bounded and discriminator-checked. Arbitrary maps and
unrecognized provider data are not extension points. Request/result/evidence
formatting redacts automatic diagnostics and automatic serialization is refused.
Do not separately log tokens, cdata, remote addresses or provider bodies.

## Qualification boundary

Canonical CAPTCHA security events are pending the shared identity-event owner
prerequisite; this is not the complete canonical CAPTCHA service. No independent
event builder or durability authority is substituted. Reference/HTTP selection,
durable consumer integration, live provider qualification, complete coverage and
mutation/release gates remain separate work. Other providers, Enterprise,
origin profiles, remote-IP disclosure, endpoint overrides and browser UI
are not implemented by these profiles.

The historical planning constructor requiring a neutral transaction coordinator
and caller-visible replay fingerprint is not implemented: current ownership puts
those concerns in identity/risk and identity/risk/postgres. This module preserves
their actual public callback rather than introducing another issuance engine.
