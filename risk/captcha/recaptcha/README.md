# Google reCAPTCHA v3 adapter

Experimental, Go 1.27. This independent module implements only Google's web
classic Siteverify API, v3, standard tier. It returns bounded provider facts
through `Verify` and the existing `risk.CaptchaEvidenceIssuerConfig.Verify`
callback through `Observe`. It never issues authority or applies a score
threshold, allow/deny, step-up or outage policy.

## Public use

`New(Config, *httpclient.Client, clock.Clock)` constructs a concurrent `*Client`
without IO. Supply the exact endpoint
`https://www.google.com/recaptcha/api/siteverify`, secret bytes, non-secret
User-Agent, explicit response budget and neutral profile:

- provider `recaptcha`, API `classic_siteverify`, version `v3`, tier `standard`,
  API profile `classic_siteverify/v3`;
- configured site key and configuration version, exact canonical hostname set,
  expected action, and empty origins/cdata with remote-IP disclosure false;
- timeout 1..15s, lifetime 1s..2m, challenge max age 1s..2m, token limit 1..8192
  bytes, concurrency 1..256. No queue, defaults, fallback or policy threshold.

Use the [compiled constructor example](example_test.go) and
[public POST-to-risk-callback tests](recaptcha_test.go). The caller supplies the
original canonical command ID and trusted opaque `risk.FlowContext`; tokens
are borrowed synchronously, unchanged, and must not be mutated concurrently.
`Observe` is assigned directly to the issuer's `Verify` field. The risk issuer
alone derives keyed token replay identity and owns durable one-use issuance.

Only v3 is implemented. V2, Android, Enterprise, endpoint overrides, origin
evidence, cdata and remote-IP disclosure fail closed. Expected actions use
Google's alphanumeric/slash/underscore alphabet and the reference 64-byte cap;
comparison is exact and case-sensitive. Configured site key is configuration
attribution, **not provider-returned site-key proof**: Siteverify does not
return that field.

## Custody, transport and shutdown

The adapter validates the 1..4096-byte visible-ASCII secret before copying it.
The host retains ownership of its original slice and obtains credentials from
its approved secret manager. No persistence or secret-envelope format is
created. `Close(ctx)` rejects new exchanges, cancels/drains active calls and
clears retained secret bytes. If it times out, call again to await completion.
The borrowed HTTP client and RoundTripper remain host-owned.

Only the supplied HTTP primitive's RoundTripper is borrowed, not its cookies,
headers, middleware, telemetry or redirect policy. The transport must verify
TLS, honor context, support concurrency and never log or retain request bodies.
Every exchange sends exactly one bounded form POST with `secret` and `response`.
No remote address, site key, command ID, action or invented idempotency field is
sent. No automatic retry, redirect following, coalescing or token-result cache
exists. Google has no documented Siteverify idempotency contract: ambiguous
consumption is not retry-safe. A new challenge does not authorize replay under
a new identity command.

Responses are limited to an explicit 1KiB..64KiB before parsing. Partial reads
are ambiguous; 429 is throttled, other non-200 responses unavailable, and
unknown transport consumption never becomes a fabricated unused token. All
bodies close. Deadline expiry during cleanup or telemetry prevents solved
publication. Saturation rejects without waiting. Transient byte buffers are
cleared where practical; Go cannot guarantee erasure of every string/runtime copy.

## Native facts and failures

The parser requires complete strict JSON and rejects duplicate/escaped-alias
keys, unknown fields, invalid types, malformed tails and oversized fields.
The closed native envelope preserves success, original UTC challenge time,
hostname/action/score availability and values, and error-code absence versus
present-empty. Score must be finite [0,1]; missing v3 score/action cannot yield
solved evidence. A low score is still reported unchanged, never decided here.
Hostname/action mismatches remain attributable and unusable. Future timestamps
fail with no skew allowance. Exclusive validity is capped by both the original
challenge's configured age (at most two minutes) and original read lifetime;
projection never renews it.

Documented error codes remain distinct in native evidence. Secret/configuration
errors and `bad-request` are unavailable; response errors and
`timeout-or-duplicate` are rejected. That last code does not distinguish expired
from replayed and is not authoritative replay proof. Safe unknown code tokens
(1..64 lowercase-letter/digit/hyphen bytes, starting with a letter, at most 16)
remain only in the redacted native member, normalize to `unknown-provider-code`
and produce unusable malformed evidence. Arbitrary diagnostic text is rejected.
Every failed result has zero usable expiry. Errors retain only stable neutral
identities, never raw provider/network messages.

Automatic formatting redacts config/native/result custody and automatic
serialization is refused. Do not separately log secret/token/site/raw codes or
provider bodies. Optional `Config.Observe` receives only closed exchange outcome,
transport class and duration before neutral binding normalization; the host
owns bounded concurrent telemetry. Observer panic is contained. This is not
canonical verification/rejection/replay/binding-mismatch audit delivery.

## Protocol sources and qualification boundary

Protocol decisions follow Google's official
[verification contract](https://developers.google.com/recaptcha/docs/verify)
(page update 2024-10-14) and
[v3 response/actions contract](https://developers.google.com/recaptcha/docs/v3)
(2024-07-10), refreshed during implementation on 2026-10-18. Tests use synthetic
values derived from those documented schemas plus verified local TLS fixtures;
they do not call Google or claim credential/live-provider interoperability.
No v2 universal test key is represented as v3 score qualification.

The preserved protocol manifest identifies historical source
`recaptcha-siteverify-20260801153447`, archive revision `20260801153447`, SHA-256
`75c8e5cebc4d1002ed635aa20cc7f47a189d2e62c361d4382b5531c5f9a4c907`.
That is retained planning identity, not a newly downloaded fixture claim.

Development composition uses a disposable external workspace with the additive
neutral profile. Publication requires repinning this module to the actual public
neutral-extension commit and proving a public-only consumer. Canonical security
events, reference/durable integration, live provider qualification and complete
coverage/mutation/release gates remain pending with their respective owners.

## FAQ

**Can score 0.01 be solved?** Yes: solved describes validated provider facts,
not authorization. The risk owner compares score against its configured policy.

**Can another endpoint or Enterprise key be selected?** No; create a separately
reviewed profile rather than silently approximating a different protocol.

**Does Close close my transport?** No. Stop callers, drain the adapter, then
close host-owned HTTP/transport resources.
