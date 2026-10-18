# CaptchaFox Free adapter

Experimental, Go 1.27. This independent module implements one CaptchaFox
Siteverify Free profile. `Verify` returns bounded native/neutral provider facts;
`Observe` is directly assignable to `risk.CaptchaEvidenceIssuerConfig.Verify`.
Neither method issues permission, reusable evidence or a policy decision.

## Public composition

`New(Config, *httpclient.Client, clock.Clock)` constructs a concurrent client
without IO. The [compiled example](example_test.go) shows the exact configuration
and callback. [Public tests](captchafox_test.go) exercise the actual bounded
POST/native response/risk callback, not only a parser or substitute authority.

Select provider `captchafox`, API `siteverify`, version `2026-08-11`, tier `free`,
API profile `siteverify/free`, configured sitekey/configuration generation and
canonical hostname set. Version is the preserved reference contract revision,
not a wire API version or current documentation date. ExpectedAction must be
empty because unsupported, not the reference text `unsupported`. Origins, cdata,
score/action binding, Enterprise insights and remote-IP disclosure are rejected.
No endpoint, secret, tier or policy default is inferred.

Endpoint must be exactly `https://api.captchafox.com/siteverify`. Supply a
non-secret User-Agent (1..256 visible ASCII including spaces), body budget
1KiB..64KiB, timeout 1..15s, lifetime 1s..2m, challenge-age bound 1s..5m, token
byte limit 1..8192 and concurrency 1..256. ChallengeMaxAge is explicit local
policy: the documented short provider validity interval has no numeric value
here. It is not copied from another provider or represented as a provider TTL.

## Wire and evidence contract

Each call makes one form POST with exactly `secret`, `response` and the
configured expected `sitekey`. Neither case-sensitive `remoteIp` nor `remoteip`,
command/flow identifiers, action or invented idempotency fields are transmitted.
No automatic retry, redirect following, token cache or coalescing occurs.
Tokens are single-use; an ambiguous exchange is not replay-safe. A new challenge
does not authorize retry under a fresh identity command. Risk alone derives
keyed replay identity and coordinates durable one-use issuance and consumption.

The Free parser accepts success, success-only challenge timestamp, optional
hostname and failure-only error codes. Present error codes on success are
inconsistent even when empty; challenge timestamps on failure are inconsistent.
Optional absent/present-empty fields remain distinct. Missing hostname or
challenge time cannot satisfy the configured positive binding/time checks.
Unknown fields, Enterprise insights, returned sitekey, action, score, origin,
duplicate/escaped-alias field names, invalid types and malformed tails fail
closed. Explicit non-JSON media types or non-UTF-8 charset declarations fail;
an absent header is allowed because the protocol does not require one, but the
same strict bounded JSON grammar still applies.

Only exact canonical lowercase ASCII DNS hostnames are configured; no suffix,
wildcard, Unicode, case folding or port substitution occurs. Configured site
attribution remains distinct from returned proof: the response has no documented
sitekey field. The immutable configured sitekey is sent to the provider rather
than invented in native evidence. Origin/action/score remain unavailable.

All seven documented error codes survive in redacted native evidence. Invalid
response, missing response and timeout-or-duplicate are rejected; secret/request
configuration failures are unavailable; invalid-ip-match is a binding mismatch,
not a claim that this non-disclosing profile sent a remote IP. Safe unknown code
tokens remain in native evidence, normalize to `unknown-provider-code` and yield
unusable malformed facts. Tokens are bounded to 1..64 lowercase-letter/digit/
hyphen bytes starting with a letter, at most 16 codes. This grammar is a local
diagnostic bound, not a claim that unknown future provider codes are supported.
No provider code proves a risk-owned durable replay-table transition.

429 is throttled; other non-200 responses unavailable. Transport errors and
partial bodies preserve unknown-consumption ambiguity. Every failed result has
zero usable expiry. Missing, future and exclusively expired original challenge
times fail; original observed-at and the earliest challenge/lifetime expiry are
preserved. Cleanup/telemetry crossing the original deadline cannot publish solved
facts. The provider's availability advice is not adopted as fail-open policy;
application/risk policy remains upstream.

## Ownership and privacy

The adapter copies 1..4096 visible-ASCII secret bytes after checking length,
borrows the caller token synchronously and preserves original opaque Flow and
canonical CommandID. Callers must not mutate borrowed data concurrently.
Only the supplied HTTP client's RoundTripper is borrowed, not its cookies,
headers, middleware, telemetry or redirects. Host transports must verify HTTPS,
honor context, support concurrency and never log or retain bodies.

`Close(ctx)` rejects new exchanges, cancels/drains active ones and clears retained
secret bytes, then closes only its isolated HTTP primitive. On timeout, call
again to await drainage. Borrowed host resources must outlive the adapter.
Transient byte buffers are cleared where practical; Go cannot guarantee erasure
of every runtime/string copy. No private credential store is created.

Formatting redacts config/results/native evidence; automatic serialization is
refused. Do not separately log token, secret, site, native codes or bodies.
Optional `Config.Observe` receives only closed exchange outcome, transport class
and duration before neutral binding normalization. Callbacks must be bounded,
nonblocking and concurrency-safe; panics are contained. Telemetry is neither
final risk policy nor canonical event delivery.

## Sources and qualification boundary

Protocol decisions follow the official [verification response and error table](https://docs.captchafox.com/en/getting-started#verification-response),
refreshed 2026-10-18. Test bodies are synthetic schema-derived fixtures with
verified local TLS, not captured provider traffic. The historical planning source
is `captchafox-siteverify-20260517115151`, archive revision `20260517115151`, SHA-256
`0aee0fcbe07c1905814a4e00261d1ca6dfa93233804028beea38601bc83ed028`; this is not a
newly downloaded fixture or an assertion that its old server page still contains
today's full contract. No live provider or documented test-key request was made.

For rotation/configuration changes, construct a new immutable client and drain
the old client. Local Close does not invalidate durable evidence. Risk/lifecycle
owners retain site disablement, configuration-generation and secret-rotation
effects. This adapter adds no policy, audit, replay, journal or lifecycle store.

Development uses a disposable external workspace for the neutral extension.
Delivery needs a real public neutral-extension pin and public-only child consumer
proof. Canonical events, durable/reference composition, provider interoperability,
full coverage/mutation, benchmarks and release/supply-chain qualification remain
separate pending work. No whole-unit or M35 closure is claimed.

## FAQ

**Can I enable Enterprise insights or action/score?** Not for this Free profile.
An independently evidenced contract is needed; no implicit fallback is selected.

**Can I omit hostname binding because the wire field is optional?** No. This
selected profile requires exact configured hostname evidence for usable facts.

**Does Close close my HTTP client?** No. Drain this adapter before shutting down
host-owned resources.
