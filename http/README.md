# Identity HTTP transport

Explicit `identity.mfa.disable` selection accepts only original stored-session
CSRF (`X-CSRF-Token`, exact Origin, no Referer fallback). It grants no general
mutation exemption, bearer fallback or renewable freshness. The optional
`http/mfa` module owns the actual disable handler and selected closed wire shape.

**Development checkpoint, not a complete identity HTTP product.** Go 1.27.
This independently versioned module currently owns server lifecycle, separate
health/readiness probe handlers, typed opt-in operation selection and bounded
ordinary request parsing, credential binding and trusted-network/tenant admission.
Dependencies are identity kernel, authentication and stable identifier contracts,
not feature implementations or the reference server.
Selected secure routing, CORS, real owner phase hooks and OpenAPI composition
are available. Complete domain/protocol handlers and their authentication,
authorization, cookie/CSRF and rate profiles remain required feature work.
This checkpoint is not a release-qualified complete identity endpoint platform.

## Selected secure router

Use `NewOperationDescriptors(FeatureServices{Features: selected})`, then
`NewRouter(TransportPolicy{Network: networkConfig, CORS: routePolicies,
HandlerTimeout: timeout, Document: DocumentConfig{Title: title, Version: version}},
operations, middleware)`. The returned handler and OpenAPI document share one
validated immutable operation snapshot. Empty selection exposes nothing;
metadata and probes are never implicit. The network policy includes all limits,
exact tenant/public host bindings, proxy prefixes and forwarding-hop bounds.
HTTPS is required; unknown hosts return 421. There is no route-prefix rewrite:
canonical, protocol and probe paths remain exact and root-mounted.

The router composes envelope/network admission, raw-body bounds, route-specific
CORS, exact dispatch and real feature-owned stages. It does not authenticate,
debit a rate bucket, serialize cookies or consume CSRF proofs a second time.
Use the same network configuration and shared domain/rate owners in selected
feature factories. Those factories must enforce their advertised controls;
metadata cannot certify an arbitrary supplied handler. CORS policy for an
unselected method/path is rejected. Preflight does no owner or hook work.

Nonempty middleware requires each selected handler to implement
`OperationMiddlewareBinder`; opaque handlers are rejected rather than receiving
invented authentication phases. All policy, descriptor and wire validation
precedes wrapper factories. Individual frozen-owner binding conflicts can still
fail construction; no partial router/document is returned. Owned probes support
global hooks at explicit public/no-auth boundaries without a principal or
ambient credential headers. Probe hook writers discard output: short circuits
produce fixed unavailable responses, never invented health/readiness. The real
readiness check runs at most once and original standalone handlers stay usable.
Bound hooks share `max(ProbeConfig.Timeout, 1ms)` as a whole-call budget while
readiness retains its original 1ns..2s bound; cancellation and drain are checked
again after hook unwind. No provider result or response is cached.

Responses retain `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`
and `Referrer-Policy: no-referrer`, including streaming and hook short circuits.
An unknown-length body overflow denies before a later response can claim success;
feature decoders must still validate body results before authentication/mutation.
The 1ms..30s whole-handler context never extends an inbound deadline. Use
`NewHTTPServer` for raw IO/write deadlines and connection/body ownership;
cooperative cancellation cannot terminate arbitrary caller code or prove rollback.
Precommit panics produce redacted 503; postcommit failures abort the response.
This selected-router checkpoint does not complete all feature handlers, protected
metadata, protocol/provider/browser journeys or release qualification.

## Explicit public metadata

`NewDocumentedHandler` never exposes a metadata endpoint. To explicitly expose
public metadata, use `NewDocumentedMetadataHandler` with `MetadataConfig`:
`Public: true`, an exact `NetworkConfig`, the shared `SafeRateLimiter` and a
positive 1ms..30s request budget. It serves only HTTPS `GET /openapi.json` on
mapped hosts, charges the canonical safe IP budget once and returns exact
validated document bytes. The endpoint describes itself in that same snapshot.
It rejects bodies, queries, retry keys and Authorization; cookies confer no
authority. No implicit HEAD, CORS or cache validation is enabled. Protected/admin
metadata remains full-router work: leave the endpoint off for that profile.
Construction never invokes handlers or readiness callbacks. Caller-owned wire
examples/descriptions must already be public; this is not a secret detector.

`OpenAPIDocument.OpenapiDocument` provides the typed side-effect-free direct
snapshot export, with its exact digest. `Coverage()` and `CoverageJSON()` export
a separate deterministic diagnostic inventory: all canonical obligations plus
selected extensions, honestly classified as selected, absent, direct-only,
middleware or unavailable shared-route variants. These do not certify runtime
implementation or full parity. The report contains disabled baseline names and
is not automatically embedded in OpenAPI or published over HTTP. Returned
storage is detached; snapshot exports and dispatch may run concurrently.

## Keyed secret-route admission

`NewKeyedSecretRateLimiter(KeyedSecretRateConfig{...})` selects canonical keyed
`rate.secret` operations only. Supply a borrowed native atomic
`rate-limit/v2.StrictAtomicBatchBackend`, immutable deployment namespace/key,
trusted clock and 1ms..2s bound. PostgreSQL requires atomic schema migration 2.
No per-item or emergency fallback is available. Pass trusted network facts,
the actual authenticated/capability subject and exactly the protected workflow's
original `identity.IdempotencyKey` in `KeyedSecretRateRequest`. If present,
challenge ID and immutable original lifetime must come from the challenge owner.
Never use client-claimed subjects, replacement retry keys or remaining TTL.

Every call debits IP10/10m, tenant/subject10/10m and optional challenge5/lifetime
as one command. Same key/tenant/subject/operation preserves original correlation;
changed IP/challenge conflicts with retained native intent rather than resetting
the command. Matching replay returns the original admission, not a new debit.
Proceed only on nil error and Allowed; domain authentication, authorization,
cumulative risk and transaction-safe proof consumption remain separately required.
Cancellation can deny continuation after a debit and does not prove refund.
Known denial uses the longest exhausted delay, ceiling seconds clamped1..3600.
Close after draining handlers; borrowed storage is never closed. Non-keyed secret
flows, real password endpoint composition and the remaining rate profiles are
still pending. Construction selects no routes or advertised capabilities.

## Password-verification admission

`NewPasswordVerificationRateLimiter(PasswordVerificationRateConfig{...})`
owns only the non-keyed `identity.password.verify` profile, not other verification
operations. Supply the borrowed native atomic rate backend (PostgreSQL atomic
schema 2), immutable deployment namespace/key, prompt trusted clock and 1ms..2s
bound. `Admit` accepts trusted tenant network facts and the actual current primary
subject in `PasswordVerificationRateRequest`. Never pass a request-claimed user.
No HTTP retry key or challenge exists for current-password verification.

Each attempt debits trusted IP20/10m and tenant/subject10/10m atomically. A fresh
server-native command counts repeated attempts; it does not reuse a workflow
command or permit caller-selected correlation. Unknown/outage/cancellation
denies without retry or local fallback. Continue only on nil error and Allowed;
the workflow still owns primary-session checks, cumulative risk, signing and
proof issuance. Cancellation may follow a debit and does not prove refund.
Known rejection returns the longest delay rounded to seconds, clamped1..3600.
Close after draining; the borrowed backend is not closed. Construction exposes
no endpoint or metadata.

## Issued-challenge verification admission

`NewChallengeVerificationRateLimiter(ChallengeVerificationRateConfig{...})`
uses the same atomic backend, namespace and key as password verification, so
IP and tenant/subject budgets are shared rather than reset by switching flows.
It selects canonical issued-challenge `rate.verify` operations only; it does
not install routes or authenticate bearer proofs.

For an HTTP attempt, call `AdmitIP` before proof processing. After the owning
workflow authenticates the original issuance, call `AdmitChallenge` with its
actual subject, original challenge ID and immutable policy lifetime (integral
microseconds, 1s..24h). Never derive these from JSON claims, a replacement challenge
or remaining expiry. The first phase debits IP20/10m; the second atomically
debits subject10/10m and original challenge10/lifetime. An IP debit is not
refunded when authentication or the second phase fails. Already-authenticated
direct callers may instead use `Admit` for all three dimensions in one batch;
do not combine it with the split phases for the same attempt.

Proceed only on nil error and Allowed. Native expiry, current authority and
stricter transaction-owned attempt limits still apply. Each phase uses fresh
server debit correlation, never HTTP retry keys or workflow command IDs.
Ambiguity, outage, cancellation and closure deny without retry or fallback.
Close after draining handlers; borrowed storage remains open. Identifier-only
challenges and endpoint adoption remain separate implementation work.

## Safe-route admission

`NewSafeRateLimiter(SafeRateConfig{...})` selects the fixed `rate.safe` catalog
policy, not arbitrary caller-supplied numeric overrides. Supply a borrowed
strong `rate-limit/v2.StrictBackend`, deployment key namespace, trusted clock,
bounded degradation recorder, positive 1ms..2s duration and bounded emergency
cardinality. Use one limiter per process/deployment namespace across all safe
routes. Close it after draining handlers; it closes only its local store, never
the borrowed backend. Copies share that store and terminal closure state.

Call `Admit(ctx, facts, operationID, authenticatedUserID)` with facts from
`NetworkResolver` and the user only from current session-owner admission. Empty
user means unauthenticated. Client input cannot select tenant, IP, user or policy.
The normalized full IP is limited to 100/minute in shared storage; authenticated
tenant/user is additionally limited to 300/minute. Atomic token buckets refill
continuously, without wall-clock window resets. Counters span canonical safe operations. An IP
debit is not refunded when a later subject decision denies or becomes unknown.

Only known shared unavailability enables the process-local 20/minute IP budget.
Unknown dispatch never becomes fallback permission. Every decided fallback
requires a bounded degradation event attributed to the operation; recorder
failure denies admission. The event's Allowed flag describes the counter
decision, not successful domain execution. Saturation fails closed rather than
evicting live budgets; on saturation, only counters idle for a full minute may
be reclaimed through the primitive. Earlier request deadlines remain effective.
Callbacks are synchronous and must honor their context; none run detached.

Proceed only on nil error and Allowed. `ErrRateLimited` carries a positive
`RetryAfter`; `ErrRateUnavailable` discloses no backend detail. An admission is
not authentication, authorization or a reusable lease. Exact HTTP status/header
mapping and session-handler integration remain pending. This checkpoint uses
committed primitive security revision `72dfa13dd0a6`, not released `v2.0.0`,
whose memory store can evict live counters. Published dependency resolution and
full release qualification are not established by local archive-backed tests.

### Original-flow, signup, sign-in and delivery policies

`NewAuthRateLimiter(AuthRateConfig{...})` selects canonical `rate.signup`,
`rate.signin` and `rate.delivery` operations from the same catalog. Supply a strong borrowed
backend, stable deployment namespace, independent nonzero 32-byte identifier
HMAC key, trusted clock and a 1ms..2s maximum duration. No emergency store or
degradation callback is used: outages and unknown outcomes fail closed.

Before starting a new tenant-bound browser flow, call
`AdmitOriginalFlow(ctx, facts)`: this applies the IP-only `rate.auth` bucket of
20/10m, shared across tenant hosts and owner instances in the same namespace.
There is no identifier or challenge yet. Do not use this method for an existing
flow or any operation with those dimensions; their applicable buckets remain
required. HTTPS/origin admission belongs to the handler, and rate admission
must precede flow entropy or durable writes. Original-flow, signup, signin and delivery
budgets are independent. This method does not register or advertise a route.

Call `Admit(ctx, facts, AuthRateRequest{OperationID: operationID,
Identifier: canonicalIdentifier, UserID: authenticatedUserID})`. Identifiers
must come from the owning workflow's canonical input or authenticated original
challenge custody. A client-claimed identifier unrelated to the challenge is
not suitable. The rate owner neither normalizes identifiers nor authenticates
subjects. HMAC key derivation length-frames profile, dimension, tenant and value;
raw identifiers and subjects never become backend keys or diagnostics.

Signup uses IP5/hour and tenant/identifier3/day, with no subject dimension;
signup requires mapped tenant facts and rejects a supplied UserID. For bounded
native normalization after IP admission, call `AdmitSignupIP` then
`AdmitSignupIdentifier` with the same owning workflow's canonical input. Do not
also call `Admit` for that request: full and split admission share the same
bucket identities. A rejected source lookup retains its earlier IP debit.
The one-hour retry ceiling never shortens the daily identifier refill period.
Neither admission method validates a flow, reads an account or permits signup.

Sign-in uses shared IP20/10m and tenant/identifier10/10m. Delivery uses shared
IP10/h, tenant/identifier5/h and authenticated tenant/subject10/h. All operations
in one profile share these continuously refilled budgets. Admission requires
every applicable bucket to allow. Per-bucket debits are atomic, but not one
cross-bucket transaction: earlier debits remain after later failure. Known
exhaustion checks remaining buckets for the longest retry delay, rounded up and
clamped to 1s..1h. No result is reusable authorization. Close after draining;
copies share terminal closure, and the borrowed backend is never closed here.
Other canonical rate profiles and actual OTP HTTP handlers remain pending.

## Start and stop

Construct `NewHTTPServer(ServerConfig{...}, handler)` with explicit address,
read-header/read/write/idle/handler/drain timeouts and a header limit. Construction
does no IO. `Start(ctx)` binds and **blocks** until serving/cleanup ends; callers
that run it in a goroutine must join its result. `Serve(ctx, listener)` transfers
listener ownership only after valid arguments and successful start reservation.
Use it for deployment-supplied TLS termination/listeners. Neither method owns
domain stores, pools or providers.

`Started()` closes on listener acquisition/admission, not dependency readiness.
Also observe the serving result: the channel remains open after startup failure
or pre-start shutdown. `Address()` explicitly returns the bound local address;
never put it in a public probe. `State()` reports lifecycle only.

`Shutdown(ctx)` refuses admission and gracefully drains under the earlier caller
deadline or configured drain. On cancellation/timeout it cancels request work
and closes owned connections; repeated calls retain its original result.
Shutdown before start is terminal. A reserved start, even failed bind, cannot
restart. An invalid/pre-cancelled start does not reserve ownership. Successful
ordinary shutdown returns nil from serving; owning-context cancellation returns
the original context error. Network failures return sanitized `ErrUnavailable`.

## Deadlines and security

Reusable durations must be positive and no greater than 24 hours; header bytes
must be 1024..65536. Handler timeout must not exceed write timeout. The reference
deployment's narrower reviewed bounds remain its composition responsibility.
There are no silently chosen production defaults. Handler context retains an
earlier inbound deadline, bounds response streaming, and interrupts blocked
request-body reads on cancellation without extending the read timeout.

Handlers must honor cancellation and release their resources. Go cannot kill
arbitrary caller code that ignores it. Connection closure/cancellation never
proves a domain mutation rolled back. No hijacking or detached handler work is
supported. `http.ResponseController.Flush` is supported inside the deadline;
the writer does not expose `Hijacker`, `ReaderFrom`, or `Unwrap` bypasses.
Raw standard-library panic/connection diagnostics are discarded because they
can disclose request values. No caller callback runs under the lifecycle lock.

Typed-nil `http.HandlerFunc` and a nil handler interface are rejected; arbitrary
handler implementations must be valid usable values. No reflection-driven
handler introspection is performed. Supplied listeners must implement prompt
Close/Accept interruption; callers retain rejected listeners. Deployment owns
TLS credentials and protocol negotiation; no TLS or outbound provider policy
is inferred here.

## Health and readiness

`NewProbeHandlers(ProbeConfig{State: server.State, Readiness: provider,
Timeout: time.Second})` returns separate handlers. Register them only at
`/healthz` and `/readyz` on a private mux before starting the server, as shown
in the executable example. Construction never calls the provider or lifecycle
callback. Timeout is explicit, positive and at most two seconds; earlier
request deadlines win. Callbacks must be prompt/concurrent-safe and readiness
work must cooperate with cancellation. No goroutine is detached to impose a
timeout on code that ignores cancellation.

Only exact GET requests are accepted: no implicit HEAD, escaped/trailing-slash
aliases, query strings, bodies, trailers or `Idempotency-Key`. Wrong paths
return 404; wrong methods return 405 and `Allow: GET`; nonempty requests return
400. Every response has `Content-Type: application/json`, `Cache-Control:
no-store` and `X-Content-Type-Options: nosniff`. HEAD rejection has no body.

Liveness returns 200 and `{"status":"alive"}` without consulting state or
dependencies. Readiness returns 200 and `{"ready":true}` only when the server
is running before and after an affirmative composed check, with no blocking
codes, errors or expired context. All other readiness outcomes return 503 and
`{"ready":false}`. Fixed bodies end in a newline. Error bodies are the fixed
`{"error":"not_found"}`, `{"error":"method_not_allowed"}` or
`{"error":"invalid_request"}`; request/callback values are never reflected.

Composition owns actual dependency/migration/key checks; do not substitute
listener acquisition or an unconditional true callback in a real deployment.
The callback's internal codes and errors are never serialized. Optional-provider
degradation does not block readiness unless composition makes it mandatory.
No readiness result is a future lease. During drain the server may refuse
network admission or close its listener even though process liveness itself
does not depend on readiness. The handlers add no routes or global registry.
They do not yet implement canonical direct operations, route rate policy,
endpoint-manifest/OpenAPI bijection or complete reference readiness.

## Explicit feature selection

`NewDocumentedHandler(ctx, DocumentConfig{Title: "Identity", Version: "1"},
selection)` returns exact selected dispatch and immutable OpenAPI 3.1.1 from
the same snapshot. `document.JSON()` and `document.Operations()` return detached
exports. Empty selection advertises no routes or components. The real probe and
optional session factories supply separate `WireOperation` definitions; a
direct-contract summary alone is rejected. No document route is enabled
implicitly. The complete security-policy router and explicit metadata endpoint
remain separate required work.

Trusted extension factories may attach bounded `WireOperation` JSON and unique
schema/security components. The builder rejects malformed/duplicate JSON,
colliding components, unresolved/external references, invalid schemas and
missing definitions before returning a handler. Internal JSON pointers only
are supported: `$id`, `$dynamicRef` and external examples are excluded from this
self-contained profile. Schema compilation and normative validation use the
pinned Golib OpenAPI owner, with no network access. Construction has a five-second
budget that never extends the caller's deadline; no runtime dependency executes.
Canonical dotted operation IDs are deliberately preserved despite the owner's
programming-identifier portability advisory; client generators must map them.
All other diagnostics and saturated reports deny. This is not release or
generated-client qualification.

`NewSelectedHandler(FeatureServices{Features: selected})` freezes exact dispatch
of validated selected features. Empty selection returns 404 and advertises
nothing. There are no redirects, path cleaning, implicit HEAD/OPTIONS, prefix
matches or escaped aliases. Unsupported methods return 405 with a sorted Allow;
HEAD errors have no body. Selection/collision failures return no partial handler.
This root-mounted dispatcher preserves each feature's parsing, authentication,
CSRF, rate and outcomes; it does not repeat those checks or debit counters twice.
Use real owned feature factories or trusted extensions implementing their full
declared controls. `NewSelectedHandler` is not the planned complete
`NewRouter`/middleware/wire-OpenAPI builder. The server still owns bounded IO.

Owned optional factories use `NewCanonicalOperation(CanonicalOperationConfig)`
to bind real handlers to the embedded catalog without maintaining policy or
digest copies. Unknown/nonrouted operations and incompatible owner/policy/schema
bounds deny. Returned schema summaries describe direct Go contracts, not HTTP
wire schemas. For self-signout and password change, `CSRFNone` means an explicitly
selected bearer handler; `CSRFSessionState` means exact cookie Origin and the
active-session token. Only self-signout permits absent/inactive origin-only
success; password change always requires an active session. The latter binds token lifetime to
active stored session state and claims no independent maximum-age enforcement.
Factories retain responsibility for selecting and enforcing the matching mode.
Password verification additionally permits explicit `CSRFNone` for a strict
bearer handler or `CSRFSessionState` for a cookie handler backed by native
stored-synchronizer protection. The cookie profile requires its configured
token header, denied Referer fallback and no independent token-age claim.
Factories must enforce the selected custody and native protection; canonical
metadata recognition alone selects no endpoint or authenticates a request.
Conditional pre-auth/session canonical rows also permit an explicit
`CSRFExactOrigin` with denied Referer fallback for a pre-auth-only selected
handler. That handler must reject session/MFA variants, never infer pre-auth
authority from ambient session credentials, and describe its restricted wire
profile. Session-only rows cannot select this narrowing. Full conditional
selection and its token requirements remain unchanged.
`SafeRateLimiter.Configured()` rejects nil/zero/closed owners without IO; true
is not backend health or future admission and may race with Close.

`NewOperationDescriptors(FeatureServices{})` returns no operations. Nothing is
enabled by importing this module. `NewProbeFeature` contributes the two real
probe handlers; pass the resulting feature in `FeatureServices.Features` to
select them. Other feature owners contribute handlers with `NewFeature`.
This constructor validates metadata; it does not supply missing domain handlers.

Feature dependencies must all be selected, in any order. Missing dependencies,
cycles, duplicate feature/operation IDs, exact method/path collisions, and
component-name or schema-ID collisions reject the entire selection with
`ErrInvalidInput`, without partial output. Canonical operations must retain
their catalog ownership, transport policies and public-contract content digests.
Custom operations use `extension.<owner, replacing slash with dot>.<suffix>`.
Direct-only and middleware operations cannot become routes through this API.

Input and output metadata are detached snapshots, sorted by operation ID;
mutating a returned slice does not change the feature. Handlers are borrowed,
not cloned: their owner must supply valid, concurrent-safe implementations.
Construction performs no IO or handler calls. Limits are 64 selected features,
1024 operations, 4096 components overall, and 64 components per operation.
See the public type documentation for individual field bounds.

`RatePolicyID` identifies a complete canonical policy, including multi-bucket
requirements; selection does **not** enforce it. `TypedSchema` binds a declared
contract and digest, not a rendered JSON Schema. Selected descriptor summaries
are not an OpenAPI document or proof of route security. The secure router,
shared-token-route dispatch, OpenAPI renderer and domain feature contributions
remain required subsequent work. The embedded canonical catalog is a validation
input, not an advertised list of implemented endpoints. Regenerate it from the
active planning snapshot with `scripts/generate-http-catalog.rb`; the generator
records source provenance and does not claim handler completion.
Contract digests use recursively key-sorted compact JSON followed by one LF;
they do not depend on a pretty printer's empty-collection formatting. Run
`ruby scripts/generate-http-catalog_test.rb` from the repository root for the
fixed empty-collection digest oracle.

The generator accepts an optional fifth `NATIVE_CONTRACTS.json` input for
new native-owned operation/semantics/type definitions not yet present in the
preserved planning snapshot. Duplicate operation/type authority is rejected
before replacing output; existing rows are not overridden. The pending-email
OTP recovery source is `otp/email_verification_contracts.json` at repository root:

```sh
ruby scripts/generate-http-catalog.rb \
  "$IDENTITY_PLAN/API_OPERATIONS.md" "$IDENTITY_PLAN/OPERATION_SEMANTICS.json" \
  "$IDENTITY_PLAN/PUBLIC_CONTRACTS.json" /tmp/identity-http-catalog.json \
  otp/email_verification_contracts.json
```

Review generated differences against the embedded native baseline before
adoption. A newer planning input can also contain unrelated changes; registering
one native operation does not authorize replacing previously retained contracts.
The checked-in catalog retains those original rows and their source provenance
alongside the new native source identity. It advertises no unselected handler.

## Bounded ordinary request parsing

Construct one `NewRequestDecoder(Limits{...})` with every bound explicit.
`DecodeJSON[T]` accepts one JSON object, validates its structural/resource
boundary, then decodes into the chosen public or feature-owned input type.
Duplicate and case-alias member names, escaped aliases, invalid UTF-8 or
unpaired surrogates, trailing values and unknown typed fields deny without
returning a partially populated value. JSON's standard field matching otherwise
applies. Caller-supplied custom unmarshaling is trusted code and must cooperate
with cancellation; it runs only after structural validation.

Root nesting depth is one. Field budgets count object members and array elements
across the entire document. Decoded byte budgets include unescaped UTF-8 keys,
string values and scalar lexical bytes, not punctuation or whitespace. Raw
bytes have a separate ceiling. `Form` parses only the urlencoded body; `Query`
parses only `URL.RawQuery`; neither merges cached request forms or the other
channel. Empty form/query is valid, a missing equals sign means an empty value,
and empty names/segments, bare semicolons, invalid percent encoding or UTF-8,
duplicate/case-alias names and idempotency-key alternatives deny atomically.

## Credential header binding

`RequestDecoder.IdempotencyKey` returns the existing opaque kernel key and a
presence flag. It preserves exact header bytes under the generic 1..256-byte
HTTP-token grammar, without normalization, hashing or retry-state management.
`HeaderRequired` is for keyed commands; `HeaderOptional` preserves explicitly
optional protocol extensions; `HeaderForbidden` (zero) rejects even empty
header presence. Unknown policy values reject as configuration errors.

`RequestDecoder.Bearer` returns the existing authentication credential, not a
verified principal. Its selected grammar is case-insensitive `Bearer`, exactly
one space, and 1..8192 ASCII letters/digits or `-._~+/`, with optional trailing
`=` padding and at least one non-padding byte. The envelope limit may impose
a smaller ceiling. Session token parsing remains the session owner's stricter
profile. Forbidden mode supports bearer issuance rejecting Authorization.

Both helpers reject duplicate/case-alias headers, enforce the envelope and
never read or close the body. Query/cookie/trailer retry-key alternatives deny;
bearer query alternatives and Proxy-Authorization deny. Ambient cookies never
provide bearer authority. Call the appropriate body decoder as well: header
extraction alone cannot prove absence of body alternatives. Multipart/protocol
codecs, route-derived policy, trusted proxy provenance, prevention of middleware
credential injection and full routing remain subsequent work. A syntactically
valid header cannot reveal whether an upstream proxy replaced it.

`RequestDecoder.CookieBearer` acquires one exact case-sensitive cookie into
the same opaque bearer type. It rejects Authorization/proxy credentials and
selected-name query alternatives rather than choosing a fallback. All Cookie
lines share 16KiB/32-part bounds; malformed siblings reject. The selected part
is unique, unquoted and at most 3800 bytes including its name. Original value
bytes are unchanged. Optional/required/forbidden policy applies to that selected
cookie only. Owning session/flow services still validate their token format,
possession and current authority. This helper creates no flow, route or session.

`RequestDecoder.AuxiliaryCookieBearer` explicitly acquires auxiliary custody
alongside one syntactically valid direct Authorization bearer. The primary
credential is still authenticated by its owner; the cookie must never serve as
a session credential or fallback. Proxy/query alternatives deny. It shares all
strict cookie limits above without modifying the request or weakening
`CookieBearer` exclusivity. Use it for explicitly selected signed browser-device
correlation, then validate that provenance with the session device codec.

## Envelope and body ownership

Media types are explicit `application/json` or
`application/x-www-form-urlencoded`, optionally with only UTF-8 charset.
Compression is absent or explicitly identity, never implicitly decompressed.
Duplicate sensitive headers, inconsistent lengths, unsupported transfer
metadata, trailers, and oversized represented headers/URLs reject before body
reads. Chunked bodies are supported through net/http's parsed transfer metadata;
the decoder is not a replacement for wire-level server framing validation.
Header accounting includes each represented name, colon/space, value and CRLF,
final CRLF and the separately represented Host. URL accounting covers the
represented origin-form request URI and rejects conflicting RequestURI/URL.
Trusted host/proxy semantics require the network resolver below. Origin admission
is separate; token-bound CSRF/CORS and router enforcement remain unfinished.

Bodies are borrowed: the server or direct caller closes them. Reads consume at
most the applicable raw or declared-length bound plus one byte, and do not
drain excess input. Earlier request cancellation wins; an arbitrary caller body
that blocks without honoring server deadlines cannot be forcibly interrupted by
this synchronous API. Returned `DecodeError` retains no raw input or reader
diagnostic. No parser authenticates a credential or performs domain work.
Trusted credential routing, protocol-specific and multipart decoding, router
status/error integration and complete endpoint verification remain pending.

## Trusted network and exact tenant admission

`NewNetworkResolver(NetworkConfig{...})` copies one immutable deployment policy.
Supply explicit decoder limits, 1..16 maximum forwarding elements (reference 8),
at most 128 canonical masked proxy prefixes and 1..1024 total exact host bindings.
Empty proxy prefixes trust none. Duplicate or IPv4-mapped prefixes reject;
overlapping prefixes are an explicit set union. Tenant/public hosts cannot overlap.
Configuration hosts must already be canonical and port-free; Unicode request
hosts use the identifier owner's fixed Unicode 15.1 nontransitional UTS46 tables.
DNS names are lowercase ASCII, IPv4 dotted decimal and IPv6 bracketed canonical
text. Wildcards, trailing dots (including mapped Unicode dots), unknown hosts
and suffix-derived tenants deny. Numeric/hex-looking final DNS labels also deny
to avoid browser legacy-IPv4 reinterpretation; use canonical IP literals instead.

`Resolve(request)` returns opaque `NetworkFacts` or zero facts with an error.
An untrusted socket peer ignores forwarding semantics and uses its actual IP,
request Host and TLS state. A trusted socket peer requires exactly one
`Forwarded` map key and value. The selected closed RFC 7239 subset requires:

- At most the configured elements and 16 parameters per element; no empty
  elements/pairs, duplicate case-insensitive names, or whitespace around `=`.
- A concrete unicast `for` address in every element; optional `by` must also
  be concrete. Unknown/obfuscated identifiers and ports, zones, unspecified
  and multicast addresses deny. Quoted IPv6/IP-with-port syntax is supported.
- All chain syntax is validated, including attacker-controlled prefixes. Walk
  right-to-left through trusted senders to the first untrusted `for` address.
  That element alone must supply both valid `host` and `proto=http|https`.
  Never borrow earlier host/proto or fall back to the proxy/direct host.
- Unknown extension parameters are syntax-checked but supply no authority.
  Quoted separators and escaped quote/backslash are handled as data.

All `X-Forwarded-*` semantics are ignored, not combined with `Forwarded`.
Missing, malformed, duplicate or exhausted trusted chains return sanitized
`ErrUnavailable`; invalid envelope/host or an unmapped host returns `DecodeError`.
Cancellation preserves its context error. Parsed header limits still apply to
ignored fields. No DNS, body reads, goroutines, stores or domain callbacks occur.

`ClientIP()` returns the full canonical unicast address, unmapping IPv4-mapped
IPv6 with no subnet aggregation. `Host()` is the exact port-free map key;
`Authority()` preserves a validated explicit decimal port. `Origin()` omits
only the scheme's default port. `Realm()` explicitly distinguishes `RealmPublic`
from `RealmTenant`; only the latter has a `TenantID()`. A query/body/header tenant
cannot override that binding. Facts are redacted in ordinary diagnostics and
cannot serialize implicitly; getters deliberately disclose metadata to trusted code.

Resolve once for each owned request before tenant-scoped work. Facts are neither
authentication proof nor a reusable authority lease. Server composition owns
RemoteAddr/Host/TLS/header custody: arbitrary in-process requests or mutating
middleware cannot establish provenance. Reload by replacing a newly validated
resolver, not mutating configuration. Routing, rate enforcement, cookies and
token-bound CSRF/CORS integration remain required subsequent work.

## HTTPS origin admission

`NewOriginGuard(OriginGuardConfig{...})` borrows the immutable network resolver
and copies 1..128 distinct trusted origins. This profile requires canonical
HTTPS origins: lowercase ASCII/IDNA hosts, no default port, path, query,
fragment, userinfo or wildcard. Configuration and Origin header values are
rejected rather than repaired when noncanonical. Nondefault ports are distinct.
Extension and local-HTTP deployment profiles are not yet supported.

`Check(request)` resolves the current network facts and requires one exact
allowlisted Origin. A present empty, malformed, duplicate or untrusted Origin
never falls back to Referer. Zero fallback and `RefererFallbackDeny` both deny
an absent Origin. Only explicit `RefererFallbackSameOriginHTTPS` admits one
absolute HTTPS Referer with an origin equal to the current trusted effective
origin **and** the allowlist. Referer path/query is permitted; userinfo and
fragments reject. Referer origins normalize ASCII host case/default ports through
the same fixed identifier policy, never by suffix or cross-origin trust.
Referer path/query bytes must satisfy RFC 3986 URI grammar; raw characters such
as `|` and malformed percent escapes deny, while encoded equivalents remain valid.

`CheckBound(request, initiatingOrigin)` additionally compares the exact validated
origin to the workflow's stored binding. It does not validate or consume that
workflow's state, nonce, PKCE, continuation or one-time token. Both methods
return an empty origin on failure, retain cancellation/network classifications,
and never read/close the body or mutate the request. Invalid origin evidence
returns redacted `OriginError`; envelope errors retain `DecodeError`.

Admission alone is not complete CSRF protection, authentication or authorization.
Cookie mutations still require session-bound tokens. Token-bound CSRF and
secure router integration remain separate work; consumers must not expose
unprotected operation handlers directly.

## Exact-route CORS admission

`NewCORSHandler(CORSConfig{Network: network, Routes: policies}, next)` validates
and copies up to 1024 distinct exact method/path policies. Each route explicitly
selects `CORSNoCredentials`, `CORSCookieCredentials` or `CORSBearerCredentials`;
incoming cookies never select or widen the mode. Empty origins disable CORS
for a route, requiring empty header/exposure lists and zero max age. Empty
Routes disables cross-origin access entirely. Configured origins follow the
same canonical HTTPS profile as `OriginGuard`, without Referer fallback.

Enabled routes require 1..128 exact origins, up to 64 distinct case-insensitive
allowed/exposed header tokens each (128 bytes per token), and whole-second max
age in 0..24 hours. Wildcards and exposed Set-Cookie/Set-Cookie2 reject. The
reference composition retains its narrower fixed origin/header profile.
There is no global method grant: preflight selects the requested exact route
and uses only its origin, method, header and credential policy. Missing or
ambiguous control fields, private-network requests and unsupported headers deny
without handler, authentication, quota/state consumption or body reads/closes.

Ordinary requests without Origin or from the current effective origin remain
usable even with CORS disabled, but receive no grants unless explicitly allowed.
Cross-origin requests require exact method/path and origin membership; unknown
routes deny. This behavior is not CSRF proof. The wrapper resolves current
network facts itself, never using cached/caller-submitted facts or arbitrary Host.
It passes the original borrowed request to `next`, using a detached bounded
header map only for the existing generic Fetch CORS engine.

Response controls remove all case aliases of downstream CORS grants and restore
only the approved snapshot before ordinary status/write/flush/ReaderFrom paths
and after header-only return. Vary preserves initial and downstream dimensions
plus Origin; preflights additionally vary by requested method and headers.
Bearer-mode responses and all preflight/denial responses force no-store, even
without Origin. Denials return a fixed bounded redacted response with no redirect
target. Cancellation denies before handler admission. The wrapper starts no
goroutines, does no IO and does not buffer response bodies. Trusted downstream
code must not unwrap/hijack the writer to bypass transport controls.

This exact-path standalone foundation is not the secure router. Actual descriptor
binding, parameterized route selection, authentication/authorization, cookie and
token CSRF, protocol flows and browser journeys remain required integration work.
Do not treat CORS grants as permission to expose unprotected domain handlers.
`ExampleNewCORSHandler` demonstrates separate cookie/bearer policy and preflight
without invoking the supplied handler.

## Exact HTTPS redirects

`NewRedirectGuard(RedirectGuardConfig{Network: network, Targets: targets})`
copies 1..128 distinct full HTTPS URLs, each at most 2048 bytes. The immutable
network owner supplies fixed host syntax only; redirect destinations need not
be served hosts. Scheme and authority must already be canonical, without an
explicit default port. Wildcards, fragments, userinfo, backslashes, malformed
escapes and non-URI raw characters reject during construction.

`Check(ctx, target)` returns the original target bytes only on full equality.
Path, percent-escape spelling, query order and empty-query markers are distinct;
the guard never repairs, resolves or serializes a URL to obtain a match. It
never consults request headers, emits Location or appends response parameters.
Denial returns an empty string and redacted `OriginError`; cancelled contexts
retain their error. Invalid guard/context returns `ErrInvalidInput`.

Construct a guard per registered policy owner. A union of clients' redirect sets
is not client-specific registration validation. Admission does not establish
tenant, client or initiating-flow binding, consume state/nonce/PKCE or authorize
arbitrary parameter appends. Owning protocol workflows still perform those
checks and construct their responses. Never send even an OAuth error redirect
to a denied target. This HTTPS foundation does not implement native-application
or loopback HTTP exceptions, browser redirect journeys or full secure routing.

## Cookie-mutation CSRF input

Construct `NewCSRFDecoder(CSRFDecoderConfig{Origins: origins, FormField:
"csrf_token"})` with an explicit immutable origin guard and form-field name.
There is no default field. Names are lowercase ASCII identifiers, 1..64 bytes,
starting with a letter; idempotency-key names are reserved. The fixed header is
`X-CSRF-Token`. This profile is selected by trusted cookie-route composition,
not by inspecting an inbound Authorization header or Cookie.

The opt-in session feature calls `DecodeCSRF(decoder, request,
session.ParseCSRFToken)`. Base HTTP does not import session. The parser is a
trusted synchronous, bounded, no-IO credential constructor, not an arbitrary
authentication callback. Errors return no credential or form data; parser
diagnostics and token values are never reflected. Cancellation is preserved.

Only exact POST, PUT, PATCH and DELETE are supported. Origin admission and
bounded envelope/query decoding precede token parsing. Exactly one canonical
43-byte unpadded base64url token must arrive through the fixed header or the
configured URL-encoded form field. Duplicate/case-alias/query channels and
header/form coexistence deny even when values agree. Cached Form/PostForm are
ignored. Forms are read under the configured limits even with a header; success
returns remaining form fields without the token. JSON requires the header and
remains unread for the owning strict typed decoder, which must reject undeclared
body credential fields before any domain work. Multipart is not supported.
Body interruption and borrowed ownership follow `RequestDecoder.Form`; this
helper does not close or drain the body or start background work.

Successful input admission is **not** authentication or a session-validity lease.
The feature must pass the opaque token to session PostgreSQL `RequireCSRF` with
the frozen original session in the protected transaction, retaining primary
fences through protected work. Token age metadata is not enforced here; no
timestamp, freshness or authority is invented. Safe methods, bearer-only routes,
pre-authentication, origin-only and bound-origin flows use separate profiles.
This helper does not install routes or replace that feature-owned integration.
The external consumer fixture in `testdata/sessioncsrf/composition_test.go`
exercises the public HTTP/session seam without adding a base-module dependency.

## Tradeoffs and FAQ

**Why is Start blocking?** Startup/bind errors and the final serving outcome have
one explicit return owner. A caller choosing concurrency must retain and join it.

**Can a stopped instance restart?** No. Construct a new owner so terminal cleanup
and shutdown results cannot be confused with another listener generation.

Canceled requests cannot emit successful responses or credentials. Before any
response commitment, an owner may synchronously return one explicit 503 with
its safe original command status, bounded to 16KiB. Only content type, retry
and transport-owned CORS headers survive; cookies, CSRF fields and trailers do
not. Oversized canceled outcomes and cancellation after response commitment
abort the connection. This does not retry work, extend deadlines or guarantee
delivery to a disconnected client; retain the original recovery correlation.

**Does cancellation undo a command?** No. The domain owner must reconcile any
possibly committed mutation before retrying; transport errors cannot decide it.

## API and verification boundary

`NewOperationPipeline[T]` is the feature integration seam for actual middleware
phases. A feature supplies its existing bounded decoder, authentication owner,
admission (authorization/rate/CSRF), domain handler and safe error mapper through
`OperationPipelineConfig[T]`. All five callbacks are explicit, including public
operations' no-auth decisions; no authentication or rate engine is added here.

Execution is decode → before-auth wrappers → authentication → after-auth wrappers
→ admission → before-handler wrappers → domain handler → after-handler observers.
Within a phase, unique numeric order fixes entry order and reverse unwind order.
Short circuit or error stops later stages; repeated `next` calls cannot repeat
the protected operation. `PipelineValue[T]` exposes the owner's typed state only
after authentication and only during the request. This is not a reusable proof.

Middleware receives detached metadata, no TLS/associated-response pointers and
no readable body. Feature callbacks
retain the original bounded snapshot, so middleware cannot rewrite the host or
credential inputs seen by those callbacks. After-handler wrappers run only after
normal, uncanceled handler return, with a read-only response facade: they observe an attempt,
not a guarantee of transaction commit. They cannot emit or replace a response.
Callbacks/wrappers are trusted synchronous code and must not retain requests,
spawn detached work, unwrap/hijack writers or ignore deadlines. Constructor callbacks
must do no IO. The server still owns raw IO and streaming bounds.
Precommit panics use the feature's safe error mapper; once output or streaming
has begun, panics abort the HTTP response rather than successfully completing a
partial result. No raw panic diagnostic is exposed. Neither path proves rollback.

`WithOperationMiddleware(handler, hooks)` appends selected router hooks through
`OperationMiddlewareBinder` at those same real phases. Pipelines retain frozen
callbacks/policy and copy the combined wrapper list; existing handlers remain
unchanged. Combined duplicate owner/name or phase/order fails before factories
run. Each new binding constructs its own wrappers, including existing ones, so
factory callbacks must remain side-effect-free and returned handlers must be
concurrency-safe. An empty hook list returns the original nonnil handler.
Opaque handlers reject nonempty binding; wrapping them outside cannot fabricate
an after-auth phase. Trusted integrations must preserve their response guards
around the bound pipeline. Binding is not full `NewRouter` qualification.

The pipeline does not itself resolve hosts, parse credentials, authenticate,
authorize or register routes. Existing direct feature handlers remain unchanged;
their adoption and the complete `NewRouter` policy binding are pending. Do not
wrap an already complete feature handler with a second authentication pipeline.

See Go documentation for `ServerConfig`, `HTTPServer`, lifecycle states and
classifiable errors. `ExampleHTTPServer` is an executable public adoption example.
Unit/network tests exercise timeout, listener ownership, graceful/forced drain,
failure and concurrent transitions. Complete route/security/parser/browser,
OpenAPI/client, exact coverage/mutation, interoperability and release gates
remain pending. This module is not marked verified.
