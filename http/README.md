# Identity HTTP transport

**Development checkpoint, not a complete identity HTTP product.** Go 1.27.
This independently versioned module currently owns server lifecycle, separate
health/readiness probe handlers, typed opt-in operation selection and bounded
ordinary request parsing, credential binding and trusted-network/tenant admission.
Dependencies are identity kernel, authentication and stable identifier contracts,
not feature implementations or the reference server.
Routes, protocol parsers, authentication/authorization, cookies/CSRF/CORS,
rate controls, hooks and OpenAPI composition
remain required subsequent work. Do not deploy an identity endpoint from this
checkpoint without those transport controls.

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
Cookie mutations still require session-bound tokens. CORS, redirect policy and
secure router integration remain separate work; consumers must not expose
unprotected operation handlers directly.

## Tradeoffs and FAQ

**Why is Start blocking?** Startup/bind errors and the final serving outcome have
one explicit return owner. A caller choosing concurrency must retain and join it.

**Can a stopped instance restart?** No. Construct a new owner so terminal cleanup
and shutdown results cannot be confused with another listener generation.

**Does cancellation undo a command?** No. The domain owner must reconcile any
possibly committed mutation before retrying; transport errors cannot decide it.

## API and verification boundary

See Go documentation for `ServerConfig`, `HTTPServer`, lifecycle states and
classifiable errors. `ExampleHTTPServer` is an executable public adoption example.
Unit/network tests exercise timeout, listener ownership, graceful/forced drain,
failure and concurrent transitions. Complete route/security/parser/browser,
OpenAPI/client, exact coverage/mutation, interoperability and release gates
remain pending. This module is not marked verified.
