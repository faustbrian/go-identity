# Identity HTTP transport

**Development checkpoint, not a complete identity HTTP product.** Go 1.27.
This independently versioned module currently owns server lifecycle, separate
health/readiness probe handlers and typed opt-in operation selection. It
imports the standard library, no feature implementation or reference server.
Routes, parsers, authentication/authorization, cookies/CSRF/CORS, trusted
network/tenant resolution, rate controls, hooks and OpenAPI composition
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
