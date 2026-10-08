# Identity HTTP transport

**Development checkpoint, not a complete identity HTTP product.** Go 1.27.
This independently versioned module currently owns server lifecycle only. It
imports the standard library, no feature implementation or reference server.
Routes, parsers, authentication/authorization, cookies/CSRF/CORS, trusted
network/tenant resolution, rate controls, hooks, probes and OpenAPI composition
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
