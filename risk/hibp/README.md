# HIBP password screening

Experimental, Go 1.27. Scoped password screening is implemented; complete
identity-risk/password workflow integration remains unfinished.
There is no public prefix-input API or password acceptance decision.

## Implemented privacy boundary

The owned parser validates an entire bounded response before making any match
available. It accepts exactly 35 ASCII hexadecimal suffix characters, one colon
and 1..10 unsigned ASCII decimal digits. Hexadecimal case is canonicalized;
leading decimal zeros are accepted within that width. LF and CRLF are supported,
with an optional final newline. Empty responses, interior blank lines, embedded
carriage returns, malformed tails, partial reads and conflicting duplicate
counts—including zero/positive conflicts—fail closed. Identical duplicates
collapse. Zero counts are padding, never a breach.

The response limit is explicitly 1 KiB..2 MiB; the count maximum is 1..1 billion.
Rows have at most 46 bytes excluding CRLF. Row count is bounded by the byte limit
and minimum row size; the parser uses a fixed 64-byte streaming buffer and never
copies a complete response. Suffix matching visits every parsed entry using
constant-time comparison, with no early acceptance at a matching row. Response
size still affects processing time; this does not claim network timing privacy.

Candidate derivation borrows `go-password.Secret` synchronously, preserves every
byte without trimming or normalization, and never destroys the caller's owner.
The selected candidate limit is positive and at most 1 MiB. Only five uppercase
hexadecimal characters become the request prefix; the remaining suffix
stays private. SHA-1 is used solely for the protocol, never password storage.
Transient hash/encoding buffers are cleared, and private values reject automatic
serialization and redact formatting. Go cannot guarantee runtime-wide erasure.

The protocol basis is the official [Pwned Passwords range and padding
documentation](https://haveibeenpwned.com/API/v3#PwnedPasswords), consulted
2026-10-03. Synthetic local tests are not provider interoperability evidence.

## Scoped checker

`New(Config, *httpclient.Client, clock.Clock)` returns a concurrent `Checker`
whose concrete type is `*Client`. The borrowed primitive transport must verify
HTTPS and cooperate with cancellation. Configure it before sharing and keep it
alive until shutdown finishes. The checker constructs an isolated primitive
client using only that RoundTripper, never inheriting middleware, cookies,
headers or redirects, mutating the supplied client or closing its transport.
The endpoint is fixed; no public prefix/URL override exists. Padding is required.

All configuration is explicit: UserAgent, AddPadding, CacheEntries (100..100000),
CacheTTL (1h..7d), ResponseBytes (1KiB..2MiB), MaxBreachCount (1..1 billion),
OutboundConcurrency (1..64), Timeout (1s..30s), immutable PolicyVersion (1..64
ASCII bytes), MaxWaiters (1..1024), MaxCandidateBytes (1..1MiB), and CacheBytes
(1KiB..128MiB). Retained backing slots are charged 48 bytes each; metadata is
additionally bounded by CacheEntries. DisableCache is optional. The reference
UserAgent is `golib-identity-reference/<module-version> (+<security-contact-URL>)`.
Neither it nor transport instrumentation may contain secrets.

CheckRequest binds trusted operation/action, tenant, purpose, subject, policy and
replay ID plus the borrowed Secret. Operation and Action must agree. Results copy
this caller's binding. Match counts are provider facts, not acceptance decisions.
CheckedAt preserves the original provider observation on cache hits. Always
inspect the error: CheckError/Outcome and errors.Is classify malformed/unavailable,
invalid input/configuration, caller cancellation/deadline, overload and shutdown.
Raw provider errors/URLs are never wrapped. Failures are not evidence and may
have no observation timestamp.

Only complete successful ranges enter the private LRU. TTL never renews on access;
there is no stale fallback. Provider rows are immutable and matched per caller.
Eviction releases references rather than clearing data concurrent waiters use.
Clock regression fails closed. Each checker has an isolated cache/coalescing
namespace. Deadlines include queueing; there are no automatic retries. Individual
cancellation leaves other waiters intact; the last caller cancels shared work.
Callers and cancellation-draining flights are bounded. `(*Client).Close(ctx)`
rejects new work, clears the cache, cancels requests and waits for owned goroutines.
If its context expires, shutdown continues; call Close again to await completion.

## Remaining integration and release evidence

Normalized risk evidence, audit/telemetry and password workflow composition remain
unfinished. Local TLS fixtures are not live-provider interoperability evidence.
Do not substitute checker success for risk allowance.

The password dependency pins committed Secret ownership at `c5746af64a6f`.
Local development uses disposable external workspace wiring; no permanent
replace directive is included. Publication, clean-consumer/API, exact coverage,
mutation, interoperability and other release gates remain pending.
