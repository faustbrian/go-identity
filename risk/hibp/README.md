# HIBP password screening

Experimental, Go 1.27. Scoped password screening is implemented; complete
identity-risk/password workflow integration remains unfinished.
There is no public prefix-input API or password acceptance decision.

## Observed screening

`NewObservedChecker(*Client, ObservationConfig)` selects security emission.
The original `Client` stays provider-only; the reference composition must select
the observed checker. Each request supplies `SecurityAttribution` from trusted
workflow state: real pre-authentication attempt, command/correlation, actor and
numeric audit-policy version. Free-form `SubjectScope` and provider configuration
versions are not audit identity. Inputs must not mutate during `Check`.

One logical call emits `identity.hibp.query_range`, plus `detect_match` when a
positive fact exists or `reject_range` when unusable evidence is discarded.
Cache hits and shared network waiters retain their own caller attribution.
Secondary records reference the actual query event ID; no event contains breach
counts, prefixes, suffixes, cache keys, range bodies or provider diagnostics.
Successful match detection is not password acceptance. Provider failures belong
to the query outcome; successful rejection means discarding unusable evidence.

`ObservationConfig.Delivery` uses the existing audit recorder configuration and
explicit failure policy. Its redactor must be nil: the shared builder performs
privacy redaction, and the recorder preserves the required profile. `AuditTimeout`
is 1ms..5s for terminal submission, including caller cancellation. Recorder
recovery has its own explicit bound. Borrowed sinks/buffers/alerts must honor
contexts and be concurrency-safe. Callbacks run outside HIBP locks.

`CheckResult.Events` distinguishes acknowledgement from provider evidence.
Undelivered required events return `ErrAuditUnavailable`, discard usable match
data and preserve the original failure. `EventDelivery.Records()` copies the
slice of immutable records for existing audit reconciliation/idempotent retry;
never rebuild a record to retry it. Rejected, committed-with-error, unknown and
invalid acknowledgements remain distinct. An alerted fail-open policy surfaces
loss but does not make missing required records into usable evidence. The host
owns durable buffering/reconciliation; this checker owns no second queue.
Alerted-loss receipts retain the primitive's authoritative `DeliveryAlert`
outcome per invocation, while forwarding the actual host alert unchanged.

`NewObservedSignalProvider` keeps normalization neutral and emits only through
the checker. On failure, `CheckError.Events` retains the same records, including
through normalization. Provider audit events do not replace the password
mutation's atomic audit contribution or establish a state transition's commit.

`NewTelemetry(metric.Meter, trace.Tracer)` borrows standard interfaces supplied
by Golib's telemetry runtime. Optional nil telemetry is explicit. Fixed names
and only `hibp.outcome` / `audit.delivery` dimensions permit at most 24 pairs.
No caller identifiers, context baggage, URLs, counts or raw errors enter labels.
Instrumentation cannot replace caller context or change evidence/delivery;
panics are contained independently. Host providers must be bounded/nonblocking
and own their exporters/shutdown. No globals or resource ownership change.
Measurements describe provider/audit completion; later caller cancellation
during synchronous observers still invalidates the returned evidence.

Each observed checker limits the complete call lifetime to the client's
`MaxWaiters`, including terminal audit recovery and telemetry. Admission is
nonblocking: saturation returns `ErrOverloaded` before screening or event
construction, even for an already-cancelled caller. No fallback queue grows.
Separate wrappers have separate admission limits; the underlying client still
owns its shared provider-work limit.

The observed wrapper owns no goroutines. The underlying Client's `Close` drains
provider work, not separately bounded synchronous audit/observer callbacks.
The host must wait for its calling goroutines before shutting down borrowed
audit/telemetry dependencies. Real durable integration, reference selection and
provider interoperability remain required before release.

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

## Neutral risk composition

`NewSignalProvider(*Client, risk.Policy)` borrows an owned checker without adding
resources or transferring shutdown ownership. Construction rejects disabled
screening or incompatible provider-cache TTL. Provider profile string versions
and risk decision numeric versions are distinct authorities. `Assess` accepts
the original exact-byte borrowed request, validates all seven result bindings,
and maps its ReplayID exactly to the risk attempt identity. Unsupported or
unselected operations reject before provider work.

The adapter returns clean, positive or unavailable facts; `risk.Policy.Assess`
owns the decision. It discards success-looking data alongside errors, retains
only bounded failure classifications and never exposes upstream diagnostics.
Failures may return a classified unavailable signal plus a safe error; caller
cancellation returns no signal and retains cancellation identity. Successful
provider CheckedAt remains original observation, ProviderValidUntil is unchanged
observation plus cache TTL, and the adapter samples a separate trusted local
comparison time. Derived expiry is capped by both original provider validity
and the consuming operation's assessment TTL; cached provider age is not reset.

This is provider-to-policy composition, not password-workflow completion or
permission to perform a mutation. Full purpose/subject/workflow custody, durable
event composition, reference telemetry selection and release gates remain unfinished.

## Checker lifecycle

`New(Config, *httpclient.Client, clock.Clock)` returns a concurrent `Checker`
whose concrete type is `*Client`. The borrowed primitive transport must verify
HTTPS and cooperate with cancellation. Configure it before sharing and keep it
alive until shutdown finishes. The checker constructs an isolated primitive
client using only that RoundTripper, never inheriting middleware, cookies,
headers or redirects, mutating the supplied client or closing its transport.
The endpoint is fixed; no public prefix/URL override exists. `AddPadding=true`
is recommended and mandatory in the reference configuration. Core callers may
select `false` to omit the padding header, sacrificing response-size privacy.
The boolean cannot distinguish an omitted value from an explicit `false`;
all other mandatory bounds still apply and a zero `Config` is invalid.
Each client retains its own immutable profile, cache and in-flight requests.

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

Complete password workflow, durable audit and reference telemetry composition
remain unfinished. Local TLS fixtures are not live-provider interoperability evidence.
Do not substitute checker success for risk allowance.

The password dependency pins committed Secret ownership at `c5746af64a6f`.
Local development uses disposable external workspace wiring; no permanent
replace directive is included. Publication, clean-consumer/API, exact coverage,
mutation, interoperability and other release gates remain pending.
