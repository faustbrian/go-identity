# Identity delivery

Experimental provider-neutral identity messaging, targeting Go 1.27. The
current development slice validates typed intents, renders versioned plain
text and non-active HTML, and composes bounded queue admission, redacted status,
cancellation, receipt/reconciliation and one-attempt worker calls. The owned
durable adapter is **not implemented yet**: these core paths do not prove
PostgreSQL authorization, dedupe, ciphertext custody, provider authentication or
durable recovery. No process-memory queue is a production durability boundary.

## Typed input

`New(Config, Queue, Renderer, Sender)` rejects absent/typed-nil collaborators;
production rejects capture senders and any backend declaration except the owned
PostgreSQL profile. A backend declaration is trusted composition metadata, not
a durability or authorization proof. Applications must select the owned adapter,
not implement their own identity store. Admission and administration calls use
the earlier caller deadline or configured sender timeout. After a worker claim,
`ProcessOne` permits one additional sender-timeout budget for synchronous outcome
bookkeeping even when the caller cancels; it never renews effect authority.
Collaborators must honor their context. No background workers or retry loops start.

`Enqueue` validates the root `identity.CommandID` (delivery aliases it), clones
message slices and renders before queue admission. The adapter reads the prepared
content through `EnqueueRequest.Rendered()` and must authorize the exact command,
tenant, resource, expiry and provider binding, then enlist authenticated encrypted
custody and durable dedupe under the existing coordinator. Prepared content is
memory-only and never grants command authority. Queue success reports admission,
not provider delivery, and never calls Sender. Unexplained admission failures
retain the original command in `AdmissionUnknownError`: recover it rather than
enqueueing a replacement. No-op-equivalent admission retains the same result
shape; its internal marker must not be exposed as recipient existence.

`ProcessOne` performs one scoped claim/send/complete without a hidden retry.
`StatusGet` exposes only bounded durable state and generation. `Cancel` separates
local prevention from remote confirmation; pending external outcomes stay unknown.
`ReceiptRecord` and `Reconcile` validate bounded normalized inputs but their owned
adapter remains responsible for authenticated provider evidence, monotonic
transitions, generation CAS, query checkpoints and no blind resubmission.
Queue/backend test doubles prove only core behavior, never those durable claims.

`ReceiptRecordRequest.Validate` checks normalized shape only. The owned adapter
can use `DecideReceipt(ReceiptSnapshot, ReceiptRecordRequest)` after authenticating
the callback/query and locking its exact tenant/provider/effect/generation. It
rejects stale generations, conflicting same-instant observations and newer
conflicting terminal outcomes; earlier callbacks are no-ops. Later accepted or
unknown observations cannot downgrade acceptance or terminal delivery, and
cancellation confirmation requires an outcome-unknown effect. `ObservedAt` is
the provider's authenticated observation time, not callback arrival time.

Apply `ReceiptDecision` atomically with durable event dedupe and the observation
checkpoint. Even a terminal no-op requires erasure to repair legacy ciphertext.
The decision starts no retry/query/send, owns no transaction and does not prove
provider authentication or durable application. Unknown receipts never grant
resubmission. Durable receipt/reconciliation composition is still unfinished.

## Explicit test capture

`NewCaptureSender(CaptureConfig{TenantID, MaxAttempts, MaxBytes})` provides the
owned test-only `Sender`, usable with the public Queue/Service composition. It
adds no memory queue, authority, lease, dedupe, retry or provider engine. The
exact tenant, 1–1024 attempts and 1–4194304 retained string bytes are mandatory;
there are no implicit bounds. Inputs are cloned so small string substrings do
not keep large caller allocations alive. Capturing reports `Accepted`, never
real provider delivery, and deliberately records duplicate invocations so tests
can detect them. A full/closed capture fails instead of silently losing content.

`Snapshot(ctx)` explicitly returns a caller-owned slice of sensitive attempts.
Changing that slice cannot change future snapshots. `Close` prevents further
capture and clears owned payload references; it cannot erase caller snapshots
or promise cryptographic erasure of immutable Go heap bytes. Use only synthetic
test messages, close after assertions, and do not log snapshots. Diagnostics
are redacted and implicit serialization is forbidden. Both production service
and worker construction reject this implementation through the Sender interface.
Actual PostgreSQL/ciphertext/provider and lifecycle claims remain separate tests.

```go
variable := delivery.TemplateVariable{
    Name: "name", Kind: "text", TextValue: "display name",
}
if err := variable.Validate(); err != nil { return err }
```

`Recipient.Validate` checks channel, 1–320 UTF-8 address bytes, control rejection
and exactly 64 lowercase hex digest bytes. Owning workflows supply canonical
addresses and derive scoped digests; this module cannot authenticate either.
`TemplateVariable.Validate` checks one selected text/URL/code/UTC timestamp arm.
`Message.Validate` binds channel, purpose, exact template version, a pre-negotiated
duplicate-free ordered locale chain and unique typed variables. It does not
negotiate locale or select a template. Errors are stable `ErrInvalidInput`.

Text may be empty and is at most 4096 UTF-8 bytes. Code is 1–128 printable ASCII
bytes. URL shape is bounded to 2048 bytes and absolute HTTPS without userinfo or
controls; rendering additionally enforces its selected template origin
policy. Timestamp is a nonzero UTC instant in years 1–9999. Non-selected union
fields must be zero. Variable names use ASCII letters/underscore initially,
then letters/underscore/digits, at most 64 bytes. Purpose starts with lowercase
ASCII letters followed by lowercase letters/digits/dot/hyphen, at most 64 bytes.
Template IDs are 1–128 printable non-space ASCII bytes. Locale shape is bounded
ASCII alphanumeric subtags separated by single hyphens; callers own canonical
locale validation and negotiation. There are at most eight locales and 64 variables.

## Ownership and security

Values contain exported fields and remain forgeable; validate at every effect
boundary. Do not mutate fields or slices concurrently with validation/rendering.
Validation has no IO, goroutines, global registry or retained caller references.
It grants neither authentication nor authorization. It cannot decide recipient
existence, allowed link origins, template/schema compatibility, durable dedupe,
generation authority or remote provider outcomes. The renderer separately checks
the exact template schema and declared origins.

## Plain-text rendering

`NewTemplateRenderer` takes 1–256 unique ID/version/channel/locale templates and
copies them into an immutable concurrent-read catalog. `Render` selects the first
exact available entry in the caller's ordered locale chain; it never substitutes
a version or channel. Each template supplies `RequiredVariables` and an equal
`VariableSchema` declaring exact names, kinds and sensitivity flags. Missing,
extra or mismatched variables fail, even if a substitution does not use them.

The current closed language accepts literal text and `{{.name}}` only, parsed
by the standard library. Functions, loops, nested lookups and template invocation
are rejected. Plain-text substitutions preserve characters rather than HTML
escaping them. Subjects reject all ASCII controls after substitution; SMS has
no subject. `MaxRenderedBytes` bounds the combined UTF-8 subject/body length
before each append, at most 262144 bytes; subjects independently stop at998.
Bodies must remain nonempty. UTC timestamps use RFC3339Nano.

URL schema entries require bounded `AllowedOrigins` containing HTTPS origins
without paths, queries, fragments or userinfo. Comparison uses case-insensitive
hostnames and exact ports, treating implicit HTTPS and explicit443 identically;
it does not authorize subdomains. Rendering performs no network requests.
URL substitutions must occupy whole whitespace-delimited tokens; adjacent
literals or variables cannot turn an authorized URL into a different hostname.
Canceled contexts fail without returning partial content. Errors are redacted.
HTML never falls back to plain text.

## HTML email profile

Email templates may declare `text/html`; SMS remains plain text. The closed
substitution language remains unchanged. HTML5 tokens are validated and
re-serialized before retention, so original markup is never sent directly.
HTML substitutions escape ampersands, angle brackets and quotes in both text
and quoted attribute contexts. Subjects always retain plain/header behavior.

The profile supports common paragraph, heading, list, table, image and inline
formatting elements. Scripts, styles (including inline CSS), event handlers,
SVG/MathML, forms, frames, comments, doctypes and executable/foreign contexts
are rejected rather than sanitized or silently enabled. It is an email fragment
profile, not an arbitrary-document or CSS rendering engine.

Links are limited to `a[href]` and images to `img[src]`: each value must be a
whole URL variable or a literal HTTPS URL at a declared origin. Concatenated,
relative, data/javascript and multi-candidate URLs are rejected. Non-URL
variables can appear in text and `title`, `alt`, `aria-label`; structural/layout
attributes must remain static. Unknown attributes are rejected. HTML5 keeps
the first duplicate attribute; only its canonical token is retained/sent,
never the discarded attribute. A variable discarded by tokenization fails
construction rather than losing its substitution silently.

Sources retain their existing bounds; HTML has at most 65536 tokens, 32
attributes per tag and 4096 bytes per attribute. Token buffers are capped at
524288 bytes. Final combined output limits apply after escaping/canonicalization.
The foundational HTML5 tokenizer is pinned to `golang.org/x/net v0.59.0`
(BSD-3-Clause, source tag checksum in `go.sum`); it is not an auth engine.

Ordinary fmt/slog output is redacted for messages, recipients and variables,
including values marked `Sensitive=false`. JSON/text serialization refuses with
`ErrSerializationForbidden`. Explicit fields remain sensitive; copying/logging them
bypasses redaction. No physical memory erasure is claimed.

## Sender contract and execution policy

`Sender.Send` accepts an already-rendered `Attempt`, bound to an exact tenant,
intent, positive generation, provider idempotency key and UTC expiry. These
fields prove shape, not lease ownership or authority; the durable queue must
record/authorize the attempt before calling. The provider callback must honor
its context and never retain the attempt, discover recipients, retry, or own
workflow policy. Exported fields remain sensitive despite redacted diagnostics.

`DefaultConfig` returns independent five-attempt policy values; `Validate`
rejects zero/invalid timeout, concurrency, retention and backoff bounds. The
reference composition will use its exact five-entry full-jitter schedule.
The internal executor makes one synchronous invocation under the earliest
parent/configured/effect-expiry deadline, with bounded capacity per composed
executor. Capacity waiting is cancellable and counts against that deadline.
No queue lock, transaction or detached goroutine spans the callback.

Accepted, delivered, bounced and permanent rejection are distinct attributable
results. `StateTransientFailure` is provider evidence only: the durable queue
decides retry admission and timing. Callback errors, panics, malformed output
and late success become `StateOutcomeUnknown` with a stable intent recovery
handle; raw errors/panic payloads are discarded. No callback is automatically
retried. Cancellation before invocation proves no call; cancellation after it
starts cannot claim no remote effect. An arbitrary callback that ignores its
context cannot be forcibly stopped safely; supplied callbacks must cooperate.

There is intentionally no exported shortcut for sending an unrecorded attempt.
The internal queue completion policy rejects stale generations and schedules
only attributable transient failures. Full jitter uses the next attempt's
configured ceiling with the provider RetryAfter as a floor; entropy work is
bounded and fails closed. Known unsuccessful attempts stop on cancellation,
expiry or exhaustion. Unknown outcomes never automatically retry or become
cancelled/expired merely because local time or cancellation changed. Expired
bearer payload custody must still be erased while retaining unknown outcome.
These decisions require atomic durable generation-CAS application; the policy
function itself supplies no lease, authentication, persistence or cleanup proof.
Owned adapters consume these same rules through `NewCompletionPolicy` and
`CompletionPolicy.Decide(ctx, CompletionSnapshot, DeliveryResult)`. Construction
freezes a copied policy; the immutable result is safe for concurrent reads.
Snapshots must come from current authoritative database state. Decisions are
proposals only: the adapter applies state, retry instant and payload erasure
atomically under exact tenant/intent/worker/generation CAS, preserving time
precision, expiry and throttle bounds. Cancellation returns no usable decision.
The internal processor now connects one scoped committed claim to one sender
invocation and one exact generation completion. Capacity is acquired before
claiming, and the sender also stops at the absolute queue lease deadline.
Queue calls must return outside their database transaction; this core contains
no database locks, queue store, background goroutine or automatic send retry.
Cancellation before invocation is reported separately from an ambiguous call.
After claiming, completion runs synchronously despite caller cancellation,
within one additional SenderTimeout budget; it cannot renew authorization,
lease or generation. Failed/malformed/ambiguous completion retains the stable
intent for recovery, even if the provider claimed success. Transfer values
refuse implicit serialization and redact diagnostics. Queue doubles establish
this handshake only, not a live lease, durable CAS or actual payload erasure.
Service admission, generation-fenced queue processing, durable completion and
the owned capture sender remain in development. Shape/concurrency tests do not
certify durable effects, queue authorization or production capture isolation.

Serialization refusal now uses `ErrSerializationForbidden` rather than the
earlier experimental `errors.ErrUnsupported`: Go1.27's legacy JSON/text method
handling replaces the latter error. Consumers should classify the new error
through `errors.Is`, including errors returned by `encoding/json`.

## Adoption and remaining work

This is an additive development module, not a complete production messaging
service. Durable workflow/outbox integration, encrypted payload retention,
bounded sender callbacks,
status/cancellation, authenticated receipts and reconciliation remain required.
Applications ultimately supply only bounded sender callbacks, not replacement
domain queues or workflow orchestration. Existing identity primitives are unchanged.

**FAQ:** Successful validation does not mean queued, accepted or delivered.
HTTPS shape does not mean an allowed origin. A scope digest is a caller-provided
binding, not proof. Full coverage/mutation, integration, provider and release
verification are pending; focused value tests do not certify those boundaries.
