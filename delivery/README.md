# Identity delivery

Experimental provider-neutral identity messaging, targeting Go 1.27. The
current development slice validates typed intents and renders versioned plain
text and non-active HTML with protected diagnostics. It does **not** yet enqueue,
send, or reconcile messages. No process-memory
queue is offered as a production durability boundary.

## Typed input

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
