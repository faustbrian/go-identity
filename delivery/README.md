# Identity delivery

Experimental provider-neutral identity messaging, targeting Go 1.27. The
current development slice validates typed intents and renders versioned plain
text with protected diagnostics. It does **not** yet render HTML, enqueue,
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
HTML context validation/escaping remains required work, not a plain-text fallback.

Ordinary fmt/slog output is redacted for messages, recipients and variables,
including values marked `Sensitive=false`. JSON/text serialization refuses with
`errors.ErrUnsupported`. Explicit fields remain sensitive; copying/logging them
bypasses redaction. No physical memory erasure is claimed.

## Adoption and remaining work

This is an additive development module, not a complete production messaging
service. Durable workflow/outbox integration, encrypted payload retention,
HTML context-aware rendering, bounded sender callbacks,
status/cancellation, authenticated receipts and reconciliation remain required.
Applications ultimately supply only bounded sender callbacks, not replacement
domain queues or workflow orchestration. Existing identity primitives are unchanged.

**FAQ:** Successful validation does not mean queued, accepted or delivered.
HTTPS shape does not mean an allowed origin. A scope digest is a caller-provided
binding, not proof. Full coverage/mutation, integration, provider and release
verification are pending; focused value tests do not certify those boundaries.
