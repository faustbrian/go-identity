# Identity delivery

Experimental provider-neutral identity messaging, targeting Go 1.27. The
current development slice validates typed intents and protects diagnostics.
It does **not** yet render, enqueue, send, or reconcile messages. No process-memory
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
controls; the future renderer must still enforce its selected template origin
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
generation authority or remote provider outcomes.

Ordinary fmt/slog output is redacted for messages, recipients and variables,
including values marked `Sensitive=false`. JSON/text serialization refuses with
`errors.ErrUnsupported`. Explicit fields remain sensitive; copying/logging them
bypasses redaction. No physical memory erasure is claimed.

## Adoption and remaining work

This is an additive development module, not a complete production messaging
service. Durable workflow/outbox integration, encrypted payload retention,
template rendering and versioned schema/origin policy, bounded sender callbacks,
status/cancellation, authenticated receipts and reconciliation remain required.
Applications ultimately supply only bounded sender callbacks, not replacement
domain queues or workflow orchestration. Existing identity primitives are unchanged.

**FAQ:** Successful validation does not mean queued, accepted or delivered.
HTTPS shape does not mean an allowed origin. A scope digest is a caller-provided
binding, not proof. Full coverage/mutation, integration, provider and release
verification are pending; focused value tests do not certify those boundaries.
