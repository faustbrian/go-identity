# Changelog

## Unreleased

### Added

- Typed rendered attempts/provider outcomes and bounded synchronous sender
  execution with expiry, deadline, concurrency and ambiguous-outcome handling.
  Provider callbacks do not retry or own workflow/queue policy. Durable service
  admission and queue orchestration remain in development.

- Stable `ErrSerializationForbidden` for sensitive JSON/text refusal, including
  Go1.27 JSON error wrappers. This replaces the earlier experimental
  `errors.ErrUnsupported` classification; content remains unavailable.

- Email HTML fragments with escaped text/attributes, whole-URL origin binding,
  canonical HTML5 tokens and a non-active element/attribute profile. SMS remains
  plain text; scripts, CSS, events and ambiguous contexts fail closed.

- Immutable versioned plain-text templates with exact typed variable schemas,
  ordered channel/locale selection, explicit HTTPS origins, header-injection
  denial and bounded output. HTML and durable delivery remain in development.

- Bounded email/SMS message and recipient validation with explicit template
  version, caller-negotiated locale chain and closed tagged variables.
  Formatting/logging are redacted and implicit serialization is refused.
  Validation is not recipient ownership, origin authorization, queue admission
  or delivery evidence. Rendering and durable orchestration remain in development.
