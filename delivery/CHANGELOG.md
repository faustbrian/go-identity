# Changelog

## Unreleased

### Added

- Immutable versioned plain-text templates with exact typed variable schemas,
  ordered channel/locale selection, explicit HTTPS origins, header-injection
  denial and bounded output. HTML and durable delivery remain in development.

- Bounded email/SMS message and recipient validation with explicit template
  version, caller-negotiated locale chain and closed tagged variables.
  Formatting/logging are redacted and implicit serialization is refused.
  Validation is not recipient ownership, origin authorization, queue admission
  or delivery evidence. Rendering and durable orchestration remain in development.
