# Changelog

## Unreleased

- Add bounded canonical locale negotiation with weighted basic language ranges,
  exact aliases, progressive region/extension fallback and explicit exclusions.
  Matching does not persist preferences or render localized errors.

- Add construction/sealing for typed error-to-message registration with exact
  copied parameter schemas, bounded wrapper traversal and redacted fail-closed
  resolution. Values retain their declared final-output context without escaping;
  unknown errors are not classified by message text.
