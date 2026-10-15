# Changelog

## Unreleased

- Bind locale composition to the current public identity kernel contracts;
  locale precedence and stored preference semantics are unchanged.

- Align owned capability dependencies with the v2 issuer-scoped contracts.

- Add canonical catalog/resolver constructors, configured fallback chains and
  bounded preference policy with tenant/version/notice validation and explicit
  unknown-write outcomes. No fallback is persisted by reads or resolution.

- Add typed error-preserving locale resolution with explicit/session/cookie/
  header/default precedence, single-snapshot rendering, bounded custom matching
  and registry/schema admission that constrains later catalog publication.

- Add bounded canonical locale negotiation with weighted basic language ranges,
  exact aliases, progressive region/extension fallback and explicit exclusions.
  Matching does not persist preferences or render localized errors.

- Add construction/sealing for typed error-to-message registration with exact
  copied parameter schemas, bounded wrapper traversal and redacted fail-closed
  resolution. Values retain their declared final-output context without escaping;
  unknown errors are not classified by message text.

- Add immutable versioned catalogs with compatible translated schemas,
  bounded literal/value/plural/select rendering and atomic expected-version
  replacement. Results retain typed contexts and value boundaries; previews
  are not context-escaped transport output.
