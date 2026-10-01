# Changelog

## Unreleased

- Add bounded user lookup through the upstream revision-fenced authorization
  service, injected canonical-ID validation and typed redaction. Reject scope
  mismatches before storage and never disclose users after cancellation,
  policy failure or malformed repository output. A read-only constructor does
  not require mutation/capability dependencies. Redaction decisions must carry
  an explicitly registered reason; missing or unknown reasons deny disclosure.

- Add tenant-bound user projections and closed lifecycle statuses, preserving
  canonical directory IDs unchanged. Add bounded explicit status-policy
  validation that denies terminal resurrection, unlisted edges and invalid
  restriction durations without performing or authorizing a mutation.

### Added

- Distinct subject and pre-authentication transaction ID contracts with
  cryptographic 128-bit generation, strict canonical reconstruction, decoded
  byte ordering and stable redacted invalid-input/entropy errors.
