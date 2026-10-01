# Changelog

## Unreleased

- Add tenant-bound user projections and closed lifecycle statuses, preserving
  canonical directory IDs unchanged. Add bounded explicit status-policy
  validation that denies terminal resurrection, unlisted edges and invalid
  restriction durations without performing or authorizing a mutation.

### Added

- Distinct subject and pre-authentication transaction ID contracts with
  cryptographic 128-bit generation, strict canonical reconstruction, decoded
  byte ordering and stable redacted invalid-input/entropy errors.
