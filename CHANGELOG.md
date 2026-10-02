# Changelog

## Unreleased

- Add versioned typed additional-field schemas and bounded command preparation.
  Preserve false, zero, empty strings/lists and full int64 values; normalize
  through explicit versioned composition, enforce field permissions through the
  existing authorization service and reject the whole request on invalid or
  denied fields. Creation defaults and returned lists are privately copied.
  This prepares values only; durable create/update commands remain in development.

- Add tenant-scoped bounded user listing with stable-snapshot continuations,
  confidential signed cursors and fresh collection/row authorization. Bind each
  continuation to its viewer, filters, limit and policy; retain its original
  expiry and withhold all partial output on cancellation or malformed pages.
  The existing get-only constructor remains valid; directory composition adds
  listing explicitly and requires an owned snapshot repository.

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
