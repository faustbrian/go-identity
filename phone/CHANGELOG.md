# Changelog

## Unreleased

- Add explicit bounded ASCII-v1 phone number policy using pinned phonenumbers
  v2.0.14 and upstream v9.0.40 metadata, with canonical E.164 comparison,
  opt-in region-bound national input and display retention, opaque redacted
  values and exact-profile sensitive persistence/restoration. Metadata changes
  require explicit migration and ownership reverification policy; structural
  number validity is not verification, deliverability or recovery authority.
