# Changelog

## Unreleased

- Add an explicit encrypted modern USER metadata-only standalone TLS Valkey
  adapter. Every admitted supplied attempt calls the real atomic source once;
  warm metadata only narrows its current grant/original deadline and never owns
  credential verification, quota, permission mutation or reconciliation.
  Preserve native outcomes through outage/publication failures, fail closed after
  original authority expiry, and reject unsupported source-free/legacy/org/cache
  authority profiles. Existing native/default configuration is unchanged.
