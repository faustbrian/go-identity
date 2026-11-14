# Changelog

## Unreleased

- Add explicit `NewOrganization` composition for modern organization metadata
  over standalone verified TLS. Genuine native verification/quota/recovery and
  current organization authority remain required on every attempt; separate
  organization/credential epochs and original deadlines cannot renew or bypass
  withdrawal. Existing USER selection/encoding and default profiles are unchanged.

- Add an explicit encrypted modern USER metadata-only standalone TLS Valkey
  adapter. Every admitted supplied attempt calls the real atomic source once;
  warm metadata only narrows its current grant/original deadline and never owns
  credential verification, quota, permission mutation or reconciliation.
  Preserve native outcomes through outage/publication failures, fail closed after
  original authority expiry, and reject unsupported source-free/legacy/org/cache
  authority profiles. Existing native/default configuration is unchanged.
