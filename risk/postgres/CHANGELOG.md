# Changelog

## Unreleased

- Accept the canonical production audit contributor alongside the original
  explicitly supported v1 composition identity. Foreign contracts, owners and
  versions remain rejected; production audit/outbox effects share native
  issuance, rollback and original-response recovery.

- Add the official authenticated issuance executor and private primary original
  response resolution. Same-Work issuance, exact-intent replay and retained-key
  rotation preserve original references and expiry; conflicting, pending,
  denied and corrupt histories cannot restart providers or disclose candidates.
  Consumption and complete risk-service behavior remain unfinished.

- Add the native issuance contributor: database-time issued evidence and
  encrypted original-response custody commit atomically with required protected
  audit, lifecycle and command receipt. Locked recovery preserves pending state
  on positive or inconsistent native evidence instead of inferring rollback.
- Use opaque command IDs for new evidence aggregate identities so audit and
  lifecycle projections do not reveal private keyed intent digests. Append the
  issuance-identity migration while preserving existing install bytes and
  legacy encrypted rows; new compositions select the complete forward history.
- Add the signed native evidence-issuance command schema and exact-intent record
  mapping, preserving original evaluation validity and purpose separation.
- Add scope-bound encrypted original-response custody with retained wrapping-key
  rotation, plus the forward-only issued-evidence migration source. Durable
  execution, recovery and one-use consumption remain in development.
