# Changelog

## Unreleased

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
