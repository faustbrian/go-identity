# Changelog

## Unreleased

- Add forward-only shared OTP lockout storage and private keyed subject/channel
  destination projections. Reissued challenges and purpose changes retain the
  same exclusion; deployment key mismatches fail closed, and wrong exhaustion
  can extend both scopes atomically with the owning denial transaction. Public
  issuance, flow authority and coordinator composition remain pending.
- Add private native consuming custody persistence, exact-generation takeover
  and transactional finalization/release projections. Reservations retain their
  original attempt, scope, expiry and comparison allowance; live writes recheck
  database expiry and preserve terminal version capacity. Public coordinator
  participant dispatch and current-authority/recovery proof remain pending.
- Add private primary challenge reconstruction and counted denial/check/expiry
  persistence with exact keyed scope, committed issuance, full-width version
  CAS and exclusive database expiry. Public counted workflows remain pending
  current flow/lockout authority and command result/audit composition.
- Add bounded local encrypted original-attempt mapping with retained issuer and
  code-key versions. Custody survives process restart without storing codes,
  regenerating attempt IDs or renewing authorization/remember policy. This is
  not stored-challenge verification or a complete login workflow.
- Add forward-only native OTP challenge storage with immutable scoped keyed
  digests and policy, bounded monotone counters, full-width versions, closed
  lifecycle constraints and retained issuance/consumer journal linkage. This
  experimental install does not yet provide issuance or participant workflows.
