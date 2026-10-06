# Changelog

## Unreleased

- Add bounded local encrypted original-attempt mapping with retained issuer and
  code-key versions. Custody survives process restart without storing codes,
  regenerating attempt IDs or renewing authorization/remember policy. This is
  not stored-challenge verification or a complete login workflow.
- Add forward-only native OTP challenge storage with immutable scoped keyed
  digests and policy, bounded monotone counters, full-width versions, closed
  lifecycle constraints and retained issuance/consumer journal linkage. This
  experimental install does not yet provide issuance or participant workflows.
