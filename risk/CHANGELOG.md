# Changelog

## Unreleased

- Add bounded server-source orchestration with startup mandatory-source ownership,
  request-independent clock/factor resolution, original-fact expiry across provider
  work, fail-closed timeouts and explicit expensive-source skips after verified deny.
  Non-issuing decisions remain non-authoritative; durable issuance is not enabled.

- Add immutable closed operation admission and scoped deterministic assessment
  with mandatory-signal completeness, exclusive freshness, fixed decision
  precedence and action-specific fail-closed behavior. Configuration remains
  explicit; generated canonical metadata preserves selected-profile ceilings.
  These checks do not issue evidence, mutate counters or execute workflows.
