# Changelog

## Unreleased

- Add disabled-by-default mandatory carrier-risk evaluation for both phone-reset
  phases, with exact parent-operation binding, version-pinned source ownership,
  original two-minute freshness ceilings and denied adverse/ambiguous facts.
  Opaque evaluator-bound assessments are preparation inputs, not durable
  RiskEvidence or recovery permission; issuance/consumption remains unfinished.

- Add exact phase-bound counter command preparation with scoped versioned HMAC
  keys and bounded single-dispatch post-state normalization. Original observation
  freshness survives replay; cancellation and ambiguity cannot invent usable
  evidence or erase a known commit. Durable adapters, journal recovery and
  protected transaction participation remain required before workflow adoption.

- Add bounded server-source orchestration with startup mandatory-source ownership,
  request-independent clock/factor resolution, original-fact expiry across provider
  work, fail-closed timeouts and explicit expensive-source skips after verified deny.
  Non-issuing decisions remain non-authoritative; durable issuance is not enabled.

- Add immutable closed operation admission and scoped deterministic assessment
  with mandatory-signal completeness, exclusive freshness, fixed decision
  precedence and action-specific fail-closed behavior. Configuration remains
  explicit; generated canonical metadata preserves selected-profile ceilings.
  These checks do not issue evidence, mutate counters or execute workflows.
