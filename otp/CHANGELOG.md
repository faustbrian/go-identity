# Changelog

## Unreleased

- Add immutable primary challenge snapshots and bounded attempt policy
  evaluation. Non-consuming checks have their own cap while all admitted
  comparisons share the profile's total budget, including successful checks;
  exact expiry, scope and versions fail closed.
  Evaluation is provisional and grants no proof or durable reservation.

- Add explicit disjoint session/pre-auth OTP continuations, preserving resolved
  session remember policy without persistence upgrades. Add server-issued
  attempt identities and keyed exact-submission fingerprints with code-free
  recovery metadata. Preparation grants no authentication or consumption;
  durable counted attempts and protected mutations remain unfinished.

- Add complete exact workflow-scoped keyed code digests and constant-time
  retained-key comparison through opaque authentication codes. Unknown/retired
  versions fail closed; digest matching is not authentication or consumption.
  Add bounded non-disclosing raw destination custody; channel canonicalization
  remains owned by the email/phone workflow. Durable counted attempts remain
  unfinished.

- Add explicit closed-purpose OTP profiles and bounded cryptographic code
  generation with rejection sampling and ephemeral callback custody. No implicit
  policy defaults or weak-randomness fallback. Durable challenge issuance,
  keyed digest storage, attempt accounting, consumption and login are unfinished.
