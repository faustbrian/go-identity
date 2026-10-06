# Changelog

## Unreleased

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
