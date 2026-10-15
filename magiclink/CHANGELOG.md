# Changelog

## Unreleased

- Use authentication v2 and authorization v3 public values with current identity,
  email and session contracts. Composed callers must use matching major-version
  types; original link custody, expiry and consumption policy are unchanged.

- Adopt capability v2 public proof/grant types and explicit trusted issuer
  policy. Update capability imports and issuer-owned keys/configuration; token
  framing and native transaction/recovery ownership remain unchanged.

- Add an explicit challenge-only consuming result with reveal-once MFA proof
  custody and original method/expiry metadata. A continuation is not a session;
  retry and recovery never redeliver its credential or renew its lifetime.

- Add a redacted typed supersession result for original-browser authenticated
  consumption; replacement invalidation does not authorize a retry or session.

- Add bounded public request and explicit consuming input with opaque grant
  and original browser custody. Validation does not authenticate or consume;
  diagnostic and implicit serialization paths redact sensitive inputs.
  Native request/delivery composition is in development; public consumption
  and a complete login workflow are not yet available.

- Add bounded scanner-safe inspection of original signed magic-link scope.
  Inspection never transfers or consumes the proof and never returns recipient
  or session authority. Signature validity does not assert remaining uses,
  supersession, current account eligibility or permission to log in.
