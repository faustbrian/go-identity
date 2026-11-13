# Changelog

## Unreleased

- Add explicit `NewGoogle` configuration for the reviewed Google
  code/query/S256 profile, RS256, POST client authentication and closed
  `openid`/`email`/`profile` scopes. Reuse the existing Google-only OAuth owner,
  immutable profile and native linking/signin composition without endpoint
  overrides or a new identity engine. This is not live-provider, direct-token,
  complete catalog or whole-unit qualification.

- Add the direct Apple client-secret signing operation with preprovisioned
  encrypted P-256 key handles, bounded integral lifetimes, exact ES256 JWT
  encoding, redacted errors and synchronous callback-only secret custody.
  This does not enable Apple login or provider-catalog discovery.
