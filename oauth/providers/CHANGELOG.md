# Changelog

## Unreleased

- Add `NewGitLab` for the catalog OAuth2/read_user existing-account browser
  profile, POST client authentication and bearer HTTPS stable integer user ID.
  Require a distinct registered callback route; no OIDC approximation, signup,
  native-token, refresh or remote-logout operation is added.

- Add `NewKeycloak` for explicitly pinned realm discovery and existing-account
  code/query/S256/nonce/RS256 linking/signin composition. Require exact issuer,
  realm-bound endpoints, RFC 9207 responses, Basic client authentication and
  closed identity scopes. This adds no enterprise routing, signup, implicit
  linking, native-token, refresh or remote-logout operation.

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
