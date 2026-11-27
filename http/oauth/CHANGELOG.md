# Changelog

## Unreleased

- Add an explicit Google One Tap redirect-button Start and HTML form callback.
  Document the selected wire profile, preserve the original path-bound flow
  and Google double-submit proofs, and grant no cross-origin script access.

- Add independently selected Google One Tap popup Start and credential
  callback routes. Keep cookie delivery tied to the fresh native outcome,
  preserve exact origin and browser custody, and expose no UI or redirect.

- Add independently opt-in provider-list public denial localization through the
  typed `identity/i18n` registry/resolver. Bounded public language negotiation
  adds only safe JSON messages and truthful language metadata; machine codes,
  status, retry policy, successful pages and the disabled profile are unchanged.

- Add independently opt-in public `GET /v1/oauth/provider-list` backed by the
  native immutable configured-provider catalog. Required bounded pagination
  returns only safe IDs, display names and selected modes, with shared safe-rate
  admission and no session, CSRF, retry key, cookie issuance or protocol work.
  Unselected discovery exposes neither a route nor capability metadata.

- Select existing-account signin-start independently and route shared query
  callbacks by native stored intent rather than ambient cookies. Original
  preauth/device custody and provider budgets remain mandatory. Only new committed
  signin delivers session and browser-readable CSRF cookies; linking is unchanged.
  Unselected routes and their capability metadata remain absent.

- Add opt-in configured OIDC account-link initiation and query callback handlers
  using native state/session authority, shared provider rate policy and bounded
  callback custody. Full social OAuth qualification remains in progress.
