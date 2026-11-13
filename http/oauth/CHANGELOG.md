# Changelog

## Unreleased

- Select existing-account signin-start independently and route shared query
  callbacks by native stored intent rather than ambient cookies. Original
  preauth/device custody and provider budgets remain mandatory. Only new committed
  signin delivers session and browser-readable CSRF cookies; linking is unchanged.
  Unselected routes and their capability metadata remain absent.

- Add opt-in configured OIDC account-link initiation and query callback handlers
  using native state/session authority, shared provider rate policy and bounded
  callback custody. Full social OAuth qualification remains in progress.
