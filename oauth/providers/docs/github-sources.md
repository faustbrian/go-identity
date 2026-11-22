# GitHub selected protocol sources

Reviewed on 2026-11-14. No complete official document or OpenAPI corpus is vendored.

- GitHub Docs commit `74d2d500a67997b55f366c2387dc0280104fd9bc`,
  [authorizing OAuth apps](https://github.com/github/docs/blob/74d2d500a67997b55f366c2387dc0280104fd9bc/content/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps.md),
  raw SHA-256 `b4c8481a707440f70f49cc8198e2ba8a15ce68b72a26480841a007f38947d574`.
  This pins code/state/S256, POST token credentials, JSON comma scopes and the
  ordinary response without expiry. Its optional expiring-token response does
  not require this profile to request `offline_access` or implement refresh.
  The same revision's [PKCE feature selection](https://github.com/github/docs/blob/74d2d500a67997b55f366c2387dc0280104fd9bc/data/features/pkce_support.yml)
  explicitly includes GitHub.com. GitHub Docs content is CC BY 4.0.
- GitHub's official REST description commit
  `4754642742db86eba8971da648439698b46ac2ec`,
  [api.github.com OpenAPI](https://github.com/github/rest-api-description/blob/4754642742db86eba8971da648439698b46ac2ec/descriptions/api.github.com/api.github.com.json),
  raw SHA-256 `f7a3de68869181d34b232d88840d31f8157ade45cad1746eaab90cd3c801b31c`.
  `users/get-authenticated`, `GET /user`, returns an authenticated bearer user's
  numeric int64 `id` for public and private response variants. The description
  is MIT licensed. [Rendered endpoint documentation](https://docs.github.com/en/rest/users/users#get-the-authenticated-user)
  describes `read:user` and the authentication failure statuses.
- [RFC 9700 section 4.4.2.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.4.2.2)
  supplies the selected distinct registered redirect-URI mix-up defense.

Updates must resolve an immutable official revision, review these selected facts
and record exact raw-source digests before testing. The public config does not
expose endpoint, scope or token-policy overrides.

## Independent implementation boundary

The test-only OAuth2 server is
[`github.com/go-oauth2/oauth2/v4` v4.6.0](https://github.com/go-oauth2/oauth2/tree/e444dfa1af98b5e2d4d9ff5dbb0747ad9e82c218),
MIT licensed. It owns code generation/consumption, S256 and POST-client-secret
checks, one-hour internal token expiry and bearer validation over verified TLS.
Test-owned wire projection changes its reported scopes to commas, removes the
server's `expires_in` field and exposes the validated user as GitHub's numeric `/user`
shape. These projections are explicit official response fixtures, not a GitHub
server implementation. Native consumers use real public identity/session/risk/
capability/password owners; the independent server is not a product dependency.
No live GitHub authorization UI, user credentials, API tenant or deployment is
claimed.
