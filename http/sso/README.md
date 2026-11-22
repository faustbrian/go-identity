# Enterprise SSO HTTP features

Select `NewFeature(Config{...})` to compose only `GET /v1/sso/discover` into
`identityhttp.FeatureServices`. The base HTTP package does not import this
module or implicitly select the route or its OpenAPI operation.

1. Build the native PostgreSQL `ProviderDiscovery` from `go-sso/postgres`
   with its audited evaluator, verified-domain router, and explicitly
   advertised static OIDC providers. Use it for `Config.Discovery`.
2. Supply the same immutable trusted host/proxy policy as `NewRouter`, the
   existing browser-device cookie policy and keys used at pre-authentication,
   and the shared strict `AuthRateLimiter`. Do not make a new limiter namespace
   for discovery. The router and clocks must be concurrency-safe.
3. Select the returned feature, pass `NewOperationDescriptors` to `NewRouter`,
   and have the browser send its existing signed host-only device cookie to
   `GET /v1/sso/discover?emailOrDomain=example.com` over HTTPS. The route does
   not create or rotate a cookie or use an authenticated user session.

Supply exactly one case-sensitive `emailOrDomain` query parameter, 1–320 bytes
after decoding. An email's local part is discarded by the SSO owner and never
used for account lookup or rate keys. Use a domain when possible. Access logs
and traces must omit this route's raw query, cookies and authorization headers.
Request bodies, idempotency keys, bearer credentials, untrusted `Forwarded`,
and supplied foreign origins are rejected. No CORS grant is configured here.

A match returns only `matched`, `providerID`, `protocol` and
`requiresConfirmation`; no match omits provider and protocol. Both carry
`Cache-Control: no-store` and `Referrer-Policy: no-referrer`. Known shared IP
exhaustion is `429` with `Retry-After`; unavailable required authority fails
closed. Neither the cookie nor any response authenticates a user or grants
enterprise sign-in. Omit the feature entirely to disable discovery.

## Existing-linked-member static OIDC

Select `NewSigninStartFeature` for `POST /v1/sso/signin-start` and
`NewSigninCallbackFeature` for `GET /sso/oidc/callback`. To select both start
and discovery, set `Config.SigninStart` when calling `NewFeature`; both share
the `sso` owner. The callback is a separate `sso/oidc` contribution. Omitted
operations have neither a route nor an OpenAPI definition.

Bind both configurations to the same exact HTTPS tenant, provider and shared
limiter. Use the same Lax flow/device cookies, clock and Remember policy as
the pre-authentication issuer. Start requires exact Origin, one
`Idempotency-Key`, and JSON containing `flowID`, `commandID`, `providerID`,
`callback`, `errorCallback`, and optional `domain` and `remember`. Retain the
original body and key for a retry. Both callback URLs must be on the configured
same-origin allowlist. Start returns the original authorization URL and
transaction identity; it does not deliver a session or cookie.

Wire the native enterprise start and completion service, including its
`SigninCallbackRateSource`, through the transport owner's typed interfaces.
When the installed ID and the OAuth parser's logical ID differ, use
`NewSigninCallbackFeatureForProvider` with the exact installed ID. The parser
still uses its own configured profile; native attribution and both quotas use
the installed ID unchanged.
The provider return uses query mode with the exact configured issuer, code,
state and original browser cookies. The flow ID comes from the native state
lookup, never the query. The original bound native transaction is charged the
callback quota before exchange. Only a fresh acknowledged completion returns a
303 with separate secure session and CSRF cookies at the exact allowlisted
success URL. Replay, denial and unresolved outcomes do not deliver credentials.

Use the explicit enterprise session admission profile for session read and
strict cookie logout. This transport does not select that policy, expose
provider tokens, implicitly create links/provision accounts, or enable another federation
protocol. Do not record the raw callback URL, query, code, state or cookies.

## Explicit linking for an active member

Use `NewSigninStartFeatureWithLink` and `NewSigninCallbackFeatureWithLink`
together to opt in. Send `link: true` on the existing keyed JSON start route,
omit `flowID`, and supply the original fresh password-session cookie and
`X-CSRF-Token` with the exact Origin. `remember` must be omitted or false.
The session cookie must be `SameSite=Lax` for the top-level provider return;
the existing signed device cookie remains required. Omitting `link` continues
to use the anonymous flow and must not send `X-CSRF-Token`.

Use the native `SharedCallbackRateSource` with both transport credentials.
The authenticated stored transaction selects the callback mode and quota
identity. A failed member check must not route to anonymous sign-in. A
committed link redirects to the selected allowlisted URL without setting a
session or CSRF cookie. Ordinary sign-in still issues its own credentials.
The previous password session may be invalidated by the credential change.
