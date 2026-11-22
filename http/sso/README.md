# Enterprise SSO discovery HTTP feature

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
