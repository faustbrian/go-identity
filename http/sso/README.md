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

## Existing-linked-member static OAuth2

Select `NewOAuth2SigninStartFeature` and `NewOAuth2SigninCallbackFeature` for
the keyed start and `GET /sso/oauth2/callback`. To retain a static OIDC
provider on the same start route, use `NewSigninStartFeatureWithOAuth2` and
select each callback separately. OAuth2 requires the configured `domain`;
the exact Origin, original browser and idempotency contract stay the same. Only an installed
`providerID` selects the configured owner. A caller cannot supply
`protocol` or opt an OAuth2 provider into OIDC member linking.

Bind the native linked-member OAuth2 completion owner and its read-only
`SigninCallbackRateSource` through the typed transport interface. Use the
exact tenant HTTPS origin plus `/sso/oauth2/callback` for the provider's
registered redirect. The raw query remains native custody: authenticated
original state supplies the transaction quota before native issuer validation,
settlement and exchange. No issuer, query cookie or callback URL selects a
provider or creates session authority. Only a fresh acknowledged native
completion sets cookies and redirects. Select strict OAuth2 cookie admission
for the later read and logout. Omit these features to expose no OAuth2 route
or OpenAPI operation, and redact all raw callback URLs from access logs.

## Existing-linked-member SAML browser sign-in

Select `NewSAMLSigninFeature` for one installed provider and add the same
`SAMLSigninConfig.ACSNavigationPolicy()` to `NewRouter`'s `TransportPolicy.CORS`.
Configure the tenant HTTPS SP origin, the IdP HTTPS origin and signed Redirect
endpoint, allowlisted application return URLs, and native start/completion
owners. The other SAML endpoints are not selected, and the ACS can never
grant CORS access or a preflight.

Initiate at `GET /saml2/{provider_id}/login` from a document on the selected
SP origin. Ordinary browser navigation must supply same-origin Fetch Metadata;
clients that send `Origin` must send the exact SP origin. There is no Referer
fallback. An optional `Idempotency-Key` aliases the original native command;
it does not select a flow. Start delivers only the signed Redirect and a
dedicated five-minute, exact ACS-path correlation cookie.

The IdP returns by form POST to `POST /saml2/{provider_id}/acs` using its
configured Origin, the original RelayState and the signed SAML response. No
normal Lax session/device cookie or browser-supplied flow ID is required. Only
fresh acknowledged native settlement returns the allowlisted redirect, normal
session and CSRF cookies and removal of the dedicated cookie. Replay or denial
never returns those credentials. Do not log `Location`, cookies, RelayState
or the SAML response. Select native SAML session access and local logout
separately; this feature does not select JIT, IdP-initiated sign-in or SLO.

## SAML Single Logout POST

For each installed provider that supports this profile, include
`NewSAMLLogoutOperation` in the selected `sso/saml` feature and install its
`SAMLLogoutConfig.NavigationPolicy()` on the same router. Set the exact SP
and IdP HTTPS origins, the IdP's exact POST reply URL, a bounded native SAML
logout owner, and any exact SP-origin continuation URLs. Omit the operation
and policy when this profile is not selected.

The configured IdP posts exactly one Base64 form field (`SAMLRequest` or
`SAMLResponse`) to `POST /saml2/{provider_id}/slo`. This navigation grants
no script CORS access, uses no session cookie, and does not accept
`RelayState`. Only a fresh acknowledged native request can produce a manual
signed-response form that submits to the pinned IdP endpoint. A settled IdP
response can redirect only to an exact configured SP continuation. If the
native owner returns no delivery, the endpoint returns 204. Do not log
the XML, encoded form fields, response HTML, or provider URL. This operation
does not start an SP-initiated logout.

## Enterprise OIDC provider logout

Select `NewProviderLogoutFeature` with the same tenant network and shared
rate configuration as `NewRouter`, the existing session and CSRF cookies, and
an owner bound to the native PostgreSQL logout service. Register the exact
`https://<tenant-host>/sso/oidc/<provider-id>/logout/callback` at each provider
with a configured end-session endpoint. A provider with no endpoint supports
local-only logout and has no callback route.

Send `POST /sso/oidc/<provider-id>/logout` with the original session cookie,
exact tenant `Origin`, `X-CSRF-Token`, `Idempotency-Key`, and JSON such as
`{"finalRedirect":"https://app.example/signed-out"}`. The final target must
exactly match the configured allowlist. A confirmed local revocation deletes
both cookies and returns either the provider redirect (303) or a local-only
outcome (200). Keep the original request and retry key on unresolved receipt.

The provider return needs no local cookie. A valid return settles the original
state once; only committed success may redirect to the allowlisted final
target. Refusal and timeout leave the local revocation intact. Do not log raw
callback queries, session inputs, or provider `Location` values.
