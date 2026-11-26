# OIDC workflow HTTP

Optional Go 1.27 transport for native explicit-self linking and existing-account
signin, plus independently selected public provider discovery. Importing this
module exposes no routes. Construct `NewFeature` with the
exact selected `LinkStart`, `SigninStart` and/or `Callback` configuration and
contribute it to `identity/http` composition. Native owners supply persistence,
protocol and authentication; these handlers supply transport, not new engines.

## Google One Tap popup transport

`NewOneTapStartFeature` opts into the canonical keyed start POST and
`NewOneTapCallbackFeature` opts into the separate credential callback POST.
When exposing both, combine their operations under the single feature ID
`identity/oauth/onetap`. Configure the exact HTTPS origin, the matching tenant
and signed device policies, the existing provider rate owner, and native Start
and Callback adapters. The package does not load Google scripts or own UI.

Start accepts one bounded prompt or popup-button selection and the caller's
Remember choice, not a provider or redirect override. A fresh native commit
returns the approved GIS options, client ID, nonce, flow ID and expiry; only
that response sets the original flow cookie. Retry uncertain Start only with
the same key and unchanged input. A replay does not issue another cookie.
A deliberate new Start may replace a previous flow cookie; that cookie never
selects or authorizes the new request.

Callback takes the returned flow ID, the original flow and device cookies,
and Google's `credential` and matching `g_csrf_token` cookie/body value.
See [Google's server-side verification guide](https://developers.google.com/identity/gsi/web/guides/verify-google-id-token)
for the double-submit protocol. Only fresh native sign-in returns a session
cookie and a separate synchronizer cookie. No credentials are returned in
JSON or on replay; unknown outcomes require native receipt recovery. These
routes do not select redirect mode, signup, or account linking.

## Public configured-provider catalog

`NewProviderListFeature(ProviderListConfig{Network: network, Catalog: catalog,
Rate: safeRate, MaximumDuration: time.Second})` selects only
`GET /v1/oauth/provider-list`. Supply the actual immutable
`providers.NewCatalog` snapshot built from the same selected native providers
and the existing shared `identityhttp.SafeRateLimiter`; no signin, link,
callback, session reader or PostgreSQL owner is required. Contribute the feature
to `identityhttp.NewDocumentedHandler` or `NewSelectedHandler`. The independent
`NewProviderListHandler` exposes the same transport without feature composition.
Omitting this feature leaves its route and advertised capability absent.

Use an allowlisted HTTPS public or tenant host and a required canonical decimal
`limit` from 1 through 100. Omit `cursor` for the first page; otherwise send the
nonempty opaque `nextCursor` unchanged with the same limit and catalog snapshot.
No implicit limit is selected. A successful response contains only:

```json
{"page":[{"id":"github","displayName":"GitHub","supportedModes":["authorization_code"]}],"nextCursor":"opaque-continuation"}
```

The exhausted page omits `nextCursor`; an empty catalog returns `{"page":[]}`.
Only configured native-supported modes are advertised, not planned providers,
signup, direct-token signin, refresh or logout. Client IDs, secrets, issuer and
other endpoints, scopes and raw profiles are never returned. Responses are
bounded, no-store/nosniff JSON and never issue cookies or redirect.

This public read requires no Origin, CSRF token or session. Ambient cookies are
ignored; Authorization, Idempotency-Key, bodies, trailers and extra query
selectors are rejected. Exact routes do not enable HEAD or aliases. Malformed
input returns 400, native denial 403, unknown host 421, exhausted rate 429 and
unavailable/canceled authority 503, without raw diagnostics. The existing shared
safe-rate owner supplies its IP100/minute policy, known-unavailable IP20/minute
emergency policy and mandatory degradation events. Only a known rate denial
emits its ceiling-seconds `Retry-After`; catalog failures invent no retry delay.
The server still owns raw IO and write deadlines, and borrowed owners must
honor the configured whole-operation deadline.

### Optional provider-list localization

Set only `ProviderListConfig.Localization` to select public translated denial
messages. Supply `ProviderListLocalizationConfig{Catalogs: catalogs,
DefaultLocale: "en"}` using `i18n.NewCatalog`. Each catalog's messages use this
module's exported `ProviderListInvalidRequestMessage`,
`ProviderListDeniedMessage`, `ProviderListRateLimitedMessage`, and
`ProviderListUnavailableMessage` IDs. All four need parameter-free default-locale
translations; other locales may omit a message and fall back to that default.
Catalogs are trusted public text and frozen at handler construction. Replace
translations by constructing a new handler; never include provider diagnostics,
credential data, cursor text or enumeration state in a template.

With this explicit opt-in, only 400, 403, 429 and 503 provider-list responses may
add a JSON `message` alongside the unchanged machine `error`. They remain
`application/json`, retain their status and existing `Retry-After`, and vary on
`Accept-Language`. A rendered message has `Content-Language` equal to its actual
catalog locale, including message fallback. Successful pages and other errors
remain unchanged. The generated operation documents only the selected profile.

The public route uses one `Accept-Language` field (at most 4096 bytes and 32
ranges), then the configured default. Regional lookup, weights and exclusions
are owned by `identity/i18n`; duplicate fields, malformed or duplicate ranges
use the default. Explicit exclusion of every supported locale, cancellation,
or an oversized serialized message retains the machine-only response without
`Content-Language`. No locale is stored, no cookie is read or written, and no
session preference or signin handler participates. Nil localization preserves
the original exact machine-only response and wire contract.

## Supported profile

- One explicitly configured HTTPS OIDC code/query/S256 provider per selected
  callback route, with a fixed client, issuer, nonce policy and redirect URL.
- `POST /v1/account/link-start`: current fresh cookie session, exact Origin,
  original `X-CSRF-Token`, required `Idempotency-Key`, configured provider/scopes
  and allowlisted success/error application callbacks. Signup is disabled.
- `POST /v1/oauth/signin-start`: original OAuth preauth flow ID, flow/device
  cookies, resolved Remember choice, exact Origin and required Idempotency-Key.
  Reuse that original flow for keyed retries. This route performs no current
  session/user lookup and does not itself issue a session.
- `GET /v1/oauth/callback`: exact issuer, original state and original browser.
  Native state reservation precedes verifier release and exchange; commitment
  redirects with 303. An exact committed retry returns the original result
  without another exchange or newly valid session epoch.

Select `Config.Signin` only with the native operation resolver, signin rate
attribution and completion owners. Stored intent selects link versus signin;
ambient cookie presence and native denial never choose another method. Keep
`Signin` nil for the original linking-only callback. Flow/device cookies must be
Lax for top-level provider navigation. The selected signin browser profile uses
same-origin application callbacks and a distinct `session.CSRFCookiePolicy`.
Only a new exact committed signin emits the HttpOnly session cookie and separate
readable synchronizer cookie. Browser code copies that CSRF value into the
existing strict logout header; it is never authentication or a URL parameter.

Configuration supplies the real native `LinkService`, common current session
reader and strong shared HTTP rate limiter, not application-built transactions
or proof factories. Native owners retain all current user, credential, factor,
policy, session, one-use, vault and rollback authority. HTTP rate attribution is
not authentication or permission to exchange a code.

## Security and adoption

The callback provider is selected by deployment, never inbound issuer or Host.
Query custody is bounded and destroyed on all return paths; provider error text
is not exposed. Responses are no-store. Shared provider/IP and original
transaction budgets deny on unavailable rate authority; there is no local
fallback. The signin-enabled shared callback returns 429 on known budget denial
with the owning limiter's bounded ceiling-seconds `Retry-After`; outages do not
invent a retry delay. This does not change the original linking-only handler.
Callback top-level navigation may omit Origin; any present Origin
must match, and native state remains bound to the original browser and origin.

Provider-error callbacks consume their original state and redirect to the
original allowlisted error callback only after committed secret erasure, without
exchanging a code or issuing a session. These handlers do not select implicit
signup, enrolled-MFA fallback, refresh, unlinking, popup, direct-token/hybrid or
form-post variants.
Native workflow integration, complete acceptance, public source pins and final
qualification are required before claiming a delivered consumer milestone.
