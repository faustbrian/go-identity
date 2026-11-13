# OIDC workflow HTTP

Optional Go 1.27 transport for native explicit-self linking and existing-account
signin. Importing this module exposes no routes. Construct `NewFeature` with the
exact selected `LinkStart`, `SigninStart` and/or `Callback` configuration and
contribute it to `identity/http` composition. Native owners supply persistence,
protocol and authentication; these handlers supply transport, not new engines.

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
