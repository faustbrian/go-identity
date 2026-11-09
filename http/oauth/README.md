# OIDC linking HTTP

Optional Go 1.27 transport for the native `identity/oauth` explicit-self linking
workflow. Importing this module exposes no routes. Construct `NewFeature` with
the exact selected `LinkStart` and/or `Callback` configuration and contribute it
to `identity/http` composition. The reference backend supplies concrete native
owners through `SocialOAuth` and independent `HTTPSocialOAuth` selections.

## Supported profile

- One explicitly configured HTTPS OIDC code/query/S256 provider per selected
  callback route, with a fixed client, issuer, nonce policy and redirect URL.
- `POST /v1/account/link-start`: current fresh cookie session, exact Origin,
  original `X-CSRF-Token`, required `Idempotency-Key`, configured provider/scopes
  and allowlisted success/error application callbacks. Signup is disabled.
- `GET /v1/oauth/callback`: exact issuer, original state and original browser.
  Native state reservation precedes verifier release and exchange; commitment
  redirects with 303. An exact committed retry returns the original result
  without another exchange or newly valid session epoch.

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
fallback. Callback top-level navigation may omit Origin; any present Origin
must match, and native state remains bound to the original browser and origin.

Provider-error callbacks consume their original state and redirect to the
original allowlisted error callback only after committed secret erasure, without
exchanging a code or issuing a session. This development profile does not yet
select social signin, refresh, unlinking, popup, token/hybrid or form-post variants.
Native workflow integration, complete acceptance, public source pins and final
qualification are required before claiming a delivered consumer milestone.
