# OAuth preview callback

`github.com/faustbrian/go-identity/oauth/proxy` implements the production-side
coordinator for a selected OIDC preview handoff. It selects one configured
production callback URI and exact HTTPS registrations for preview deployments.
The selected OIDC adapter returns verified evidence only, never provider tokens.

Construct `ProductionCallback` with an `oauth.OIDCProxyExchange`, the configured
evidence codec and a durable `ProductionCallbackStore`. The store must reserve
the original state and fence its current authority before releasing PKCE. A
trusted HTTP adapter supplies the actual registered callback URI and raw query to
`Handle`. It must never derive the trusted URI from unverified request headers.

On success, `Handle` returns an encrypted result and the exact registered
destination only after token disposal and acknowledged settlement. It does not
set cookies or write local identity state. Do not log callback queries or the
handoff, and do not automatically retry exchange on `CallbackReconcile`. Look up
the original durable outcome and withhold any unresolved handoff.

The store is the native replay and audit owner. This module does not ship the
PostgreSQL adapter or HTTP route yet. Opening the evidence is not the same as
consuming it: preview must still reserve and consume its own artifact before
using the verified subject for local sign-in.
