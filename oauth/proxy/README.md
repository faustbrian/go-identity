# OAuth preview callback

`github.com/faustbrian/go-identity/oauth/proxy` implements the production-side
coordinator for a selected OIDC preview handoff. It selects one configured
production callback URI and exact HTTPS registrations for preview deployments.
The selected OIDC adapter returns verified evidence only, never provider tokens.

## Trusted preview initiation

Construct `PreviewInitiationAdmission` once per trusted deployment registration.
Configure its exact tenant and actor Directory IDs, issuer, audience, canonical
HTTPS `PreviewTarget`, `authentication.Authenticator` from
`github.com/faustbrian/go-authentication/v2`, and a positive authentication budget
of at most 20 seconds. Issuer and audience accept 1..2048 visible ASCII bytes,
without whitespace or normalization. Configuration is not request-selected.

`Admit` passes the request's 1..8192-byte bearer token to that authenticator with
the earlier caller or configured deadline. It requires an authenticated result
with the exact configured actor and issuer, exactly one configured audience and
exactly one `identity.oauth.proxy-start` scope. Context principals and tenant
hints are not authority. The authenticator must honor cancellation, support
concurrent reuse and not retain borrowed credentials; admission starts no
background work and never accepts a late success or a panic.

Supply independent canonical command and transaction IDs, a nonzero request
fingerprint and the already resolved `session.RememberPolicy`. Successful
admission returns those unchanged with the configured registration, but no raw
credential. Keep this binding within trusted composition: formatting is redacted
and JSON/text serialization is rejected. `InitiationInvalid`, `InitiationDenied`
and `InitiationUnavailable` are stable redacted failures without diagnostics.

Admission does not create OAuth state, reserve a transaction, perform provider
exchange, write a user or session, or expose an HTTP route. Those owners must
still enforce their own current authority and atomic one-use operation.

## Production callback

Construct `ProductionCallback` with an `oauth.OIDCProxyExchange`, the configured
evidence codec and a durable `ProductionCallbackStore`. The store must reserve
the original state and fence its current authority before releasing PKCE. A
trusted HTTP adapter supplies the actual registered callback URI and raw query to
`Handle`. It must never derive the trusted URI from unverified request headers.

Native adapters that already own reservation, preparation and settlement can
use `NewProductionCommandCallback` instead, passing a
`ProductionCallbackCommandStore` and leaving `ProductionCallbackConfig.Store`
nil. The adapter runs the supplied synchronous generation only after its
original durable reservation and generation marker. It must acknowledge the
commit before returning. Retained evidence may be reconciled without invoking
the provider again or giving a replay a fresh handoff.

On success, `Handle` returns an encrypted result and the exact registered
destination only after token disposal and acknowledged settlement. It does not
set cookies or write local identity state. Do not log callback queries or the
handoff, and do not automatically retry exchange on `CallbackReconcile`. Look up
the original durable outcome and withhold any unresolved handoff.

The store is the native replay and audit owner. This module does not ship the
PostgreSQL adapter or HTTP route yet. Opening the evidence is not the same as
consuming it: preview must still reserve and consume its own artifact before
using the verified subject for local sign-in.
