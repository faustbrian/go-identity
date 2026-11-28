# Impersonation HTTP

This opt-in contribution exposes approved-grant Start and browser self-stop.
Install the native self-stop and existing request-key preparation migrations
before composing native services for the selected routes. Select
`NewStartStopFeature` to use one ingress policy for both, or
`NewStartFeature` or `NewStopFeature` to expose just one. Base HTTP does not
import this adapter.

## Start

`POST /v1/impersonation/start` requires the exact mapped HTTPS Origin,
the original ordinary administrator cookie and its `X-CSRF-Token`,
one `Idempotency-Key`, and JSON with only `grantID` and
`expectedVersion: 2`. The grant must independently be approved. Native
`NewKeyedStartService` owns policy, current authority, durable keyed
admission and replay. Child cookies never substitute for the original
administrator or its synchronizer.

The original acknowledged commit alone returns a host-only, Secure,
SameSite=Strict child credential and a separately readable child
synchronizer. Neither the ordinary cookie nor its proof is changed.
The child bearer is HttpOnly. Browser cookie lifetime is capped at 15
minutes; authoritative grant expiry can be sooner. The credential-free
JSON marks the actor, target and grant. A receipt-only retry returns
`credentialIssued: false` without setting any cookie.

## Stop

`POST /v1/impersonation/stop` accepts strict JSON `{}`, the exact mapped
HTTPS Origin, the `__Host-identity_impersonation` cookie and its
`X-CSRF-Token` synchronizer. The client reads the separate
`__Host-identity_impersonation_csrf` cookie for the header. The configured
ordinary actor cookie is optional. Its value, when present, is passed
separately for native verification against the original parent; it does not
authorize self-stop or substitute for child credentials. The adapter never
issues or clears an ordinary session cookie.

This repeat operation accepts no Idempotency-Key or client command ID. Each
call uses one native command; only its exact successful commit clears the
two child cookies. Failed, canceled and ambiguous attempts do not clear
cookies, and the adapter does not retry an unresolved mutation. An exact
known response includes the command ID for operator correlation. There is no
automatic HTTP recovery, approval, revoke or Reference composition in
this selection.
