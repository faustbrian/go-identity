# Impersonation HTTP

This opt-in contribution exposes approved-grant Start, browser self-stop
and distinct-administrator denial of a pending grant.
Install the native self-stop and existing request-key preparation migrations
before composing native services for the selected routes. Select
`NewStartStopFeature` to use one ingress policy for both, or
`NewStartFeature` or `NewStopFeature` to expose just one. Base HTTP does not
import this adapter. Select `NewDenyFeature` for denial alone or
`NewStartStopDenyFeature` for all three on the same ingress.

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

## Deny

`POST /v1/impersonation/deny` requires the mapped HTTPS Origin and the
distinct ordinary administrator's cookie and stored `X-CSRF-Token`.
Send only `grantID`, `expectedVersion: 1` and a private non-blank
`reason` of at most 1024 UTF-8 bytes. Do not send `Idempotency-Key`,
a caller-selected command ID, or a bearer header.

Compose the native `NewServiceWithDenial` only after its migration history
through version 9. Use the existing shared audited admin quota, with the
same namespace and key as other administrative operations. The admitted
native preparation supplies the actual actor before the rate debit; a quota
failure never invokes native Execute.

On success, JSON includes `denied: true`, the committed outcome, and the
exact command and grant IDs. No response includes the reason or changes
any cookie. Repeating the semantic request after a denial returns a
conflict, without another terminal effect. The transport never retries an
unresolved native command. This selection enables no approval, quorum or
revocation endpoint.
