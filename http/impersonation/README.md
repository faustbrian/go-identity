# Impersonation HTTP

This opt-in contribution exposes browser self-stop for a prepared native
impersonation session. Install the native self-stop migration and compose a
native `NewServiceWithSelfStop` before selecting `NewStopFeature` in the
shared HTTP dispatcher. Base HTTP does not import this adapter.

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
automatic HTTP recovery, Start, approval, revoke or Reference composition in
this selection.
