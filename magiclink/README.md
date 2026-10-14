# Magic-link workflows

This experimental module currently provides read-only signed-scope inspection.
The complete durable request, delivery, consumption, resend and session workflow
is in development; this module is not yet a usable passwordless login service.

## Scanner-safe inspection

Construct `NewInspector` with the upstream `capability.Service`, trusted tenant,
exact issuer/audience, exact HTTPS callbacks, explicit lifetime and timeout.
Construction snapshots callback policy without callbacks or IO. Pass the opaque
proof and exact callback to `Inspect`; keep the proof alive until the call ends.
Calls may overlap when the borrowed verifier supports concurrent calls.

Inspection authenticates signature, upstream key/time/revocation policy and the
closed one-use magic-link profile. The profile binds `magiclink.identifier`,
`magiclink.callback` and `magiclink.intent`; the latter is exactly `signin-only`
or `signup-if-allowed`. Callbacks are compared as original strings, not suffixes
or normalized equivalents. Invalid input, scope denial, authenticated expiry
and unavailable authority have redacted typed classifications. Caller
cancellation and deadlines remain context errors. Collaborator panics deny.

Inspection has no consumption or transaction dependency. It never issues,
reserves, consumes, redirects, transfers proof bytes or returns the selected
recipient, user or session. No raw bearer should appear in URLs or diagnostics.

**`SignatureValid` is not login permission.** It says nothing about remaining
uses, supersession, current account/factor/risk authority or original browser
possession. Even a consumed link can retain a valid signature. The eventual
native explicit-consume workflow must recheck the full original intent and
current authority, then consume and issue the session in one protected
transaction. Inspection cannot be used as a session issuer or a replacement
for that workflow.

The module retains the existing capability format and upstream opaque proof.
It adds no token store, replay cache, key engine or consumption table. PostgreSQL
workflow composition, HTTP/reference exposure and final release qualification
remain outstanding.
