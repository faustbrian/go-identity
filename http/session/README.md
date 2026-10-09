# Session HTTP integration

An optional Go 1.27 module. Importing `identity/http` does not import this module
or the session implementation. This checkpoint owns session-read and self-signout
handlers, not the full session transport, feature/router/OpenAPI composition or
release-qualified backend platform.

## Quick start and ownership

Pass the same feature selection to `identityhttp.NewDocumentedHandler` for
concrete OpenAPI 3.1.1 and its matching handler snapshot. The feature owns the
real HTTP schemas separately from opaque direct contracts: optional cookie or
bearer credentials, no GET body/query, strict JSON/form logout, conditional
cookie CSRF, credential-free session metadata, exact clearing instructions and
original recovery outcomes. Structured logout failures and generic dispatcher
errors are both represented. `actorKind` serializes as an upstream string;
optional `linkMode` remains a numeric identity enum. No trusted origin, tenant,
host mapping, key or provider configuration enters the document. The full
security router, metadata endpoint and generated-client/browser qualification
remain required, not inferred from document export.

For both implemented routes, call `NewFeature(SignOutConfig{...})`, then pass
the contribution in `identityhttp.FeatureServices.Features` to
`identityhttp.NewSelectedHandler`. No application-written handlers or route
registration are needed. The selected snapshot contains exactly session get
and self-signout; omitting the feature exposes neither route nor their selected
metadata. Probes may be selected independently. The factory constructs both
real handlers without calling stores, clocks or policy callbacks, and rejects
nil/zero services and closed rate owners atomically. Configuration inspection
does not certify backend health; compose the same primary and policy owners and
retain their lifetime responsibility. This remains root-mounted exact dispatch,
not the full wire-OpenAPI/security-router implementation.

Call `NewGetHandler(GetConfig{...})` with a real owner-constructed
`*session.SessionService`, one shared `*identityhttp.SafeRateLimiter`, explicit
`session.CredentialCookie` or `session.CredentialBearer`, valid cookie policy,
trusted clock, whole-handler deadline and exact `identityhttp.NetworkConfig`.
The native PostgreSQL session service supplies primary authority in reference
composition. Do not supply a consumer-written domain store as authentication.

Construct dependencies before serving and retain them until handlers drain.
The handler borrows dependencies, starts no goroutines, owns no store or
transaction, and closes neither requests nor dependencies. The HTTP server owns
connection/body cleanup and bounded writes. Earlier request deadlines win.
Do not synthesize credential headers or mutate trusted request metadata in
middleware. No hidden registration, default transport or global state exists.

## API and security

`NewGetHandlerWithMiddleware(config, middleware)` adds trusted synchronous
hooks at the real before-auth, after-auth, before-handler and after-handler
boundaries. `NewGetHandler` uses the same pipeline without hooks. After-auth
and later hooks may call `identityhttp.PipelineValue[sessionhttp.GetState](r)`
and `state.Principal()` for detached credential-free metadata; neither the
value nor that metadata is a reusable authority proof. Before-auth has no
principal. Trusted hooks still receive original credential-bearing request
headers in their detached view: never log, serialize or retain those headers.
Only the typed state is credential-free. Middleware cannot replace the original
tenant/credential inputs,
read a body or repeat authentication/admission by calling next twice. Original
validity is checked after admission and again after before-handler hooks;
hooks cannot renew it. After-handler is read-only and observes an attempted
read, not a transaction commit. Short circuits suppress later stages. Borrowed
hooks must honor context, avoid retaining state and support concurrent requests.
The read handler enforces no-store/nosniff, JSON media type and no Set-Cookie at
response commit even for short circuits and attempted header removal. Hooks own
their bounded JSON denial bodies. Self-signout hook adoption and the full
security router remain in development.

Only exact `GET /v1/session/get` is accepted. Requests have no body, query or
Idempotency-Key. Tenant comes only from an exact trusted HTTPS host binding.
Unknown/public hosts return 421 before tenant-state access. Malformed requests
return 400, wrong path 404, wrong method 405, limits 429 with Retry-After, and
unavailable/canceled authority 503. Responses use fixed safe errors, JSON,
`Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.

Cookie mode rejects Authorization and ambiguous selected cookies. Cookie bounds
are 32 entries, 16KiB total value bytes and 3,800 bytes per selected name/value.
Bearer mode uses exactly one strict Authorization header and ignores ambient
session cookies; missing or invalid bearer cannot fall back. No credential is
accepted from query, body, form or redirects. Both modes forbid proxy credentials.

Successful `GetResponse` contains admitted principal, public session timestamps,
original lifetime deadlines and advisory refresh metadata, never token, lookup
digest, CSRF state, complete authority vector or historical proof. The handler
validates original owner custody after rate work; a copied result cannot renew
freshness. Unauthenticated is `{"authenticated":false,"needsRefresh":false}`.
Reading does not rotate, update activity, clear cookies or refresh authority.

## Self-signout

Call `NewSignOutHandler(SignOutConfig{...})` with the same `GetConfig` and
exactly the selected `CookieSignOut` or `BearerSignOut` owner. Cookie mode uses
the strict `*session.CookieSignOutService`, composed with the owned native
transactional CSRF executor, and an explicit exact HTTPS `TrustedOrigins`
allowlist. Referer fallback is denied. Bearer mode uses `*session.SignOutService`
and no trusted-origin configuration. All services must share the same primary,
policy and cookie configuration; a returned cookie tuple mismatch fails closed
without clearing transport, even when the original command committed.

Only `POST /v1/session/signout` is accepted. Use JSON `{}` with a single
`X-CSRF-Token` header, or URL-encoded form with that header or one `csrf_token`
field. Empty URL-encoded forms are valid; media type is always explicit. No
query, target/user/policy fields, Idempotency-Key or alternative credential
channels are accepted. Duplicate/equal token channels deny. Bearer mode rejects
CSRF inputs and ignores ambient cookies. Absent/inactive logout needs no CSRF
token; active cookie logout requires its exact token under the original primary
transaction, not merely syntactic parsing or an HTTP precheck. Origin remains
required for every cookie-mode request, including absent logout.

Successful logout revokes only its authenticated session and clears only its
selected transport. Cookie deletion uses the exact owned secure serializer;
bearer success returns `clearBearer:true`, never a Set-Cookie. Outage, denial,
ambiguity, conflict, in-progress and cancellation clear nothing, including a
committed receipt accompanied by a delivery error or cancellation. Unknown
outcome is never translated into rollback or automatically retried.

`SignOutResponse` includes a server-generated original `commandID`, explicit
`commitOutcome` and, when prepared, `SignOutRecovery` with the original exact
scope. `none` means no authoritative command observation. Recovery is a locator,
not permission: query the durable owner's recovery API under current policy
before retrying an unknown command. The underlying operation remains
`identity.session.revoke-one`; transport does not rename that recovery scope.
Errors are fixed redacted codes: malformed 400, denied 403, conflict/in-progress
409, rate 429 with Retry-After, and operational/ambiguous/canceled 503. Host,
path and method errors follow the read profile. All responses are no-store.

## Adoption, tradeoffs and FAQ

Use one rate limiter per process/deployment namespace across selected routes.
Subject admission requires owner authentication, so read authentication precedes
combined IP/subject admission. This handler does not claim a preauthentication
database-work budget. Its canonical rate counters remain owned by the primitive.

Cookie issuance/CSRF-token delivery, enrichment/extensions, feature descriptors,
rendered OpenAPI, browser/reference journeys and exact coverage/mutation/release
gates remain required subsequent work. A bare handler is not that complete
transport. Published dependency/checksum resolution is pending; local development
uses immutable owned-source archives only in disposable test modfiles, never
permanent module replacements. See `CHANGELOG.md` for release notes.
