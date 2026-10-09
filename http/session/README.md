# Session HTTP integration

An optional Go 1.27 module. Importing `identity/http` does not import this module
or the session implementation. This checkpoint owns session-read and self-signout
handlers, not the full session transport, feature/router/OpenAPI composition or
release-qualified backend platform.

## Quick start and ownership

Select `NewPreAuthHandlerWithBrowserDevice(config, deviceConfig)` or
`NewPreAuthFeatureWithBrowserDevice(config, deviceConfig)` to include the
session-owned browser correlation cookie. Dedicated versioned keys, namespace,
bounded lifetime and `__Host-identity_device` policy are mandatory. Share the
same device configuration with the selected OTP Send transport. Existing
flow-only constructors do not select or inspect this cookie. A valid device is
reused across flows without renewal; invalid/duplicate/expired custody denies
before preparation. Absent custody is generated only after IP admission and
delivered alongside the flow cookie only on fresh successful commitment.
This signal is not authentication, hardware identity or MFA trust. Clearing or
copying it can evade/share correlation; IP and identifier controls remain
independent requirements. Middleware variants retain protected dual-cookie
ownership. Neither constructor alone proves a complete browser login journey.

For an original browser login flow, construct `NewPreAuthHandler(PreAuthConfig{
Network: network, Service: preAuthService, Rate: authRate, Cookie: flowCookie,
Lifetime: sessionLifetime, Origin: trustedOrigin, Action: trustedAction,
CallbackURL: trustedCallback, PolicyID: policyID, PolicyVersion: policyVersion,
Now: trustedClock, MaximumDuration: handlerBudget})`. The selected reference
`FeatureSet.PreAuth()` handle satisfies the borrowed service interface; do not
write another flow store or issuance workflow. Use the secure
`__Host-identity_flow` Lax/Strict cookie policy and the same configured issuer
action/origin/callback/policy. Empty callback explicitly disables redirects.

Only `POST /v1/session/preauth-issue` accepts bounded JSON `{}` or an optional
boolean `remember`. Null, extra/duplicate fields, query, trailers, Authorization
and Idempotency-Key deny. The request needs the exact configured HTTPS Origin
and host-mapped tenant. Ambient cookies are not authentication for initiation.
IP-only shared `rate.auth` admission precedes command/flow entropy and persistence.
Each deliberate fresh start is independent; the handler never retries an unknown
outcome or prepares another command as recovery. Subsequent OTP Send must use
the returned original flow ID/cookie and its own keyed contract.

The native issuer resolves the original five-minute flow independently of final
session persistence. Remember is resolved once through Lifetime before Prepare
and checked unchanged in the original command. Only an exact fresh committed,
error-free result delivers the cookie; replay, expiry, failure and cancellation
emit none while preserving known native outcome and safe original locators.
The response contains no nonce, digest or bearer. Native recovery requires its
current policy and never delivers or renews a cookie. For selected routing and
OpenAPI, pass `NewPreAuthFeature(config)` to `FeatureServices` alongside any
other explicitly selected features. This separate contribution does not select
session reads/logout or OTP; `NewFeature` remains unchanged. Omission exposes no
initiation route or metadata. `NewPreAuthFeatureWithMiddleware` retains the same
owned typed phases. Construction performs no issuance or network IO. The real
PostgreSQL/browser journey and complete release qualification remain pending.

To select reads/logout and initiation together, use
`NewFeatureWithPreAuth(signOutConfig, preAuthConfig)` (or its
`NewFeatureWithPreAuthAndMiddleware` variant). These operations retain one
canonical session feature owner; do not add two `identity/session`
contributions to the same selection. Duplicate owners reject atomically.

Cookie acquisition uses the base transport's shared strict decoder. Trailing
SP/HTAB in either the selected cookie value or an unrelated cookie value denies
before session lookup; values are not repaired into valid credentials. Token
format validation remains session-owned, and bearer mode still ignores cookies.

For protected opt-in `GET /openapi.json`, call `NewMetadataRouter(ctx,
identityhttp.DocumentConfig{Title: title, Version: version}, MetadataConfig{
Read: getConfig, Authorization: authorizer, PolicyRevision: revision,
Action: action, ResourceType: resourceType}, selectedServices, middleware)`.
`authorizer` is the existing authorization engine, not a new role callback.
It must explicitly allow the owner-established user and host-mapped tenant for
the configured action/resource type and fixed `identity.openapi.document`
resource ID at the configured revision. No permission is inferred from scopes,
headers, a user ID supplied by the client, or mere authentication.

This selects only protected metadata plus the supplied services, not session
routes or a public alternative. It uses `getConfig`'s bounded session cookie or
bearer profile, network, clock, whole-handler duration and shared safe-rate owner.
Missing/inactive sessions return 401, explicit authorization denial 403,
rate denial 429, and stale/expired/failed authority 503. Both authenticated and
unauthenticated well-formed attempts share the trusted-IP budget; authenticated
attempts additionally share the tenant/user budget with other safe operations.
The exact immutable OpenAPI snapshot includes protected metadata once and no
unselected routes; no credentials, cookies or runtime host details are exported.
Global middleware sees real `GetState` and cannot replace original custody.

Select `identityhttp.NewProbeFeature` in the same `FeatureServices` to add
public `/healthz` and `/readyz` alongside protected metadata, including with
nonempty shared middleware. Those hooks receive no session principal or ambient
credentials on probes; probe output remains fixed and readiness remains owned
by the supplied lifecycle/dependency checks. Probe selection never grants
metadata access or implicitly enables session routes. Omitting the probe
feature omits both probe routes and their document entries.

This profile supports tenant-host administration and disables CORS grants.
The shared transport rejects plaintext with JSON `https_required` (403).
Cross-origin rejection is fixed `text/plain` `identity.http.origin_denied`
(403, or 408 if cancellation is observed during origin admission); neither
rejection enters session or policy work. OpenAPI describes both media profiles.
Public-realm mapping and JWT/API-key administration are not inferred. Base HTTP's
existing explicit public metadata profile remains distinct and metadata stays
off in ordinary constructors. Use `NewHTTPServer` for raw IO/streaming bounds.
Reference browser, provider, full feature and release qualification remain pending.

For shared secure transport, obtain descriptors with
`identityhttp.NewOperationDescriptors` and pass them to `identityhttp.NewRouter`
with `TransportPolicy.Network` equal to the feature network configuration,
explicit handler timeout/document identity and selected route CORS policies.
Router middleware binds into the actual GET/self-signout owner phases, retaining
one credential acquisition and one rate admission. Cookie serialization, CSRF,
primary revalidation and unknown-outcome recovery remain feature-owned. This is
selected composition, not all-session/browser/release qualification.

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
their bounded JSON denial bodies. The full security router remains in development.

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

`NewSignOutHandlerWithMiddleware` exposes the same four real phases for logout;
`NewFeatureWithMiddleware` applies a selected list independently to both real
routes. Existing constructors use those pipelines without hooks. Authenticate
discovers the original subject once, then the signout domain service performs
its existing required primary revalidation and protected transactional CSRF.
No extra router authentication or rate debit is introduced. `SignOutState`
provides credential-free `Principal()` and detached `Attempt()` projections.
An attempted result may be unknown, denied or unavailable; it does not assert a
commit. Copies of recovery metadata cannot change the original command. Only
normally returned uncanceled Handle attempts reach after-handler observation.
The original preliminary validity is rechecked after hooks, never extended.
The shared response guard suppresses every hook-created cookie and permits only
the owned exact deletion tuple after successful selected cookie logout. Bearer,
denied, ambiguous and short-circuit responses clear no cookies. Hooks must not
log/retain credential-bearing headers, retain state or start detached work.

Both handlers support base HTTP's `WithOperationMiddleware` binding after
feature construction. It preserves the frozen network/origin policy and
borrows the same domain owners, appends rather than replaces existing hooks,
and keeps response protection outside every hook. Original handlers remain
usable; binding never reconstructs them from mutable caller configuration.

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
