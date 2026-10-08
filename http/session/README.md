# Session HTTP integration

An optional Go 1.27 module. Importing `identity/http` does not import this module
or the session implementation. This checkpoint owns the real session-read
handler, not the full session transport, feature/router/OpenAPI composition or
release-qualified backend platform.

## Quick start and ownership

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

## Adoption, tradeoffs and FAQ

Use one rate limiter per process/deployment namespace across selected routes.
Subject admission requires owner authentication, so read authentication precedes
combined IP/subject admission. This handler does not claim a preauthentication
database-work budget. Its canonical rate counters remain owned by the primitive.

Cookie delivery/CSRF, enrichment/extensions, signout, feature descriptors,
rendered OpenAPI, browser/reference journeys and exact coverage/mutation/release
gates remain required subsequent work. A bare handler is not that complete
transport. Published dependency/checksum resolution is pending; local development
uses immutable owned-source archives only in disposable test modfiles, never
permanent module replacements. See `CHANGELOG.md` for release notes.
