# Magic-link HTTP

Experimental Go 1.27 backend library, not a UI. This optional module is not
imported by base `identity/http` and imports no PostgreSQL adapters.

## Quick start and adoption

Provide `RequestConfig` with native `magiclink/postgres.RequestService`, a shared
`identityhttp.AuthRateLimiter`, trusted network/tenant mapping, exact HTTPS
`Origin` and allowlisted `CallbackURL`, service actor, current policy revision
and 1ms..30s call budget. Supply the existing session-owned signed browser-device
profile and prompt trusted clock; reuse initialization's dedicated keys/policy.
Both routes require `__Host-identity_device` alongside the original flow cookie.
Device correlation is not authentication, MFA or a trusted-device factor.
Install native migrations and keys before serving.
Borrowed services must support concurrency and outlive handlers; drain before
closing owners.

Call `NewFeature(FeatureConfig{Request: &config})` and contribute it to
`identityhttp.FeatureServices` using `NewDocumentedHandler` or `NewRouter`.
`NewRequestHandler` also supports direct mounting. Middleware variants bind
actual decoding, normalization, admission and native-call phases. Omission
exposes no route or OpenAPI metadata; construction performs no IO.

POST `/v1/magic-link/request` with exactly:

```json
{"commandID":"<stable-original-command>","email":"person@example.test","intent":"signin-only","callbackURL":"https://app.example/login","preAuthID":"<original-flow>"}
```

Supply one `Idempotency-Key`, exact trusted `Origin`, and the existing
`__Host-identity_flow` cookie. Preserve command, input and key after uncertainty.
Cookie parsing is not authentication: native processing rechecks current
tenant/browser/intent custody and authority. The native profile must support
the requested intent; `signup-if-allowed` does not bypass account/factor policy.

## API and outcomes

`RequestService` supplies processing and frozen normalization ports.
`RequestConfig` selects trusted composition. `NewRequestHandler` selects direct
initiation; `NewFeature` adds concrete selected-route metadata. Both have
middleware variants. `RequestResponse` preserves original command/outcome.

200 means committed processing, not account existence or queued/sent mail;
suppressed recipients receive the same acknowledgement. 400 is invalid input,
403 origin/HTTPS/native denial, 404 path, 405 method, 409 conflict/busy, 421
unmapped host, 429 exhaustion and 503 unavailable/unknown. Inspect
`commitOutcome`: a known commit remains committed after disclosure failure.
Entered work that panics remains unknown, not fabricated rollback. `commandID`
supports native proof-free recovery but is not recovery authority. There is no
automatic retry, recovery endpoint, redirect or session issuance.

## Security and tradeoffs

Trusted IP admission precedes owning address normalization; destination admission
uses only its canonical result. Budgets share existing delivery IP10/hour and
tenant/destination5/hour owners without fallback or double IP debit. Earlier
debits remain after later denial. Admission cannot replace native risk,
recipient, factor, browser or protected-transaction authority.

Closed bounded JSON rejects duplicates, unknown fields and alternate credential
channels. Responses are JSON/no-store/nosniff; cookies, credential headers,
redirects and trailers are stripped at commitment and middleware unwind. Never
log input or canonical rate source. Middleware is trusted synchronous borrowed
code, not authority; it must honor cancellation and not retain input.

## Explicit consumption

Select `Consume: &consumeConfig` independently or together with `Request`.
`ConsumeConfig` uses the native `magiclink/postgres.ConsumeService`, existing
`ChallengeVerificationRateLimiter`, exact trusted network/Origin/callback,
service actor/query revision, native issuer audience/session-cookie policy and
a prompt trusted clock. Call `NewConsumeHandler` for direct mounting.
Set `ProofLimits` to the native issuer's selected limits, including its supported
prospective-signup caveat count. Zero retains the generic default; narrower
limits remain restrictive. Parsing does not authorize consumption or replace
the native owner's exact signature, scope and transaction checks. Reference
composition supplies these limits from its actual selected issuer.

POST `/v1/magic-link/consume` with closed JSON containing `commandID`,
`preAuthID`, `token` and `callbackURL`, and the original flow cookie. Use the
original consuming command, distinct from the request that issued the link.
Do not send `Idempotency-Key`, Authorization, query tokens or a scanner GET.
IP admission precedes bounded proof parsing and authenticated native source;
subject/challenge admission retains original signed lifetime. Only the native
protected transaction can consume the link and create the session.

Fresh exact commitment delivers the native bearer only in its Secure/HttpOnly
cookie and CSRF synchronizer in `X-CSRF-Token`. JSON carries original outcome
and historical session ID, not either secret or subject. Current source subject,
grant/command, audience, session/CSRF binding, original expiry and cookie profile
must agree before delivery. Replay returns409 without credentials; unknown,
cancelled, mismatched or error-bearing results withhold them. Known commitment
is not rewritten as rollback. Native proof-free recovery does not redeliver.
Owned ingress proof custody is cleared after every pipeline exit; this local
cleanup is not durable one-time consumption.

Set `ConsumeConfig.MFAContinuation` only with the native consumer's explicit
MFA profile. An enrolled TOTP account then receives challenge-only JSON
(`challengeRequired`, `challengeID`, `challengeMethod`, `challengeExpiresAt`)
and its reveal-once proof in `X-MFA-Token`. This is **not** authentication: no
session cookie or `X-CSRF-Token` is delivered. Keep the original browser flow
and submit the child to the selected MFA completion owner; do not put either
token in redirects, logs or analytics. Replay/error/unknown results never
redeliver, and response commitment cannot extend the original expiry.
The wire schema exposes this arm only when selected. Complete reference TOTP
completion remains in development.

## FAQ and qualification

There is no UI. Consumers supply configuration and native services, not missing
handlers/stores. Request and consuming transports are implemented; reference
qualification and complete magic-link functionality remain unfinished.
Transport tests use real decoder/network/origin and primitive counting with
explicit native-IO/shared-consistency seams. The native PostgreSQL integration
suite separately exercises the selected HTTP request/delivery/consume journey,
actual strict rate storage and authentication of the delivered session cookie.
See `CHANGELOG.md`; no stable release is claimed.
