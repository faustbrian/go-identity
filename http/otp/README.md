# OTP HTTP transport

## Email-signin Send

`NewEmailSigninSendHandler(EmailSigninSendConfig)` selects only
`POST /v1/otp/send` with closed JSON `flowID` and `email`, exactly one original
flow cookie, one valid existing device cookie, exact initiating HTTPS Origin
and one `Idempotency-Key` header. The trusted host mapping, actor, policy,
target, IP, purpose and channel cannot be overridden by JSON. Use the same
device policy as selected initiation. Missing/invalid custody denies; Send
never creates replacement flow/device cookies. Email owns normalization; the
native Send owner retains primary authentication, counted risk, durable
issuance/suppression and replay, not consumer callbacks.

Share the retained transport rate owner across requests. A 202 response with
`accepted:true` means native acceptance committed, not that an account exists,
a challenge was created or a message was delivered. Ambiguous outcomes remain
503 with safe original command status, never automatic replacement/retry.
Explicit native replay resolution retains the original key and exact input.
No destination, code, device, cookie or session authority appears in responses.
Typed middleware observes detached `SendState.Attempt` metadata and cannot
forge cookie/CSRF output, including trailers.

`NewEmailSigninSendFeature` selects only this handler and concrete wire schema.
`NewEmailSigninFeature(send, signin, recovery)` selects all three operations
under one OTP owner without duplicate flow components. Missing dependencies
fail without partial selection or owner IO. Existing signin/recovery factories
remain unchanged. This is not full multi-purpose Send or a browser-login proof;
SMS, session/MFA purpose profiles and complete runtime/release gates remain.

## Consuming signin

Explicitly opt-in integration: importing base `identity/http` does not require
OTP. `NewSigninHandler(SigninConfig)` constructs only `POST /v1/otp/signin`.
The configuration borrows the selected native OTP signin/source owner and the
retained strict shared auth-rate limiter. No storage or workflow callbacks are
required. Composition supplies exact tenant hosts, origin, secure host-cookie
policies, service actor/policy revision, issuer audience and bounded clock/deadline.

## Request and response

Send strict JSON with exactly `flowID`, `sendCommandID`, and `code`, the original
`__Host-identity_flow` cookie, and exact initiating `Origin`. The flow and Send
locators come from the existing native initiation/Send operations. Do not submit
destination, remember policy, tenant, user, Authorization or Idempotency-Key.
The shared signin IP budget applies before native source lookup, including
rejected possession and outages. The original native source then determines
the canonical identifier rate budget without charging IP again;
the consuming service independently revalidates authority and finalizes atomically.

Fresh committed success returns credential-free `SigninResponse` JSON, one
Secure/HttpOnly host-only session cookie and `X-CSRF-Token`. Store the synchronizer
for protected cookie mutations; never log it. Errors and ambiguity deliver no
credentials. Preserve original recovery correlation and use native code-free
`RecoverSignin` or the explicit recovery handler; do not retry signin as recovery.
Recovery correlation is not permission, proof or current session authority. A prepared attempt can retain
recovery before issuance has observed an outcome; this is reported as `none`,
not rollback or permission to resubmit.

## Status and tradeoffs

`NewSigninHandlerWithMiddleware` exposes the shared typed operation pipeline.
Hooks run before authentication, after authentication, before handling and after
handling. Authentication here means original-flow possession, not user login.
After authentication, `PipelineValue[SigninState]` exposes only detached,
credential-free attempt metadata through `Attempt`; private request input cannot
be replaced. An attempted result is not proof that credentials reached the browser.
Do not retain pipeline state beyond the request. Implicit serialization is denied.

Router middleware rebinding retains the same credential-delivery owner. Hooks may
deny or observe a request, but cannot supply session cookies or synchronizers,
replace original input, or run the native consuming owner twice by repeating
`next`. Cancellation before handling prevents consumption; cancellation after
execution preserves the known outcome without delivering fresh credentials.
This fixed JSON response profile permits no trailers, including credential fields
added during hook unwind.

`NewSigninFeature` and `NewSigninFeatureWithMiddleware` explicitly contribute
only the real signin route and its concrete OpenAPI 3.1.1 wire schema. Pass the
returned feature to the base HTTP selected-handler/router constructors. Omit it
to expose neither the route nor its metadata. Construction performs no native
owner IO. The schema describes closed original-flow JSON and credential-free
results; fresh credentials are delivered only through selected response headers.
Shared router HTTPS/origin denials retain their actual JSON/plaintext media.

## Original outcome recovery

`NewSigninRecoveryHandler(SigninRecoveryConfig)` constructs only
`POST /v1/otp/signin/recover`; it does not advertise a feature or route metadata.
Send exactly `flowID` and the original `recovery` object, with the same flow
cookie and initiating Origin. No code, replacement subject, new attempt or
remember policy is accepted. The recovery object is correlation, not permission:
the native owner validates original custody and current disclosure policy even
after consumption/expiry. It does not require an executable source lookup.
Configure request limits for at least 44 total JSON fields/elements and depth 3;
the existing 32-byte scope digest remains a numeric array, never a string.

Recovery shares the strict signin IP budget before a single native historical
read. It never compares codes, charges an OTP attempt, issues a session or
reveals credentials. A resolved history returns 200 with `signedIn:false`;
`sessionID` on committed history is not a live-login assertion. Unknown outcomes
and unavailable history return 503, retaining authenticated correlation when
the native owner supplies it. Rate denial returns 429 and bounded Retry-After.
Typed middleware uses `PipelineValue[SigninRecoveryState]` and detached `Attempt`
metadata; response custody prevents cookie/CSRF injection, including trailers.

`NewSigninRecoveryFeature` selects only this real handler and concrete recovery
schemas. `NewSigninFeatureWithRecovery` selects signin plus recovery under one
OTP owner, declaring their shared flow-cookie security scheme once. Middleware
variants retain each operation's distinct typed state. Do not supply separate
signin and recovery contributions with the same owner to one router. Constructors
perform no native IO and return no partial feature for missing dependencies.
Omitting recovery exposes neither its route nor metadata. The wire advertises
historical outcomes without cookie/CSRF response headers; runtime scope checks
remain mandatory even when JSON shape validates.

This remains a development checkpoint, not a complete server. Remaining Send
purpose/channel profiles,
composed native browser login, exact coverage/mutation,
clean-consumer and release qualification remain pending. The single-factor
profile must deny when further factors are required; complete MFA continuation
composition remains required. No production memory fallback exists.

Domain owners must honor contexts and be concurrency-safe. The handler owns no
goroutines or resources and never closes borrowed dependencies. The enclosing
server must also bound raw request and response IO. Caller policy is composition
context, not user authentication; the native owner authenticates actual original
cookie possession. Responses are no-store/nosniff; no private errors escape.

## FAQ

- **Can clients change remember policy at completion?** No: initiation owns it.
- **Can a different email avoid the rate budget?** No replacement is accepted.
- **Does source resolution prove login?** No, it is code-free admission only.
- **Does a transport timeout prove rollback?** No; retain returned commitment
  and original recovery correlation when available.

Public API documentation describes configuration and statuses. See
`CHANGELOG.md` for release notes; this module is experimental and unpublished.
