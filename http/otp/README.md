# OTP HTTP transport

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
`RecoverSignin`; do not retry signin as recovery. Recovery correlation is not
permission, proof or current session authority. A prepared attempt can retain
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

This development checkpoint provides a standalone typed handler, not a complete
feature/server. Send HTTP transport, HTTP recovery, feature registration and
concrete OpenAPI remain pending, as do composed native browser
login, exact coverage/mutation, clean-consumer and release qualification. It
advertises no feature metadata. No production memory fallback exists.

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
