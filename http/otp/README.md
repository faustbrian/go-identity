# OTP HTTP transport

## Primary-email replacement

`NewEmailChangeFeature(EmailChangeConfig)` independently selects the following
cookie-only routes. Supply the actual `otp.EmailChangeService` and
`EmailChangeRateSource`, a retained keyed-secret request limiter and verification
limiter, secure session/device cookies, exact HTTPS Origin and stored-session
synchronizer keys. The feature borrows these owners; it creates no workflow store.

| POST path | Exact JSON fields | Idempotency-Key |
| --- | --- | --- |
| `/v1/otp/email-change-request` | `flowID`, `originCommandID`, `addressID` | Required |
| `/v1/otp/email-change-confirm` | `flowID`, `sendCommandID`, `code` | Forbidden |
| `/v1/otp/email-change-confirm/recover` | `flowID`, `recovery` | Forbidden |

First perform the existing fresh-password keyed email-change request. Use its
committed command/candidate as the origin, then independently request/deliver
the OTP. A generic pending-address addition is not replacement authority.
Every route requires the original session cookie, exact Origin and
`X-CSRF-Token`; request also requires the existing signed device cookie.
Request returns safe 202 acceptance, not delivery or replacement. Only fresh
committed confirmation returns `changed:true` with the exact address ID/version.
Recovery returns original durability metadata without address/session credentials,
code comparison, another attempt debit, notification or renewed validity.

Success replaces one genuine primary, queues a notice to its original old
mailbox and invalidates old identifier-bound sessions. No route emits cookies
or synchronizers. Unknown outcomes retain code-free recovery: do not resubmit
the consuming confirmation to find out whether it committed. With the native
`AllowInitialPrimary` opt-in and original `PrimaryOrSoleVerifiedAddress` policy,
the same routes can establish the first primary from a sole verified old mailbox.
That old mailbox retains its identifier/verification history; notice and session
effects are unchanged. HTTP selection alone cannot enable that native profile.
Stronger-factor, current-address OTP and auto-signin are not selected. Ordinary
pending-email verification and link confirmation retain their distinct profiles.

## Pending-email verification

`NewEmailVerificationFeature(EmailVerificationConfig)` independently selects
three cookie-only operations. It requires the actual native email-verification
service/source, strict delivery/challenge rate owners, secure session cookie,
exact HTTPS Origin, retained synchronizer keys and trusted bounded clock/policy.
The feature borrows owners and creates no storage, background work or session.

| POST path | Exact JSON fields | Idempotency-Key |
| --- | --- | --- |
| `/v1/otp/send` | `flowID`, `addressID`, `addressVersion` | Required |
| `/v1/otp/email-verify` | `flowID`, `sendCommandID`, `code` | Forbidden |
| `/v1/otp/email-verify/recover` | `flowID`, `recovery` | Forbidden |

Every request needs the original session cookie, `Origin` and `X-CSRF-Token`.
Send also needs the existing signed `__Host-identity_device` cookie under the
configured browser-device policy; it never mints a replacement. Caller-selected
user/tenant/actor/purpose, Authorization, query/trailer alternatives, extra/null
or duplicate JSON fields deny. Recovery carries the original code-free metadata
returned by completion, never a submitted code.

Send returns 202 acceptance, not verification or delivery. Only fresh committed
completion returns `verified:true` and the exact address ID/version. Recovery
returns original durability metadata without an address; denied originals remain
`not_committed` and uncertainty remains `unknown`. No route emits cookies, tokens
or synchronizers. Original session possession supports history after its own
identifier-authority transition, but does not grant new mutation authority.
This selected verification profile does not support pre-auth, primary replacement,
stronger MFA, auto-signin or multiple Send purposes on the same route. Reference
composition rejects conflicting OTP-signin Send selection explicitly.

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
