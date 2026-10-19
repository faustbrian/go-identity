# Explicit authenticated phone HTTP profiles

Go 1.27. This optional module selects existing-account **cookie-only** enrollment,
SMS verification and original, code-free recovery. It supplies no UI. Signup,
signin, reset, replacement and enrolled-MFA continuation are not enabled.
Self-removal is separately opt-in as described below.
Full phone-platform qualification remains unfinished.

Construct `NewVerificationFeature(VerificationConfig{...})` and pass its feature
to the base HTTP router. Without that explicit selection there are no phone
routes or advertised capabilities. Construction performs no native IO. The
reference backend owns concrete persistence/migration/provider wiring; applications
must not implement substitute domain authorities to make this profile work.

## Selected requests

All three POST operations require the exact configured HTTPS tenant host,
`Origin`, original session cookie and current stored `X-CSRF-Token`. Unknown
fields, duplicate keys, query/trailers and Authorization headers deny. Identity,
tenant, policy, session effects and challenge lifetime are not JSON inputs.

| Path | Closed JSON body | Additional requirement |
| --- | --- | --- |
| `/v1/phone/send-verification` | `flowID`, `number`, `proofID` | One `Idempotency-Key`, existing signed browser-device cookie and genuine fresh action-bound password proof |
| `/v1/phone/verify` | `flowID`, `sendCommandID`, `code` | No idempotency header; each submission is a native counted attempt |
| `/v1/phone/verify/recover` | `flowID`, `recovery` | No code or idempotency header; unchanged original recovery correlation only |

`VerificationSource` authenticates original session possession, exact keyed
destination and original issued challenge duration before shared rate admission.
It supplies neither new session authority nor a replacement CSRF token. The
concrete native service independently fences current policy and all transactional
effects. Delivery uses canonical IP/identifier/subject limits; verification uses
IP admission followed by original challenge/subject limits. Recovery debits only
the verification IP budget, never another OTP comparison or challenge attempt.
An unavailable authority or shared backend denies; there is no local fallback.

## Responses and ownership

Send returns 202 only for committed queued intent, not carrier delivery or phone
ownership. A fresh known verification can return the value-free verified
identifier ID/version. History returns durability and code-free original
correlation only, including after identifier epochs change. Unknown is not
rollback: retain its original recovery and do not repeat a consuming attempt.
No response sets cookies, reveals session/CSRF credentials, returns the phone
number/code or signs the user in. JSON is no-store/nosniff.

Configuration freezes policy/key slices; services and clocks remain borrowed and
must be concurrency-safe, context-bounded and valid for the handler lifetime.
Close shared limiters only after draining handlers; this module closes no native
pool, key owner or provider. `WithOperationMiddleware` preserves the actual typed
phases rather than wrapping them with a second authentication/rate execution.

OpenAPI describes the selected closed wire profile, separately from direct Go
contract summaries. Optional number-display/national parsing policy remains owned
by the actual pinned native number policy; transport does not redefine E.164.

## Independent self-removal

`NewRemovalFeature(RemovalConfig{...})` selects only `POST /v1/phone/remove`.
Supply the actual signed-proof repository, native `RemovalService`, immutable
number policy, cookie/Origin configuration and shared keyed-secret limiter.
The native owner authenticates current proof/session/factor/recovery authority
and commits removal and required effects; this transport cannot replace it.

The request requires the session cookie, exact Origin, `X-CSRF-Token` and exactly
one `Idempotency-Key`. Closed JSON contains `number`, `identifierID`,
`expectedIdentifierVersion`, `expectedVerificationVersion`, `proofID`, `reason`.
Versions are canonical positive decimal strings below uint64 maximum, not JSON
numbers. Tenant/user, OTP, command/body-key and suppression overrides reject.

Success contains only original command and pending cascade correlation, never
a phone, proof, code, session or CSRF credential. Matching original-key retries
remain usable after removal invalidates the old session. Unknown is not rollback;
retain original custody and use native code-free reconciliation, not a new
logical mutation. Pending cleanup and SMS delivery do not restore old-phone
authority. See the concrete reference module's phone guide for composition,
required migrations, independent recovery policy and a runnable consumer.
