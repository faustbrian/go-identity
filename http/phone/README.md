# Explicit authenticated phone HTTP profiles

Go 1.27. This optional module independently selects existing-account
**cookie-only** enrollment, verified-phone replacement or self-removal, with
their original recovery. An additional explicit profile selects no-session
phone/password recovery below. It supplies no UI. Signup, signin and enrolled-
MFA continuation are not enabled. Each profile is separately opt-in below.
Full phone-platform qualification remains unfinished.

## Explicit phone/password recovery

`NewPasswordResetFeature(PasswordResetConfig{...})` selects only these POSTs:

| Path | Closed JSON body | Retry header |
| --- | --- | --- |
| `/v1/phone/password-reset-request` | `commandID`, `riskIssuanceCommandID`, `flowID`, `number` | Exactly one `Idempotency-Key` |
| `/v1/phone/password-reset-complete` | `commandID`, `riskIssuanceCommandID`, `flowID`, `token`, `phoneCode`, `totpCode`, `newPassword` | Forbidden |

Both require exact HTTPS tenant host/Origin, the original `__Host-identity_flow`
cookie and the deployment-signed `__Host-identity_device` cookie. Authorization,
`X-CSRF-Token`, remember, actor/user/tenant overrides, queries, trailers and extra
or duplicate JSON members deny. Initiate a separately selected target-bound
`PreAuthPhonePasswordRecovery` browser first; it carries no remember policy.
Retain every original command, risk-issuance ID, cookie and input across retries.
Each risk-issuance command is distinct from its consuming command. Use distinct
initiation and completion risk artifacts; never submit raw carrier facts/verdicts.

Supply the actual native `PasswordResetService`, owned phone-risk evaluator and
authenticated completion rate-source reader. Request admission counts IP and
canonical destination without looking up an account. Completion counts IP before
capability/source work, then the authenticated subject/original SMS challenge
with its immutable issued interval. The native workflow repeats current
authority/freshness and atomically consumes canonical capability, SMS, independent
confirmed TOTP and risk evidence with HIBP-screened password replacement and
all-session revocation. No SMS-only fallback, session issuance or cookie mutation
exists. Only the native owner distinguishes new consumption from original
terminal replay; HTTP never renews evidence to make a retry pass.

For any valid, rate-admitted request, **202 `accepted:true` means only public
acknowledgment**, not account eligibility, durable queueing or SMS delivery.
The same response covers native/risk/provider failure and exposes only the
client's original attempt ID. This prevents eligibility enumeration; use native
operational state and actual sender observations to establish delivery. The
transport does not retry or fabricate a committed receipt.

Successful completion returns credential-free original command/outcome,
credential version and required session-revocation result. An error never claims
completion or session effects; an unknown result remains unknown. Keep original
scope for the native code-free recovery APIs; this feature adds no public history
route. All responses are no-store/nosniff. Borrowed password/capability custody is
terminated after each bounded request, including failure. Drain requests before
closing borrowed shared rate, database or key owners.

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

## Independent verified-phone replacement

`NewChangeFeature(ChangeConfig{...})` selects authenticated new-number sending,
`POST /v1/phone/update` and code-free `POST /v1/phone/update/recover`.
Enrollment and replacement use the same canonical sending path, so select one
profile per server; duplicate selection fails, never silently dispatches or
falls back. Native enrollment remains independently usable.

Sending requires `flowID`, `number`, `previousNumber`, `identifierID`, canonical
decimal `expectedIdentifierVersion`/`expectedVerificationVersion`, and `proofID`.
Completion requires `flowID`, `sendCommandID`, `code`, a distinct update `proofID`
and the original registered `reason`. Both require one header `Idempotency-Key`.
Recovery takes only `flowID` and unchanged original `recovery`, without a key,
code or fresh proof. All require original cookie/Origin/stored synchronizer;
send additionally requires the existing signed browser-device cookie.

Use the real native `PhoneChangeService` for both workflow and read-only
`ChangeSource`, genuine proof storage and shared delivery/keyed-secret/recovery
limiters. Original destination/lifetime reads do not authorize execution or
disclosure; the native owner repeats current authority and commits OTP/proof
consumption, replacement, retirement, old-number notice and pending cascade.
History never sets `updated` or issues a session. An unchanged successful or
wrong-code key recovers its original receipt; it is not another OTP attempt.
Unknown outcomes require original recovery, not a fresh logical submission.
