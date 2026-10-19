# Existing-account phone enrollment and signin

This optional backend profile attaches and verifies a phone on an existing,
verified account. Password and SMS-code signin are separately selected below;
phone signup, reset, replacement and MFA remain unselected. Authenticated
self-removal is a separate explicit selection described below.
Unknown/enrolled/changed factor authority denies the
single-factor enrollment profile; it never falls back to weaker authentication.

## Explicit selection

Set `StoreConfiguration.Phone` with the number policy, native domain/request
custody keys, `Primary` action `identity.phone.send-verification` and matching
password-reauthentication target/audience. Select the actual password signin,
password verification, sessions, OTP and delivery owners. Leave `Native.Issuer`
and `Native.Risk.Evaluation` zero: the graph injects the native owners rather
than accepting substitutes. Use distinct request-key namespaces under the same
authoritative policy. Retained session keys must match the real session issuer.

The `Issuance` policy must have purpose `phone-verification`, bounded attempts,
lifetime, sends and replacement policy. Select an SMS template, its provider
version and locale chain, and configure a delivery worker for that provider for
every selected tenant. Composition rejects a missing selected worker. Consumers
supply the bounded external SMS sender, not OTP storage or verification logic.

Use the selected graph's `StoreSet.ReferenceMigrationCheck`,
`ReferenceMigrationPlan` and `ReferenceMigrationApply` before initializing or
serving. The generic `MigrationSource` does not include independent histories.
The selected catalog reuses native identifier normalization, action proof,
factor authority and consuming OTP histories, then installs forward phone-purpose
suffixes and the selected HTTP atomic-rate history. Installed histories
keep their namespaces, versions and checksums; do not manually replay older
purpose constraints or invent/backfill missing factor authority.

`FeatureSet.Phone()` returns the guarded native service. Separately select
`HTTPPhoneVerification` for exactly:

- `POST /v1/phone/send-verification`
- `POST /v1/phone/verify`
- `POST /v1/phone/verify/recover`

The transport requires the existing HTTPS origin, cookie session and CSRF policy,
signed browser-device profile, actual password proof repository and shared strong
rate backend. Native selection alone exposes no route or advertised capability.

## Consumer journey

1. Register, capture the verification email, confirm it and sign in through the
   selected existing owners. Retain the real session cookie and CSRF token.
2. Initialize the existing signed device profile if needed; it is not a session.
   Obtain a fresh password proof for `identity.phone.send-verification` and the
   configured audience through `/v1/password/verify`.
3. Send `{flowID, number, proofID}` to the phone-send endpoint with the original
   session ID, signed device/session cookies, exact Origin, CSRF and a stable
   `Idempotency-Key`. Matching retries preserve the original pending phone,
   challenge and delivery; changing input under that key conflicts. Accepted
   means queued, not delivered or verified.
4. Run the selected SMS delivery worker. Submit `{flowID, sendCommandID, code}`
   to verification with original session custody and CSRF. Every submission is a
   new native counted attempt; wrong codes deny without verifying the phone.
5. Fresh known commitment atomically consumes the code and verifies the pending
   identifier. Required session-authority effects invalidate the old session;
   no session or CSRF replacement is issued. Sign in again before further work.
6. Retain returned recovery correlation for ambiguity. Submit `{flowID, recovery}`
   with original possession and CSRF to recovery, **without the code**. Recovery
   observes the original outcome under current disclosure policy; it never
   compares, charges, renews validity, verifies another phone or returns secrets.
   Do not retry an unresolved verification as a new logical attempt.

Retain original keys/configuration across supported command history. Never log
phone numbers, proofs, delivered codes, cookies or explicit recovery correlation.

## Independently selected phone/password signin

Set `StoreConfiguration.PhoneSignin = &PhoneSigninConfiguration{Policy: policy}`
to compose verified-phone login with the existing `PasswordSignin` native keys,
policy, verifier, original-flow issuer and session configuration. This selection
does not require `Phone` enrollment or `HTTPPhoneVerification`; an already
verified phone must still carry the matching stored canonical profile. No phone,
account or missing factor authority is invented during login. Configured email
and username owners remain separate.

`FeatureSet.PhoneSignin()` exposes native signin/recovery;
`PhoneSigninPreAuth()` exposes its guarded issuer and lookup-free canonical
target binder. Direct callers derive the nonzero binding with
`BindPreAuthIdentifier` before Prepare. Never accept a client-selected binding.
The native workflow independently rechecks the exact original target before
identifier risk, account discovery and raw password comparison, and fences
current phone/credential/account/factor authority within atomic issuance.

Separately select `HTTPPhoneSignin` with the trusted service actor/revision,
shared HTTP pre-auth/device and rate configuration. Then:

1. Send `{"method":"phone-password","identifier":"+12025550123","remember":false}`
   to `POST /v1/session/preauth-issue` with the exact configured Origin. Keep the
   original flow/device cookies and returned flow ID. The trusted graph derives
   the target binding after IP admission; no account is looked up here.
2. Send `{flowID, phoneNumber, password, callbackURL, remember}` to
   `POST /v1/phone/password-signin`. Callback and remember must match that
   original flow. Retargeting or cookie/action substitution denies; it cannot
   redirect attribution or reach credential work under another number.
3. Only fresh known commitment delivers one session cookie and `X-CSRF-Token`.
   Use the existing selected session read/signout routes. Browser and persistent
   remember choices retain their native cookie and session lifetimes.

Retain password-free recovery metadata and original custody after ambiguity;
native `RecoverSignin` observes that original attempt without password retry,
token redelivery or deadline renewal. Enrolled or unavailable factors deny;
phone-origin MFA continuation is not selected. Disabled HTTP selection exposes
neither the route nor initiation method/schema. Install the selected native
phone/password and session provenance suffixes after all selected predecessor
histories using the graph migration APIs; do not copy or replay older SQL.
This checkpoint qualifies adding phone signin after those selected histories;
enabling additional predecessor profiles afterwards is not yet qualified.

## Independently selected phone SMS-code signin

Set `StoreConfiguration.PhoneOTPSignin` with the immutable `NumberPolicy`, a
consuming-only `CodePolicy` for purpose `signin`, independent `RequestKeys`
namespace, SMS template/version, provider version and locale chain. The graph
reuses `OTP.Signin`, `OTP.PreAuth`, counted risk, encrypted delivery and `Session`
read/logout configuration. Those common owners must match; enrollment, password
login and their HTTP routes are not implicit dependencies. Existing verified
phones must have the exact retained normalization profile, and actual current
factor authority must be known-empty. Unknown/enrolled factors deny without an
MFA or password fallback.

`FeatureSet.PhoneOTPSignin()` exposes native send/signin/code-free recovery and
trusted original-source resolution. `PhoneOTPSigninPreAuth()` supplies its own
lookup-free canonical binder and original issuer. These handles retain startup,
tenant and shutdown guards. Apply the graph's selected migrations before use:
the native session-purpose suffix is last, after every selected username,
phone/password, verification or MFA history. It preserves populated rows and
installed checksums. Selecting this provenance history does not enable password
authentication. Add a worker for the selected SMS provider for every tenant.

Select `HTTPPhoneOTPSignin` separately with the canonical service actor ID and
matching authorization revision. The HTTP actor is independent of the original
flow issuer's actor; do not substitute an informal service label where canonical
risk-audit attribution is required. HTTP additionally requires signed
`HTTPPreAuth.Device`, the original flow cookie and strong `HTTPRate` admission.
Nil selection advertises no routes or initiation method.

1. Start `POST /v1/session/preauth-issue` with
   `{"method":"phone-otp","identifier":"+12025550123","remember":false}`.
   Retain its flow ID and both original flow/device cookies. The trusted binder
   fixes the canonical number without an account lookup.
2. Send `{flowID, number}` to `POST /v1/phone/send-signin` with exact Origin,
   original cookies and a stable `Idempotency-Key`. Matching retries retain the
   original challenge; changing input is a different request, not a safe retry.
   Accepted means queued or suppressed, not delivered or verified eligibility.
3. Run the selected SMS worker, then submit `{flowID, sendCommandID, code}` to
   `POST /v1/phone/signin` with the original flow cookie and exact Origin.
   Password, purpose, user and remember overrides are not accepted. A wrong code
   is one counted native attempt; only fresh known commitment delivers the
   session cookie and `X-CSRF-Token` with the original remember policy.
4. Use the ordinary session get/signout endpoints. For an ambiguous submission,
   retain its returned correlation and call `POST /v1/phone/signin/recover`
   with `{flowID, recovery}` and original custody, **without the code**. Recovery
   never compares, charges, renews or returns credentials. Do not submit the
   same code as a new attempt to resolve an unknown outcome.

Phone enrollment, password signin and SMS-code signin can be composed together
under one `identity/phone` HTTP owner. Email OTP remains a separate selection.
Additional predecessor profiles enabled after the final phone suffix still need
their own populated-history qualification; this profile does not claim it.

## Independently selected phone self-removal

Set `StoreConfiguration.PhoneRemoval` with the immutable number policy,
`Primary.Action = "identity.phone.remove"`, an explicit proof audience and
positive `MaximumAge` (no more than 15 minutes). Register that exact action and
audience in the selected password-verification owner's target allowlist. Select
the actual password signin, reset, proof, session, protected-risk and delivery
owners. The supported profile requires their known-empty MFA authority; missing,
changed or enrolled factors deny instead of falling back. A verified address
alone is insufficient: the retained email/password identity must be usable by
both configured signin and reset owners under the protected transaction.

Configure `Native.RequestKeys` with an independent stable namespace, protected
counters with lockout enforcement, an explicit identifier-removal cascade and
one required SMS notice template/provider/locale/TTL. The notice has no caller
variables and targets the original removed number. Leave
`Native.Risk.Evaluation`, `Native.Risk.Keys`, `Native.Notice.Delivery` and
`Native.Notice.Templates` zero: the graph injects its actual owners. For cookie
transport leave `Primary.CSRFKeys` empty for the same reason. Add a worker for
the notice's selected SMS provider for each tenant.

Apply the graph's selected migration catalog before startup. Forward suffixes
extend the existing phone proof and identifier-removal cascade histories and
install protected lockouts without selecting MFA or username workflows. Preserve
installed namespaces/checksums. Enrollment is not required merely to select
removal, but an existing verified phone must retain the exact canonical profile.

`FeatureSet.PhoneRemoval()` exposes `Remove`, original `RemovalRateSource` and
code-free `RecoverRemoval`. The rate-source method grants no mutation authority.
Native bearer or cookie custody is chosen at construction, not from a request.
Separately set `HTTPPhoneRemoval` with the trusted Origin and matching policy
revision for the cookie-only `POST /v1/phone/remove` route. Native selection alone
exposes neither that route nor its capability. HTTP requires the original
session cookie, exact Origin, `X-CSRF-Token`, one `Idempotency-Key` header and:

```json
{
  "number": "+12025550123",
  "identifierID": "<original verified identifier ID>",
  "expectedIdentifierVersion": "2",
  "expectedVerificationVersion": "2",
  "proofID": "<original password-verification proof ID>",
  "reason": "user-requested"
}
```

Versions are canonical decimal strings in `1..18446744073709551614`, not JSON
numbers. IDs, versions and the original action-bound proof come from supported
identity/proof APIs; the reason must be registered in the native cascade policy.
OTP, tenant/user, command/key and notification-suppression overrides are rejected.

A known commitment atomically removes and retires the exact phone, consumes the
one-use password proof, advances identifier authority and queues the encrypted
old-number notice plus lifecycle cascade. Prior identifier-bound sessions and
old phone-password/preissued OTP authentication then deny. Removal neither uses
an OTP nor issues a replacement session. `cascadeStatus: "pending"` describes
unfinished downstream cleanup, not physical deletion of every session row.
Sender failure cannot restore the removed phone's authority.
The protected security audit uses `identity.identifier.remove`; command and
recovery identity remain `identity.phone.remove`. There is no synonymous second
security event.

Retain the exact original key and request for matching retries, including after
the original session is invalidated by removal. Changed input under that key
conflicts. For code-free native reconciliation, retain the returned command ID
and exact `RecoveryQuery` binding and use the original `identity.phone.remove`
self-resource caller under current historical disclosure policy. Recovery never
reexecutes removal or renews proof/session validity. An unknown response is not
rollback and must not be resubmitted as a new logical request. A retained verified
email/password signin and reset path remains usable after successful removal.

## Reproduce the selected HTTPS journey

Use [the disposable baseline setup](BASELINE.md), its explicit loopback port and
task-owned build/module/temporary caches. From this module:

```sh
GOWORK=off go test -race -tags=integration \
  -run '^TestReferencePostgresPhoneEnrollmentHTTPS$' -count=1 -v .

GOWORK=off go test -race -tags=integration \
  -run '^TestReferencePostgresPhonePasswordSigninHTTPS$' -count=1 -v .

GOWORK=off go test -race -tags=integration \
  -run '^TestReferencePostgresPhoneOTP(Signin|PasswordUsernameCoexistence)HTTPS$' \
  -count=1 -v .

GOWORK=off go test -race -tags=integration \
  -run '^TestReferencePostgresPhoneRemoval(HTTPS|CommitCustody)$' -count=1 -v .
```

The test uses real public registration, proof, session, OTP, PostgreSQL and
encrypted delivery owners; only external HIBP IO and the SMS/email senders are
controlled at their declared seams. It is selected-profile consumer evidence,
not real-provider delivery, deployment or complete phone/package qualification.
