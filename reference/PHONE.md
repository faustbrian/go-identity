# Existing-account phone enrollment and password signin

This optional backend profile attaches and verifies a phone on an existing,
verified account. Password signin is separately selected below; phone signup,
OTP signin, reset, replacement, removal and MFA remain unselected.
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

## Reproduce the selected HTTPS journey

Use [the disposable baseline setup](BASELINE.md), its explicit loopback port and
task-owned build/module/temporary caches. From this module:

```sh
GOWORK=off go test -race -tags=integration \
  -run '^TestReferencePostgresPhoneEnrollmentHTTPS$' -count=1 -v .

GOWORK=off go test -race -tags=integration \
  -run '^TestReferencePostgresPhonePasswordSigninHTTPS$' -count=1 -v .
```

The test uses real public registration, proof, session, OTP, PostgreSQL and
encrypted delivery owners; only external HIBP IO and the SMS/email senders are
controlled at their declared seams. It is selected-profile consumer evidence,
not real-provider delivery, deployment or complete phone/package qualification.
