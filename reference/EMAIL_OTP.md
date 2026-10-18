# Delivered email OTP signin

This is an optional backend login profile, not a UI. It composes the public OTP,
identity, encrypted delivery, risk, MFA authority and session owners. Consumers
supply configuration, retained keys, templates, authorization and a bounded
external sender, not missing challenge stores or authentication workflows.

## Select the public owners

Configure `StoreConfiguration.OTP` with a signin-purpose `otp.AttemptPolicy`,
retained codec/request/risk keys, the actual pre-auth/session namespaces,
bounded execution and a declared delivery template/provider. `OTP.Signin`
selects the native consuming service; nil preserves Send-only behavior.
`OTP.PreAuth` selects original flow issuance. Neither selection exposes HTTP.

Independently select `HTTPPreAuth`, its original browser-device configuration,
the shared strict `HTTPRate` owner, and `HTTPEmailSignin`. Address canonicalization,
actor, policy revision and target are trusted deployment configuration. Native
and HTTP authorization services/revisions must agree. Select `Session` and
`HTTPSession` for current session reads and synchronizer-protected logout; their
keys, cookie, namespace and audience must match the OTP issuer.

| Selection | Public surface |
| --- | --- |
| Original browser | `POST /v1/session/preauth-issue` with omitted method |
| Issuance | `POST /v1/otp/send` |
| Consuming signin | `POST /v1/otp/signin` |
| Original code-free recovery | `POST /v1/otp/signin/recover` |
| Guarded native services | `FeatureSet.OTP()`, `OTPSignin()`, `OTPSigninSource()` |

Disabled selections expose no corresponding route or advertised capability.
Source discovery is native-only, for trusted rate admission; never expose its
recipient projection to a client or treat it as an authentication proof.

## Apply history and establish actual authority

Use public migration Check/Plan/Apply before initialization and readiness. HTTP
email signin always selects the native known-empty MFA profile and its existing
MFA-authority migration prefix in addition to the OTP consuming/session histories.
Apply the selected `identity/mfa/postgres` owner as well as the other requested
owners. Shared installed MFA histories retain their original versions/checksums.

An eligible verified account must have real owner-provisioned factor state.
Missing, enrolled, corrupt or changed authority denies this OTP-only profile.
Installing a table does not initialize existing accounts; never infer or backfill
known-empty state from an absent row. The genuine journey below creates account
and factor state through public registration and email verification.

Raw native callers can explicitly select
`otp/postgres.SigninConfig.RequireKnownEmptyFactors`. Its false value retains
the existing policy-only API contract, whose policy must enforce actual factor
requirements. Reference HTTP email login enables native fencing regardless of
that compatibility setting. An enrolled factor requires a separately implemented
and selected MFA continuation, not fallback to an OTP-only session.

## Consumer journey

1. Compose stores/providers/workers/features/server through the public reference
   API, apply selected history, initialize and check readiness.
2. Issue the original browser flow. Resolve optional `remember` once here and
   retain its flow ID, host-only flow cookie and signed browser-device cookie.
3. Submit the original flow and canonicalizable email to `/v1/otp/send` with
   one stable `Idempotency-Key`. Matching retries preserve original issuance;
   the neutral accepted response is neither delivery nor evidence of membership.
4. Schedule `WorkerSet.ProcessDeliveryOne`. Only committed encrypted delivery
   reaches the bounded external sender. The code has the configured purpose,
   destination, subject, tenant, expiry, replacement and attempt bindings; only
   its keyed digest is challenge lookup state. Do not log codes or credentials.
5. Explicitly POST original flow ID, Send command and delivered code to signin,
   with original cookies and exact origin. No replacement email, remember choice
   or caller-generated attempt ID is accepted. GET/scanner requests do not
   authenticate. Wrong codes use the native shared attempt budget.
6. Only fresh known commitment delivers the session cookie and CSRF synchronizer.
   Browser/persistent policy remains the original choice. Read the resulting
   session and sign out through the selected session owner.

After an unknown result, retain the returned original recovery correlation and
call the recovery endpoint with original flow possession, **without the code**.
Do not resubmit signin to retry an unresolved attempt. Recovery observes original
metadata under current disclosure policy; it never compares, charges, renews
authority, creates a session or redelivers credentials. A historical session ID
does not prove current authentication. Retain the original keys/configuration
for supported command history across restarts.

## Reproduce with isolated PostgreSQL

Use [the disposable baseline setup](BASELINE.md), its explicit loopback port and
task-owned build/module/temporary caches. From this module:

```sh
GOWORK=off go test -race -tags=integration \
  -run '^TestReferencePostgresEmailOTPSigninHTTPS$' -count=1 -v .
```

These cases use actual registration, verification, original browser, risk,
encrypted delivery, OTP consumption, session reads and logout. They cover browser
and persistent sessions, original Send retry, wrong code, foreign browser/origin,
scanner/replay denial, actual lost-COMMIT acknowledgement and code-free recovery.
Genuine confirmed TOTP enrollment, missing factor state and a factor generation
change during native policy admission must deny without charging the challenge
or creating a weaker session. External HIBP IO and delivery are controlled at
their declared seams; no provider delivery, OTP-MFA continuation, phone workflow
or full package/platform qualification is claimed by this signin profile.
