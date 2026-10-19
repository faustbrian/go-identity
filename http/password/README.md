# Password HTTP integration

**Experimental development checkpoint, not a complete password HTTP product.**
Go 1.27. Base `identity/http` does not import this optional module.

## Adoption and API

### Verified-phone password signin

Select `NewPhoneSigninFeature(signinConfig)` or `NewPhoneSigninHandler` with
the native phone-enabled password owner. The route is exactly
`POST /v1/phone/password-signin`, with `flowID`, `phoneNumber`, `password`,
`callbackURL` and optional boolean `remember`. First obtain the original
phone-target-bound flow through the shared initiation route's explicitly
selected `phone-password` method. Its trusted binder derives the canonical
target; a caller-chosen digest is never accepted.

Exact HTTPS tenant/Origin, original flow and signed device cookies, callback
and remember policy remain mandatory. Native current phone/profile, account,
credential and known-empty-factor authority are decisive. `MFAContinuation`
must be false; no OTP, enrollment or phone-MFA route follows from selection.
Only fresh known commitment delivers the original session cookie and CSRF.
If also selecting phone enrollment, combine operation descriptors under one
`identity/phone` feature instead of registering that owner twice. The reference
composition supplies this wiring without another domain workflow or store.

### Browser password-reset request

Select `FeatureConfig.ResetRequest` with `ResetRequestConfig`. Supply the native
`password/postgres.ResetService` with request issuance/delivery enabled, the
existing shared `AuthRateLimiter`, mapped HTTPS tenant and exact Origin,
fixed allowed callback, signed browser-device codec, public-entry actor/policy
and bounded clock/deadline. No session or pre-auth flow is required.

`POST /v1/password/reset-request` takes closed JSON `commandID`, `identifier`,
`callbackURL`, exactly one `Idempotency-Key` header and the existing
`__Host-identity_device` cookie. Preserve commandID and key across explicit
retries; changing the original intent conflicts. Unknown fields, duplicate JSON,
query/trailers, alternative keys and Authorization deny. Trusted-IP admission
precedes native normalization, then shared destination admission and one native
request. Neither transport nor normalization discovers account existence.

Eligible and suppressed recipients receive the same acknowledgement. Responses
contain only original command/outcome and attempt/tenant/actor recovery metadata,
never a mailbox, token, key or session. For native proof-free recovery, use the
returned commandID and attemptID as `RecoveryQuery.CommandID` and
`AnonymousFlowID`; trusted current query policy remains required. No automatic
retry, recovery or redirect occurs. A real PostgreSQL-through-HTTP journey
exercises request, captured delivery, completion and session revocation.
Reference-server composition remains unfinished; this is not a delivered reset
slice or verified-unit claim.

### Explicit password-reset completion

Select `FeatureConfig.ResetComplete` with `ResetCompleteConfig`, alone or
alongside request. Supply the native reset service, existing shared
`ChallengeVerificationRateLimiter`, mapped HTTPS tenant/Origin, signed device
codec, trusted public-entry actor/policy and bounded clock/deadline.

`POST /v1/password/reset-complete` requires closed JSON `commandID`, `token`,
`newPassword` and the signed device cookie. The command is the original
completion attempt, distinct from request initiation. Idempotency-Key,
Authorization, query/trailers, identity overrides and GET consumption deny.
Trusted-IP admission precedes real purpose-bound durable issuance lookup;
subject/original-challenge admission follows. The native owner repeats current
account/factor authority, HIBP/password policy, atomic use and all-session
revocation. Reset never automatically signs in or emits a session.

Error-free known commitment returns replacement version and session-revocation
metadata. Errors/ambiguity withhold success while preserving original command
and proof/password-free recovery scope. Use response commandID, recovery
tenantID/userID/credentialID/actor metadata to build the native recovery query;
credentialID maps to `RecordID`, and operation is
`identity.password.reset-complete`. Current trusted query policy remains
required; never automatically resubmit a password after uncertainty. Owned
password and proof are cleaned up on all exits; transient JSON/string copies
are not erasure proof. The real PostgreSQL-through-HTTP journey also exercises
original-input replay and changed-password conflict without corrupting the
original result. Reference-server composition remains pending.

### Browser required-email-verification signup

Select `NewSignupFeature(SignupConfig{...})` or `FeatureConfig.Signup`. Supply
the real `password/postgres.SignupService`, shared `AuthRateLimiter`, exact
mapped tenant/HTTPS origin/callback, original flow cookie and signed device
configuration, public-entry actor/policy, bounded clock/deadline and the native
creation `FieldSchema`. Lifetime/default remember must match initialization.
Omission registers no route or metadata; base HTTP retains no feature imports.

`POST /v1/password/signup` requires exactly one original `Idempotency-Key`
header and closed JSON `flowID`, `email`, `password`, `callbackURL`; optional
`remember` is boolean. Optional `allowedFields` contains whole-value replacements
`{"name":"name","kind":"string","value":"Ada"}`. Only input-writable names
and exact kinds from the selected schema are admitted: string, bool, int64,
RFC3339 time or bounded string-list. Native authorization, normalization,
defaults and constraints remain authoritative. False, integer zero, empty
strings/lists remain present; floats, nulls, unknown fields and duplicate names
deny. The selected OpenAPI advertises only those input-writable fields and
never returns them.

Both original flow and signed device cookies are required. Alternative key
channels, Authorization, query/trailers and client-selected identity deny.
IP admission precedes native address projection, then the shared identifier
budget and one native keyed signup. No account lookup or live-flow gate exists
in transport, so native keyed replay can retain its history after the original
flow was consumed/deleted. Do not replace a key or automatically resubmit a
password after ambiguity. The owned password is destroyed on every exit;
transient JSON/string copies are not erasure proof.

This explicit profile requires email verification and delivers no session,
account identity, address or credential. New/occupied identifiers share the
same acknowledgement. Known original outcome and password-free recovery
correlation survive errors, ambiguity and replay; correlation grants no
disclosure permission. A changed-intent native key conflict returns `409`
without inventing history. Immediate-session and MFA signup remain owed and
are not silently selected or downgraded. Native SQL-through-HTTP composition,
browser evidence and complete password lifecycle/release gates remain pending.

### Browser password signin

Select `NewSigninFeature(SigninConfig{...})`, or `FeatureConfig.Signin` alongside
other password operations. Supply the real `password/postgres.SigninService`,
shared `identityhttp.AuthRateLimiter`, trusted tenant network, exact HTTPS
origin/callback, public-entry service actor/policy/audience, original pre-auth
cookie, session cookie and browser-device codec configuration. Lifetime/default
remember policy must match pre-auth initialization. The selected endpoint is
`POST /v1/password/signin`; construction performs no IO and disabled selection
exposes neither its route nor OpenAPI metadata.

Closed JSON requires `flowID`, `identifier`, `password`, `callbackURL`, with
optional boolean `remember`. Both original flow and signed browser-device
cookies are required; Authorization, retry keys, query/trailers and identity
overrides are forbidden. IP admission precedes native normalization/custody;
canonical identifier admission precedes one native signin. The transport never
looks up accounts, hashes passwords or stores a workflow. It destroys its owned
password on every exit; transient JSON/string copies are not erasure proof.

Shared signin/signup admission outages fail closed with `503` and stable
`rate_limiter_unavailable`; exhaustion returns `429` with bounded `Retry-After`.

Fresh error-free known commitment delivers the original secure session cookie
and `X-CSRF-Token`, never bearer JSON or redirects. Failure/replay/recovery emit
no credentials. Retain password-free original recovery correlation and call the
native recovery API with original possession; never resubmit secrets after an
ambiguous attempt. This checkpoint supports verified-email single-factor
signin, not MFA continuation or the complete password lifecycle. Real native
SQL-through-HTTP and browser/release qualification remain pending.

### Protected password change

Construct `NewChangeHandler(ChangeConfig{...})`, or
`NewChangeHandlerWithMiddleware` to select trusted synchronous hook phases.
Mount the returned handler for exact `POST /v1/password/change`; construction
does not register routes or advertise metadata. The selected session service,
original proof source and change workflow must share the native authority.
Supply a real `password/postgres.ChangeWorkflow` in bearer mode or
`password/postgres.CookieChangeWorkflow` in cookie mode, the session owner's
primary service, the password repository's original signed-proof source, one
shared `identityhttp.KeyedSecretRateLimiter`, trusted network and policy revision,
clock and 1ms..30s whole-request bound. Every borrowed owner must outlive calls.
Deployment owns migrations/key retention and handler drain, not workflow glue.

For selected routing and OpenAPI 3.1.1, contribute `NewChangeFeature` (or
`NewChangeFeatureWithMiddleware`) to `identityhttp.FeatureServices`, derive
operation descriptors and compose through `identityhttp.NewRouter`. This
contribution selects only password change, with the same native owners and
credential profile. Omission exposes neither its route nor metadata; selecting
it with missing owners fails construction. The document describes the closed
request and credential-free responses, not reflected domain or runtime objects.

JSON contains exactly `proofID` and `newPassword`; the proof ID comes from
completed credential-specific password verification for this action. Exactly
one original `Idempotency-Key` header supplies the protected command's only key.
Do not supply proof projections, tenant/user overrides, replacement retry keys
or request-selected revocation policy. Password bytes are not normalized.
The handler destroys its owned secret on every exit; the server owns body/IO
cleanup. Transport tests do not prove erasure of transient JSON/string copies.

Cookie mode requires one selected secure cookie, exact allowed HTTPS Origin
and canonical X-CSRF-Token; Authorization is forbidden. The native cookie
workflow validates current primary synchronizer state with protected effects.
Bearer mode requires one strict Authorization header, ignores ambient cookies
and rejects CSRF alternatives. No channel fallback is permitted. No response
emits cookies, bearer or CSRF tokens, including middleware short circuits.

`ChangeState` exposes only detached principal/attempt metadata to hooks. Before
auth no typed state is available. Hooks cannot replace original input; they must
not retain or log credential-bearing detached headers. Hook observations do not
certify commit, successful delivery or reusable authority.

## Outcomes and security

### Bearer password verification

Native PostgreSQL verification uses Authentication risk and requires signed
browser-device correlation. Select
`NewBrowserDeviceBearerVerificationFeature(BrowserDeviceBearerVerificationConfig{
Verification: verificationConfig, Device: deviceConfig})`, or the corresponding
handler/middleware factory. The device configuration must match the existing
`http/session.NewPreAuthFeatureWithBrowserDevice` initialization issuer:
dedicated retained keys, namespace, lifetime and `__Host-identity_device`
cookie policy. Initialize once, then submit that original cookie alongside the
sole Authorization bearer. The verifier never mints a replacement. Missing,
duplicate, altered, foreign-scope or expired custody denies. This correlation
is not session authentication, hardware identity or MFA trust.

For change plus this profile, select `NewFeature(FeatureConfig{Change:
&changeConfig, BrowserDeviceBearerVerification: &deviceVerificationConfig})`.
Selecting both verification variants is invalid. The generic APIs below remain
cookie-ignoring and are suitable only for a verification owner whose selected
policy does not require device correlation; they do not satisfy the native
PostgreSQL Authentication risk profile alone.

`NewBearerVerificationHandler(BearerVerificationConfig{...})` (or its typed
middleware variant) owns exact `POST /v1/password/verify`. Supply a verification
owner whose selected policy does not require device correlation, a primary session service,
one shared `PasswordVerificationRateLimiter`, trusted network/policy revision,
prompt clock and 1ms..30s bound. This selects bearer only; cookie verification
requires a separate protected native profile and has no bearer fallback.
For selected routing and OpenAPI, contribute `NewBearerVerificationFeature`
(or its middleware variant) when selecting verification alone. When selecting
both operations, use `NewFeature(FeatureConfig{Change: &changeConfig,
BearerVerification: &verificationConfig})` or `NewFeatureWithMiddleware`.
This creates one password-owned contribution without duplicate feature IDs;
do not select the standalone change and verification features together.
Nil fields omit operations; selecting neither or any invalid owner fails with
no partial contribution. A cookie-change configuration does not select cookie
verification. Existing change-only factories remain change-only. Shared hooks
must handle the distinct `ChangeState` and `VerificationState` typed phases.
The actual wire schema is closed and advertises only strict bearer security,
not a request key, cookie fallback or a reflected signed record. The explicit
device-bound variant has focused native SQL-over-router qualification;
cookie verification, browser interoperability and full release remain pending.

The closed JSON body contains exactly `password`, `purpose`, `action` and
`audience`. The native owner enforces its trusted exact target allowlist;
clients cannot select subject, tenant, assurance, expiry or signing policy.
`Idempotency-Key`, query/trailer overrides and CSRF alternatives are rejected.
Only one strict `Authorization: Bearer` header supplies original credential
custody; ambient cookies are ignored. Every native invocation is a fresh
counted command. Password bytes are unchanged and the owned secret is destroyed
on every exit, including middleware short circuits. Transient JSON/string
buffer erasure is not claimed.

`VerificationState` exposes detached principal/attempt observations to trusted
synchronous hooks, not reusable authority. Native verification retains original
primary/password/policy/risk/signing and atomic commitment ownership. Preliminary
session validity never refreshes through hooks, rate or native work. On a fresh
known commit only, the response includes `verified=true` and a `proof` object
with original `proofID`, `purpose`, `action`, `audience`, `issuedAt`, `expiresAt`.
The original native proof ID is its command ID; protected change looks up the
original signed record, not this client projection. No session identity,
credential, cookie, CSRF or signing record is delivered. Generic mismatch is
403; invalid input400, inactive primary401, path404, method405, host421, rate429,
native policy denial403 and unavailable/ambiguous/canceled work503. Failures
preserve valid original `commandID` and `commitOutcome` but never the proof.
`none` is not rollback. Scoped native recovery returns history, not proof
redelivery or permission to resubmit the password automatically.

### Password change

Responses are credential-free JSON with no-store/nosniff. Error codes are stable
and redacted. Invalid input is400; missing/inactive session401; origin/CSRF or
proof mismatch403; path404; method405; host421; rate429; operational/ambiguous
failure503 (including proof-source outages); native conflict/in-progress409.
A native pre-command conflict has no command or recovery locator; transport
does not manufacture one. `commitOutcome=none` is not rollback. Known command/outcome/recovery
metadata survives errors, while `changed` and successor fields require an
error-free known commit. Recovery is a locator under current result-access
policy, not a permission or instruction to automatically repeat mutation.
Recovery JSON uses `commandID`, `tenantID`, `userID`, `actorID`, `actorKind`,
`operationID` and `recordID`; the Go response retains `*identity.RecoveryQuery`.
Anonymous/account-link fields are not part of this password wire contract.

The preliminary read never refreshes authority through hooks/rate/proof IO.
Native protected work rechecks proof, current primary authority, cumulative risk,
screening, authorization and one-use effects. Rate success grants none of those.
An unknown rate result denies before protected work; cancellation does not prove
that either a debit or mutation rolled back. Deployment keys/namespaces must
remain stable while retained commands exist.

## Tradeoffs, FAQ and remaining qualification

### Protected cookie verification

Select `NewCookieVerificationFeature` with `CookieVerificationConfig` and the
native `password/postgres.CookieVerificationWorkflow`. Supply the original
session cookie policy, exact HTTPS `TrustedOrigins`, original browser-device
issuer policy and the shared native atomic verification rate limiter. The
distinct cookie service cannot be replaced by bearer verification. Compose
verification with change through `FeatureConfig.CookieVerification`; only one
verification profile may be selected per operation.

Requests use the original session cookie, signed `__Host-identity_device` cookie,
exact trusted `Origin` and exactly one `X-CSRF-Token` header, plus closed JSON
`password`, `purpose`, `action` and `audience`. No Authorization, Referer fallback,
body/query/trailer credentials or retry key is accepted. Native protection owns
the current synchronizer and primary transaction fences. HTTP never issues or
renews either cookie, token, validity evidence or proof. Only fresh error-free
known commit returns the original proof locator/target/timing; protected change
loads the signed original. Errors retain permitted original command observations
without proof or automatic retry. Real cookie SQL-over-router and browser
qualification remain pending.

- Why a separate module? Optional password/session imports cannot enter base HTTP.
- Why a proof ID? The original signed native verification is loaded unchanged;
  transport never creates a proof from client-claimed identity or timestamps.
- Can consumers implement stores/transactions? No: select the platform adapters.
- Is this full password feature parity? No. Signup/signin/reset/set,
  native selected-router and browser qualification, privacy/interoperability
  and exact coverage/mutation/release gates remain. Native SQL-over-handler
  password-change behavior has focused integration coverage, not browser proof.
- Does a committed error mean HTTP success? No; reconcile original scoped
  recovery without new keys or resubmitted secrets.

See [release notes](CHANGELOG.md) and Go documentation for the public contract.

### Explicit username selection

`NewUsernameFeature(UsernameFeatureConfig{...})` contributes the separate
`identity/username` owner. Select only needed `Signup`, `Signin`, `Available`
and `Rename` configurations; nil entries expose neither routes nor metadata.
Existing `NewFeature` password routes may coexist and are never relabeled.

Signup/signin use the corresponding username-enabled native password owner,
original username-specific pre-auth flow and signed browser device. Signup
requires email plus username and returns neutral verification acknowledgement.
Signin accepts `username` instead of `identifier`; the selected profile requires
authoritative known-empty MFA. `MFAContinuation` is rejected, not downgraded.

Availability accepts only one bounded query `username` and calls the native
durable risk/audit/occupancy owner on every attempt. Its no-store boolean is
advisory, not a reservation or account-status disclosure.

Rename requires the original session cookie, exact trusted `Origin`, sole
`X-CSRF-Token` and original `Idempotency-Key`, plus closed JSON `proofID`,
`identifierID`, `expectedIdentifierVersion`, `expectedVerificationVersion` and
`username`. Select the actual native rename service and original native signed
proof repository, never consumer-written stores. Original proof/request custody
is authenticated before shared rate admission. There is intentionally no new
current-session read before original-key resolution: a committed rename already
invalidates identifier-bound sessions, but exact retries must retain metadata.
Native mutation independently checks current authority/MFA/CSRF and atomic
proof/name/cooldown/session effects. Responses never reissue credentials or
grant automatic retry permission. Full reference/HTTPS qualification remains
pending until its separately selected composition is delivered.
