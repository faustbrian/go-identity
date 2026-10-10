# Password HTTP integration

**Experimental development checkpoint, not a complete password HTTP product.**
Go 1.27. Base `identity/http` does not import this optional module.

## Adoption and API

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

- Why a separate module? Optional password/session imports cannot enter base HTTP.
- Why a proof ID? The original signed native verification is loaded unchanged;
  transport never creates a proof from client-claimed identity or timestamps.
- Can consumers implement stores/transactions? No: select the platform adapters.
- Is this full password feature parity? No. Cookie verification/signup/signin/reset/set,
  native selected-router and browser qualification, privacy/interoperability
  and exact coverage/mutation/release gates remain. Native SQL-over-handler
  password-change behavior has focused integration coverage, not browser proof.
- Does a committed error mean HTTP success? No; reconcile original scoped
  recovery without new keys or resubmitted secrets.

See [release notes](CHANGELOG.md) and Go documentation for the public contract.
