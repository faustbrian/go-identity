# Email HTTP integration

## Explicit original-browser verification and signin

Select `FeatureConfig.VerificationSignin` instead of `SignupConfirmation` for
this registration-only profile of `POST /v1/email/verification-confirm`. Supply
the real native signin service and original registration rate source, exact
origin/actor/policy, signup flow-cookie policy, signed browser-device config and
matching session cookie/audience. The closed body is unchanged: `token`,
`callback`, `commandID`; no identity or remember override is accepted. Original
flow/device cookies are required and never treated as authenticated sessions.

The response preserves the verification outcome and optional distinct `signin`
command outcome/recovery. Only a fresh error-free committed login delivers one
secure HttpOnly cookie and `X-CSRF-Token`. Neither is in JSON or redirects;
replay/unknown/failure never redelivers them. Selected OpenAPI describes this
profile. Default, shared managed-address and primary-change confirmation stay
verification-only; conflicting verification-route selectors reject at startup.

For administrative removal, explicitly select
`RemovalConfig.AdministrativeTargets` with a matching native capability. Optional
`targetSubjectID` selects another account; the original signed password proof,
session cookie and CSRF still identify the actual administrator. Native policy
must grant the current exact target action. Default handlers reject and do not
advertise this field. Selected requests retain normal keyed replay/recovery and
no-store outcomes; no credential, session or UI is issued by removal.

Experimental Go 1.27 backend library, not a UI or complete email product.
Base `identity/http` does not import this optional module.

## Safe self-removal

Select `FeatureConfig.AddressRemove` with `RemovalConfig`, or use
`NewAddressRemoveHandler`. Borrow the native removal/rate-source owner, original
password-proof repository, shared keyed secret limiter, cookie policy and trusted
network/origin/revision. This selects only `POST /v1/email/address-remove`.
Exactly one session cookie, `Origin`, `X-CSRF-Token`, `Idempotency-Key` and closed
JSON are required (versions are canonical decimal strings, never floats):

```json
{
  "proofID": "AAAAAAAAAAAAAAAAAAAAAQ",
  "addressID": "owned-address-id",
  "expectedIdentifierVersion": "2",
  "expectedVerificationVersion": "2",
  "reason": "user-requested",
  "primaryDisposition": "leave-unassigned",
  "recoveryDisposition": "preserve-verified-email"
}
```

The sample proof ID grants no authority: supply the actual retained fresh password
proof for this action/session/configured audience. Use `preserve-primary` only
for a nonprimary target; removal never infers a replacement. To remove the current
primary and nominate a verified replacement, use `"primaryDisposition":
"replace-primary"` and add exactly these three fields to the request:

```json
{
  "replacementAddressID": "owned-verified-replacement-id",
  "expectedReplacementIdentifierVersion": "5",
  "expectedReplacementVerificationVersion": "7"
}
```

Those are additional fields, not a separate request. Both versions come from the
replacement's address projection; the native owner checks the exact current
verified same-subject record under the removal lock. Missing, stale, self-target
or foreign replacements deny; old dispositions reject replacement fields. Native
policy denies
losing the last actual signin/reset path. Unknown/duplicate fields, body identity/
policy overrides, query/trailers, bearer and weaker-factor fallback deny.

Original possession precedes shared secret admission; native current authority
is checked atomically. Exact retry after session invalidation retains the
original result. No-store responses contain `removed`, `commandID`,
`commitOutcome` and pending `cascadeID`/`cascadeGeneration`/`cascadeStatus`.
Pending means admission, not completed cleanup; unknown is not rollback. No
credentials/redirect or HTTP recovery endpoint are implicitly enabled.

## Authenticated self address reads

Select `FeatureConfig.AddressGet` and/or `AddressList` with `AddressQueryConfig`.
The graph borrows the actual native session reader, email query owner, one shared
canonical safe-rate limiter, cookie policy and current authorization revision.
Each route is independent; selection emits no mutation or verification route.

- `GET /v1/email/address-get?addressID=...` selects one owned address.
- `GET /v1/email/address-list?limit=25&cursor=...` selects a native page; omitted
  limit defaults to25, explicit limit is1..100 and cursor is at most512 bytes.

The default profile is cookie-authenticated human self access, with no bearer
fallback. Set `AddressQueryConfig.AdministrativeTargets` explicitly to accept
optional `targetSubjectID` on either query. The service must implement
`AdministrativeAddressQueryService` with native required auditing configured;
otherwise construction fails. Selection never grants permission: the real
session user remains the actor, the native authorization engine decides each
target/action/tenant, and audit acknowledgement precedes disclosure. Selected
OpenAPI alone advertises the selector. Without selection it is rejected.
Explicitly authorized administrative queries may inspect blocked target users;
the actor still needs an actual active session and current permission.
Body/trailers, Authorization and idempotency headers
deny, as do unknown/duplicate queries and user/tenant overrides. Missing/foreign/forbidden
addresses are indistinguishable. Native canonical/display omission and independent
identifier/verification versions are preserved; account blocks observed by the
primary deny even while preliminary session evidence has time remaining.
Responses are no-store credential-free JSON bounded to1MiB, preserving native
512-byte value bounds without truncation. They issue no cookie, token, command,
refresh or mutation. Final body delivery repeats original session validity and
withholds personal data after expiry/cancellation or a changed failure status.
Public direct constructors are `NewAddressGetHandler`/`NewAddressListHandler`;
feature middleware attaches to their actual typed operation phases.

## Quick start and adoption

Configure `ConfirmationConfig` with the native `password/postgres.SignupService`
(the committed confirmation/rate-source API), a shared
`identityhttp.ChallengeVerificationRateLimiter`, exact trusted network/tenant
hosts and HTTPS Origin, a deployment service actor/current query-policy revision,
a prompt trusted clock and 1ms..30s whole-call budget. Install the native owner's
selected migrations, counters, keyring and original delivery/issuance policy.
Borrowed owners must outlive handlers; drain before closing them.

For an already-authenticated managed-address request's delivered link, select
`ManagedConfirmationConfig` with native
`password/postgres.EmailManagementService`, then call
`NewManagedConfirmationFeature` or `NewManagedConfirmationHandler`. This uses
the owner's `ManagedVerificationRateSource`, never signup provenance. The wire,
origin/counter ordering and no-session response policy below are shared. Install
both the rate backend's state and atomic-command histories before enabling it.
Selection verifies a pending non-primary address only: add/resend/change/removal
and their policies are separate native operations, not supplied by this handler.

Both selections own the same canonical route. Do not register both features:
composition rejects duplicate ownership instead of silently choosing one. A
graph supporting both link families instead selects `ProfiledConfirmation` in
`FeatureConfig`, using the native `password/postgres.EmailVerificationRouter`.
The existing issuer authenticates the signature and persisted original issuance
before its closed signed-profile switch. A selected-source error is terminal;
there is no unsigned-token inference or failed-owner fallback. Historical
provenance preserves exact-command replay without granting fresh validity.

For new-address-confirmed primary changes, select `ChangeConfirmationConfig`
with the native change-request `EmailManagementService`. Its separate
`ChangeConfirmationRateSource` cannot borrow verification-only provenance.
`NewChangeConfirmationFeature` exposes POST `/v1/email/change-confirm`; the body
has the same token/callback/command shape below. The original password proof,
new-address possession, primary transition, old-address notice and required
session invalidation remain one native workflow. Confirmation issues no session.

Select `NewFeature(FeatureConfig{SignupConfirmation: &signup,
ChangeConfirmation: &change})` to compose both canonical operations under one
feature identity. `ManagedConfirmation` may replace `SignupConfirmation`, but
selecting both for the same verification route is invalid. Empty selection is
invalid; omit the feature to expose no routes or metadata. `ProfiledConfirmation`
is also mutually exclusive with either single-profile verification selection.
Request transport is selected separately as described below; the shared
confirmation router alone does not supply it. Complete reference feature
delivery remains pending. Read transport is selected separately as above.

Call `NewConfirmationFeature(config)` and contribute it to
`identityhttp.FeatureServices`. Compose descriptors through `NewRouter` for
selected HTTP/OpenAPI 3.1.1, or `NewDocumentedHandler` for explicit dispatch.
`NewConfirmationHandler` supports direct mounting without registering metadata.
The `WithMiddleware` variants bind the same real typed phases. No consumer
handler, domain store or workflow is required.

POST `/v1/email/verification-confirm` with exactly this JSON shape:

```json
{"token":"<original-issued-capability>","callback":"https://app.example/finish","commandID":"<stable-confirmation-command>"}
```

Use the same original command ID when resolving its outcome. Never substitute
the signup command, regenerate it after uncertainty, or send `Idempotency-Key`.
The callback must exactly match original allowlisted issuance. No token in URLs,
query strings, cookies, redirects, Authorization headers or logs. Tenant, actor,
subject, challenge ID and policy lifetime are not body choices.

## API and semantics

### Keyed cookie requests

`RequestConfig` with `NewVerificationSendHandler` independently selects
`POST /v1/email/verification-send`. Supply exactly `proofID`, `address` and
`callback` in JSON; resend additionally supplies `addressID` and may omit
`address` to resolve the exact retained pending target. `NewChangeRequestHandler`
selects `POST /v1/email/change-request` with `proofID`, `newAddress` and `callback`,
and requires explicit `NotifyCurrentAddress` startup policy. Select these through
`FeatureConfig.VerificationRequest`/`.ChangeRequest` to combine with reads and
confirmation in one email feature.

Change requests may use the exact `identity.email.change-request` multi-factor
TOTP proof when both the proof source and native service explicitly select that
profile. The proof source reads original committed factor evidence; the native
owner authenticates, fences and consumes it with the protected request. This selects
neither a step-up route nor password fallback, and other email actions retain
their original proof profiles.

Both require the configured session cookie, exact HTTPS Origin, `X-CSRF-Token`
and `Idempotency-Key`. Body identity/policy/command overrides, bearer alternatives,
duplicates and aliases deny. The signed original proof and native retained-input
custody establish rate metadata before mutable session lookup; this does not
renew proof/session freshness or grant fresh work without native admission.
Verification requests use canonical shared delivery quotas; change uses shared
keyed secret quotas. Native protected counters remain cumulative.

202 `queued` means the original local delivery intent committed, not that mail
was delivered or the address verified/changed. Responses contain command/outcome
metadata only. 409 pending/conflict, 429 quota and 503 unavailable/unknown never
claim rollback or expose a mailbox/session. Preserve the same original key and
input on retry. Native typed recovery remains separate; no HTTP recovery route,
redirect, automatic retry or signin is enabled. Add/resend and primary-change
confirmation still require their separately selected native handlers.

### Confirmation

- `ConfirmationService`: consumer-owned native original-source/confirmation
  port, implemented by `SignupService` without an HTTP dependency.
- `ConfirmationConfig`: immutable explicit no-session selection.
- `ManagedConfirmationService`, `ManagedConfirmationConfig` and their handler/
  feature constructors: explicit management-link selection with the same bounded
  wire and middleware phases, without a signup or auto-signin fallback.
- `ChangeConfirmationService`, `ChangeConfirmationConfig` and their constructors:
  exact primary-change confirmation, original-action recovery and no credentials.
- `FeatureConfig`/`NewFeature`: explicit operation grouping, never hidden
  registration, inferred link ownership or an automatic signin selection.
- `NewConfirmationHandler`, `NewConfirmationFeature` and their middleware
  variants: real execution; omission exposes no route or metadata.
- `ConfirmationState.Attempt`: detached attempted metadata, not execution or
  authentication authority. Hooks cannot replace private input or repeat stages.
- `ConfirmationResponse`: original observed outcome, command and recovery
  correlation. `confirmed` means the original command committed, not current
  account eligibility. Fresh successful commit may include `ConfirmedAddress`.
  Replay and failures omit the address and all session/credential output.

Trusted IP20/10m is charged before proof parsing/source lookup. Authentication of
original issuance then supplies subject10/10m and original challenge10/lifetime
admission, without recounting IP or renewing expiry. Share namespace/key/backend
with password verification to share budgets. Native protected counters remain
cumulative. Neither admission nor historical consumed provenance grants reuse.
Storage outage, ambiguity, cancellation and unknown outcomes deny without
automatic retry or fallback. The first debit is not refunded after later failure.

HTTP statuses are 200 receipt, 400 malformed input, 403 origin/proof denial,
404 path, 405 method, 409 conflict/in-progress, 421 unmapped host, 429 exhaustion
and 503 unavailable/unknown. Retry-After is bounded ceiling seconds when present.
All responses are no-store/nosniff. Later disclosure failure preserves a known
`committed` outcome while withholding the address; inspect status and outcome.
Recovery correlation is not permission and selects no HTTP recovery endpoint.

## Security, tradeoffs and FAQ

This original-signup require-before-signin profile issues no session and ignores
ambient cookies as authority. Exact HTTPS tenant and Origin are mandatory, with
no Referer fallback. Closed bounded JSON rejects duplicates, aliases, unknown
members and credential alternatives. Response commitment and middleware unwind
strip cookies, CSRF/bearer headers, redirects and trailers. Personal projections
are authorized snapshots, not cached validity evidence.

Does this sign the user in? No. Verified-email password signin is separate;
auto-signin requires original pre-auth/session transaction composition, not a
transport flag. Does replay reveal the address again? No. Is an uncertain result
safe to replace? No; retain original command scope and use native recovery.

Removal, stronger-factor management, full auto-signin, browser interoperability,
exact coverage/mutation and remaining release gates are still pending. Selected
request/read/confirmation journeys have local native PostgreSQL/HTTPS evidence,
not whole-unit qualification. See [CHANGELOG.md](CHANGELOG.md).
