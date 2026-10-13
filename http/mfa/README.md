# MFA HTTP transport

## Opt-in disable

`FeatureConfig.Disable` / `NewDisableHandler(DisableConfig)` independently selects
`POST /v1/mfa/disable`. One target uses `{"target":"one","factorID":"…","proofID":"…"}`;
all uses `{"target":"all","proofID":"…"}` and forbids factorID even empty/null.
No body command, expected authority generation, action, label or subject override
is accepted. The native owner derives optimistic generation from actual original
disable-purpose proof custody. Supply real session/proof/service/shared-rate
owners plus exact cookie/Origin/CSRF and one `Idempotency-Key`.

The selected native sole-TOTP profile returns safe `factors` only from a fresh
known commit. One-target preserves and reports unexpired pending siblings with
closed display fields (`id`, `method`, optional `label`, `state`, `createdAt`,
`version`), bounded to100. All-target erases pending siblings and returns an empty
set. Failure/uncertainty retains safe outcome metadata without factors;
responses are no-store and issue no session cookie or replacement proof. Native
historical recovery remains the outcome path after deliberate session revocation.
Additional unsupported active factors fail closed. Unselected disable contributes
no route or OpenAPI capability; existing rename/removal defaults are unchanged.

## Safe listing

`NewListHandler(ListConfig)` owns cookie-only `GET /v1/mfa/list`;
`FeatureConfig.List` contributes that operation and its closed OpenAPI schema
independently of all mutation/login routes. Supply the real session/listing
owners, shared `SafeRateLimiter`, trusted network/tenant mapping, cookie policy,
clock and positive whole-call budget. No application domain store is needed.

The route rejects Authorization, query/body, target-user and idempotency overrides.
It is a read, not a mutation-CSRF operation. Safe IP/subject quotas and middleware
work do not renew original session validity. Output contains only bounded factor/
device metadata and remaining code count, including legitimate empty/count0
state. It emits no cookie, CSRF, proof, redirect or transaction outcome. Every
response is no-store/nosniff JSON; existing final-status/body custody guards also
withhold metadata after expiry or failed delivery. Consumers render labels as
untrusted display text. No UI or automatic refresh is provided.

Go 1.27 opt-in `net/http` adapters for native pending TOTP enrollment and the
password/TOTP and magic-link/TOTP completion profiles. This is backend transport, not a UI or a
factor verification engine.
Full MFA transport remains in development; the selected reference HTTP journey
proves actual native completion, metadata-only retry, session read and logout.

## Adoption

Provide a `TOTPVerifyConfig` containing the same native completion/source owner,
strict shared verification rate limiter, trusted network/tenant mapping, exact
HTTPS origin/callback, original signed device profile and session cookie policy.
The native owner performs current authority checks and atomic shared-attempt,
one-use, audit, lifecycle and session effects. The transport creates no stores,
transactions, issuer, global registration, goroutines or automatic retries.

```go
handler, err := mfahttp.NewTOTPVerifyHandler(config)
```

Use `NewFeature(FeatureConfig{TOTPVerify: &config})` when composing the owned
HTTP operation router and OpenAPI document. Omit the feature to expose nothing.
Select `FeatureConfig.PasswordTOTPVerify` for a password-origin native owner.
When both login profiles are selected, `X-MFA-Variant: password` selects password
completion and no header selects magic-link. Password-only selection defaults to
password. The standalone handler requires `TOTPVerifyConfig.PasswordPrimary`
for password delivery. Profiles reject one another's authentication evidence;
failure never falls back to another login owner.
Resources and callbacks remain borrowed; close them only after calls finish.
`NewTOTPVerifyHandlerWithMiddleware` and `NewFeatureWithMiddleware` attach hooks
to the actual decode, source, rate-admission and execution phases.

## Wire contract

### Authenticated TOTP step-up

`NewActiveStepUpHandler(ActiveStepUpConfig)` and `FeatureConfig.ActiveStepUp`
select only `X-MFA-Variant: step-up` on `POST /v1/mfa/totp-verify`. Closed JSON
contains `commandID`, `factorID` and `code`. The original session cookie, exact
HTTPS Origin and native `X-CSRF-Token` are required; Authorization,
Idempotency-Key, query/trailer fields, purpose overrides and trusted-device
choices are rejected. Native `ActiveStepUpService` supplies authenticated
read-only quota/deadline custody before actual protected TOTP verification.

Only fresh known commitment returns `verified`, `commitOutcome`, `commandID`
and `proofID`. No session is issued. The proof is exclusively for recovery-code
regeneration, not login or enrollment. Replay, uncertainty, expiry and failed
delivery return no proof. Original observation and proof deadlines are retained
through rate admission and final-response middleware. Selecting this variant
does not select the regeneration route or another verify variant. Allow the
variant header in CORS only when this feature is explicitly selected.

### Recovery-code regeneration

`NewRecoveryRegenerateHandler(RecoveryRegenerateConfig)` and
`FeatureConfig.RecoveryRegenerate` independently select
`POST /v1/mfa/recovery-regenerate`. Closed JSON is `commandID`, `proofID`.
Supply the actual current session cookie, exact HTTPS Origin and native
synchronizer. No user, set, count, purpose, Authorization, request-key header,
query or trailer is accepted. Borrow the native replacement service and its
committed original reauthentication source; metadata alone grants no authority.
The native service must authenticate original issuance and atomically consume
the proof with replacement, factor advancement, session revocation and events.

Configure `CodeCount` identically to native policy (1..64) and use its positive
`MaximumAge` (at most five minutes). The modern native profile returns independent
16-byte random codes as canonical 22-byte unpadded base64url; the transport
checks that profile before disclosure. The original proof lifetime determines
shared challenge quota; native command identity retains debit/retry correlation.
Original proof/session/freshness deadlines remain exclusive across waits and
delivery. Successful mutation intentionally revokes the source session: output
uses the original observation deadline, not a renewed read or session revival.

Only an error-free fresh known commit returns `regenerated`, `commitOutcome`,
`commandID`, `recoveryCodes`. Secrets are destroyed after explicit delivery and
never cached or redelivered on replay, uncertainty, cancellation, expiry or failed
final-response middleware. After revocation, further cookie retries may return
401; reconcile the original native command through code-free recovery instead
of interpreting uncertainty as rollback. Sign in again after successful replacement.

### Recovery-code completion

`NewRecoveryUseHandler(RecoveryUseConfig)` and `FeatureConfig.RecoveryUse`
select `POST /v1/mfa/recovery-use` explicitly. The closed body contains
`commandID`, `preAuthID`, `continuationID`, `token`, `recoveryCode` and
`callbackURL`; original flow/device cookies and exact Origin are required.
Caller-selected users, factors, recovery sets, remember policy and OTP fields
are rejected. Select `PasswordPrimary` only for matching password-origin native
issuance. There is no TOTP fallback. Fresh delivery includes `recoveryRequired`
from committed native policy; it does not grant authority for regeneration.
The standalone transport requires a `RecoveryUseService`. The reference server
supplies the native password-primary owner through `PasswordSignin.Recovery`
and `FeatureSet.PasswordRecovery()`. Select `HTTPMFA.PasswordRecoveryUse` to
expose that profile; the transport alone does not implement authentication.

The composed verify route reserves `X-MFA-Variant: enrollment` for its distinct
authenticated confirmation profile. Absence selects existing login. Empty,
duplicate, unknown and unselected values deny before authentication, with no
cookie/body inference or fallback. Select `FeatureConfig.EnrollmentConfirmation`
with its native source, session, verification rate and cookie owners; setting
this header alone does not enable it. When configuring browser CORS, allow
this header only for an explicitly selected confirmation profile.

`POST /v1/mfa/totp-verify` accepts a closed JSON object containing `commandID`,
`preAuthID`, `challengeID`, `factorID`, `token`, `code`, `callbackURL` and
`trustDevice`. Original `__Host-identity_flow` and signed
`__Host-identity_device` cookies and exact Origin are required. Subject, tenant,
actor and network are never accepted from JSON. Idempotency-Key, Authorization,
query strings, trailers and redirects are forbidden.

Admission is trusted IP → native authenticated original source → shared
subject/challenge quota → actual native completion. The source lifetime is the
original signed interval, not remaining or renewed validity. HTTP retries can
spend ordinary transport quotas; native original-command retries do not spend
the protected MFA budget again. Unsupported native trusted-device requests deny
rather than silently changing policy.

JSON contains only original outcome/command and historical session metadata.
Only a new error-free committed result can deliver its native secure cookie and
`X-CSRF-Token`. Replay, ambiguity, denial, mismatched provenance, cancellation,
expired delivery and middleware changing the final response status deliver
neither credential. Responses are no-store; secret headers cannot be injected
through middleware unwind or trailers. A known commit without delivered
credentials remains a commit, not proof of rollback or permission to reissue.

## Scope and caveats

### Pending enrollment selection

`FeatureConfig.Enable` independently selects `POST /v1/mfa/enable`. Supply
`EnableConfig` with the native session reader, committed reauthentication source,
enrollment service, shared keyed rate owner, session cookie policy and exact
trusted HTTPS origins. The request body contains only `proofID`; the session
cookie, `Origin`, `X-CSRF-Token` and original `Idempotency-Key` are mandatory.
The HTTP handler does not accept body-selected users, methods or factor policy.

An error-free known commit returns pending enrollment metadata (`active:false`).
Only a fresh commit includes reveal-once `recoveryCodes`; securely retain these
and never log the response. A matching retry returns no codes. Error/unknown
observations retain the original command ID when available and are not proof of
rollback. Do not replace the original request key or verification proof to retry.
The handler issues no session, cookies or provisioning URI. URI revelation and
code confirmation are separate required steps; URI HTTP/reference wiring is
available through explicit selection below, including confirmation HTTP.

`FeatureConfig.URI` separately selects `POST /v1/mfa/totp-uri` using `URIConfig`.
The native service also supplies the original enrollment's quota lifetime and
earliest delivery deadline. JSON accepts only `commandID` and `enrollmentID`;
cookie, exact Origin and original synchronizer are required. Idempotency-Key,
Authorization and subject/lifetime overrides are forbidden. Keep the same
canonical random reveal command across retries. The first known committed
disclosure returns its URI; matching replay returns 409 with committed metadata
and no URI. All outcomes send no-store/no-cache and issue no session or redirect.
Select `FeatureConfig.EnrollmentConfirmation` separately for HTTP code
confirmation. Select password-first login independently through
`FeatureConfig.PasswordTOTPVerify` as described above.

The selected login profiles use original password or magic-link primary plus confirmed TOTP, with
original remember policy and primary authentication freshness. It does not add
OTP, recovery-code, passkey, security-key, trusted-device or reusable
step-up routes. Those remain required platform work. Expired-proof historical
reconciliation uses the native proof/code-free recovery API; no automatic
recovery endpoint is implied here.

Focused transport tests use native completion and atomic rate-store seams;
they prove parsing, ordering, response custody and denial, not durable factor
authentication. The real reference HTTP integration proves the selected durable
journey. Final coherent-slice review and all applicable release gates remain
required before broader delivery/completion claims.

## Opt-in factor management

Select `FeatureConfig.FactorUpdate` separately with the real native manager,
session and original signed-proof source, exact HTTPS origins and the existing
shared keyed limiter. `POST /v1/mfa/factor-update` accepts only `factorID`,
`proofID`, `action: "rename"`, explicit `name` (empty clears), and positive
`expectedVersion`. Send one `Idempotency-Key`, the session cookie, `Origin` and
the original `X-CSRF-Token`. Subject, tenant, command and proof method/purpose
cannot be supplied in the body; bearer/query/duplicate alternatives deny.

Empty `FactorUpdateConfig.Actions` preserves rename-only behavior. Explicitly
select `mfa.Remove`, alone or with `mfa.Rename`, only with a native manager whose
recovery owner is configured. Remove takes the same fields except `name`, which
is forbidden even when empty. Both actions are closed startup selections; replace,
duplicates and unknown actions deny. Selected OpenAPI reflects the same action
and response-state set. Successful removal returns revoked safe metadata, not
recovery codes, a reset grant or a new session.

To issue the matching TOTP proof, separately configure `ActiveStepUpConfig.Purposes`
and send the exact selected `purpose` on the existing authenticated step-up arm.
An empty purpose set preserves regeneration-only compatibility. Missing purpose
is allowed only if regeneration is selected; null never selects a default.
Management selection does not enable step-up, enrollment, login or regeneration.

Rename and removal revoke subject sessions, including this cookie. Fresh success returns
safe factor metadata and the owner-derived command; subsequent recovery uses
the native outcome API, not a revoked HTTP cookie. HTTP has no implicit recovery
endpoint and never redelivers factor proof, session credentials or fresh metadata.

## FAQ

- **Does a successful quota read authorize login?** No; native completion must
  independently authenticate original proof/browser and current factor policy.
- **Can a replay deliver the session again?** No; it returns metadata without
  token, cookie or synchronizer custody.
- **Can middleware renew delivery validity?** No; final commitment compares
  original primary/MFA deadlines and session lifetime without issuing anew.

See [CHANGELOG.md](CHANGELOG.md) for release notes.
