# Email HTTP integration

Experimental Go 1.27 backend library, not a UI or complete email product.
Base `identity/http` does not import this optional module.

## Quick start and adoption

Configure `ConfirmationConfig` with the native `password/postgres.SignupService`
(the committed confirmation/rate-source API), a shared
`identityhttp.ChallengeVerificationRateLimiter`, exact trusted network/tenant
hosts and HTTPS Origin, a deployment service actor/current query-policy revision,
a prompt trusted clock and 1ms..30s whole-call budget. Install the native owner's
selected migrations, counters, keyring and original delivery/issuance policy.
Borrowed owners must outlive handlers; drain before closing them.

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

- `ConfirmationService`: consumer-owned native original-source/confirmation
  port, implemented by `SignupService` without an HTTP dependency.
- `ConfirmationConfig`: immutable explicit no-session selection.
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

Address management, scanner/delivery HTTP, full auto-signin, native SQL-over-HTTP
journey qualification, browser interoperability, exact coverage/mutation and
remaining release gates are still pending. See [CHANGELOG.md](CHANGELOG.md).
