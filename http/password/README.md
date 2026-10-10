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

Responses are credential-free JSON with no-store/nosniff. Error codes are stable
and redacted. Invalid input is400; missing/inactive session401; origin/CSRF or
proof mismatch403; path404; method405; host421; rate429; operational/ambiguous
failure503 (including proof-source outages); native conflict/in-progress409.
A native pre-command conflict has no command or recovery locator; transport
does not manufacture one. `commitOutcome=none` is not rollback. Known command/outcome/recovery
metadata survives errors, while `changed` and successor fields require an
error-free known commit. Recovery is a locator under current result-access
policy, not a permission or instruction to automatically repeat mutation.

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
- Is this full password feature parity? No. Verify/signup/signin/reset/set,
  selected Feature/OpenAPI composition, composed native HTTP/browser checks,
  privacy/interoperability and exact coverage/mutation/release gates remain.
- Does a committed error mean HTTP success? No; reconcile original scoped
  recovery without new keys or resubmitted secrets.

See [release notes](CHANGELOG.md) and Go documentation for the public contract.
