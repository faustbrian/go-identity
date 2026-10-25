# go-identity/http/organization

Optional **bearer-only** HTTP integration for native organization creation,
explicit organization reads, member listing, admission and removal. Omit its
feature contribution to expose no organization routes or metadata. It imports
only transport-neutral organization contracts, never PostgreSQL.

## Composition

1. Construct the actual native organization `OperationService` and its genuine
   session owner. Apply that owner's request-key/preparation and concurrent
   removal-lookup migrations before selecting direct operations. Existing native
   `Prepare*` APIs remain unchanged.
2. Construct one base `identityhttp.SafeRateLimiter` shared with other safe
   routes and one `NewAdminRateLimiter` using a genuine shared
   `ratelimit.StrictAtomicBatchBackend`. PostgreSQL rate stores require their
   native atomic schema. The caller owns those stores and lifetimes.
3. Supply the copied exact host/proxy/input-bound `Network`, actual `Sessions`,
   native `Service`, trusted `Now` and bounded `MaximumDuration` in `Config`.
   Never infer tenant or client IP from arbitrary headers or body input.
4. Call `NewFeature(FeatureConfig{Config: cfg, Create: true, Get: true,
   MemberList: true, MemberAdd: true, MemberRemove: true})`. Each operation is
   independently opt-in. Pass the resulting contribution through
   `identityhttp.NewOperationDescriptors` and `NewRouter` (or the corresponding
   documented composition), sharing the same network policy. Use the base
   bounded HTTP server for raw IO/write deadlines and body closure.

`organization/postgres.OperationService` implements `Service` directly. No
application organization store, command journal, transaction adapter or identity
engine is required. The transport authenticates once for current actor-rate
custody; the native owner independently retains its actual final authorization,
session, protected risk, membership and atomic commit fences.

## Selected wire contract

| Operation | Exact route | Request |
| --- | --- | --- |
| Create | `POST /v1/organization/create` | JSON `name`, `slug`; required original `Idempotency-Key` |
| Get | `GET /v1/organization/get` | Required query `organizationID` |
| List members | `GET /v1/organization/member/list` | Query `organizationID`, optional exclusive `cursor`, `limit` 1..100 (default100) |
| Add member | `POST /v1/organization/member/add` | JSON `organizationID`, target `userID`, `role`, `organizationVersion`, `memberVersion`; required original key |
| Remove member | `POST /v1/organization/member/remove` | JSON `organizationID`, target `userID`, exact positive organization/member versions; **no key** |

Every request requires exactly one syntactically strict Authorization Bearer
header containing the native opaque session token. Cookies are ignored as
authority, never a fallback. HTTPS and an exact configured tenant host are
required. No browser-origin/CSRF-cookie workflow is selected; the canonical
descriptor's narrow bearer exception does not enable other mutations.

Mutations accept a closed JSON object only: unknown, duplicate/case-alias or
missing names, nulls, fractional/overflowing versions, query/trailer alternatives
and identity/tenant/actor/command overrides fail before owner IO. The membership
`userID` is a target selector, not a claimed acting identity. Member version zero
on add means never admitted; removal requires a positive exact version. Header
and body/query limits come from the base bounded decoder. IDs remain
case-sensitive; names and slugs retain the root module's validation. Caller
correlation and command IDs are not accepted; the owner supplies correlation.

Create/add forward the **single unchanged original key** to the actual native
owner. Matching retries recover that original command; changed intent conflicts.
The transport never reconstructs an old bearer, refreshes original evidence,
chooses another command ID, retries automatically or interprets a timeout as
rollback. Removal remains a naturally repeatable exact-version operation. Its
native owner must prove an actual matching historical receipt under current
authority; a missing member or tombstone alone cannot manufacture success.

## Rates and denial auditing

The identity-platform `API_OPERATIONS.md` canonical `rate.admin` row owns the
fixed limits: actor30/minute, tenant100/minute, trusted full-IP60/minute. All three
are admitted atomically by the existing shared strict backend; no per-item
fallback, local rate engine or emergency administrative budget exists. Share
immutable namespace, HMAC key and policy identities across all administrative
routes. Rotating these identities resets effective budgets and is an explicit
deployment decision, not a routine key refresh.

Each HTTP attempt receives a fresh owner-generated **rate debit** command, not
an application mutation ID or client idempotency key. Repeat/keyed HTTP retries
still consume the shared HTTP budget. Ambiguous admission grants no authority
and is never automatically redispatched. The required bounded `Denied` callback
records limit and infrastructure denials without actor, tenant, IP, credentials,
submitted values or underlying diagnostics. Audit failure itself fails closed.
Protected native domain audit and risk counters remain separately mandatory.

Reads use the actual base `rate.safe` owner, including its documented bounded
emergency behavior. Neither rate owner authenticates or authorizes a mutation.

## Results, recovery and security

Responses are bounded explicit no-store/nosniff JSON, never credentials,
redirects or internal authority vectors. Success is200; malformed input400,
denial403, last-owner/conflict/limit409, rate429 with bounded ceiling
`Retry-After`, and unavailable/unknown503. Wrong paths/methods retain404/405;
unknown tenant hosts deny. Native errors and panics never expose diagnostics.

Inspect `commitOutcome` even when status/error is non-success. Only a validated
actual committed receipt sets `committed`. `unknown`, `not_committed`, conflict
and in-progress remain distinct. A post-dispatch timeout cannot erase a known
original outcome. `commandID`/`recovery` contain safe original scope, not a
receipt or permission by themselves. Persist them when needed, together with
the original request/key; use the native owner's current-authorized
`RecoverOperation` for explicit recovery. No extra recovery HTTP route is
selected. Never resubmit an unknown operation with a replacement key.

`State` offers only detached principal metadata to trusted synchronous
middleware through the base real pipeline. Detached request headers still
contain credentials: never log or retain them. Hooks cannot rewrite immutable
owner inputs, extend original proof validity, replay stages or emit credential
headers/trailers. After-handler observation means an attempt, not a commit.
All dependencies are borrowed, no goroutines are started, and earlier caller
cancellation wins. Callers retain raw body and server cleanup ownership.

## Tradeoffs / FAQ

- **Cookies, invitations, teams or active selection?** Not selected. These need
  their own native profile and transport contract, not fallback through this one.
- **Does a role or recovery scope grant access?** No. Current native authority
  is checked again; last-owner protection is never a transport decision.
- **Can I use an in-memory fake as shared production rate storage?** No. The
  strict atomic port requires actual strong, durable, indivisible ownership.
- **Does OpenAPI prove durability?** No. Wire tests prove transport; the separate
  genuine native integration proves session/authorization/SQL commit behavior.
- **Who closes borrowed stores?** The application, after requests finish. Closing
  `AdminRateLimiter` only prevents new calls; it does not close its backend.

Public API reference is the Go documentation for `Service`, `Config`,
`FeatureConfig`, `NewFeatureWithMiddleware`, `AdminRateConfig`,
`AdminRateLimiter`, `State`, and the explicit response DTOs. Release notes are in
[CHANGELOG.md](CHANGELOG.md).
