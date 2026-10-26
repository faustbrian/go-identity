# go-identity/http/organization

Optional **bearer-only** HTTP integration for native organization creation,
explicit organization reads, metadata/role updates, member listing, admission/removal and original-key
invitation sending/resend and once-only acceptance. Omit its
feature contribution to expose no organization routes or metadata. It imports
only transport-neutral organization contracts, never PostgreSQL.

Metadata replacement (`Update`) and static member-role replacement
(`MemberUpdate`) are independently selected. Supply the actual native
`OperationService` as `Config.MetadataUpdater` and/or `Config.MemberUpdater`,
with current `Sessions` and shared `AdminRate`. Neither selection requires
`Service` or `SafeRate`; existing five-method Service implementations remain
compatible. Native current authority, exact versions and last-owner protection
are not replaced by HTTP admission.

Invitation reads are independently opt-in through `InvitationGet` and
`InvitationListMine`. Supply the actual native invitation owner through
`Config.Invitations`; it implements the narrow `InvitationReader` port directly.
An invitation-read-only selection needs `Sessions`, shared `SafeRate`, network/clock
and timeout configuration, but neither the five-operation `Service` nor
`AdminRate`. No application invitation store or authority adapter is needed.

Invitation sending is independently opt-in through `InvitationSend`. Supply
`Config.InvitationSender` as the actual native `InvitationOperationService` and
`Config.Invitations` as its underlying `InvitationService`, plus `Sessions`,
shared `AdminRate`, trusted network/clock and timeout configuration. A send-only
selection requires neither `Service` nor `SafeRate`. Install the existing native
request-key/preparation/expiry-fence and invitation/capability/delivery migrations
before selecting it. No application workflow or transaction adapter is required.

Invitation resend is independently opt-in through `InvitationResend`. Supply
the actual native `InvitationOperationService` as `Config.InvitationResender`,
current `Sessions` and shared `AdminRate`. Neither `Service`, `Invitations` nor
`SafeRate` is needed. Install the native resend and retained request-key/expiry
histories first. The recipient, role and original exclusive expiry are fixed;
the request cannot choose an address, proof, command or new deadline. Native
current owner/administrator and recipient security remain authoritative.
The returned delivery state belongs to the original command, even after later
resends or acceptance. No owner-only current-invitation read is substituted for
administrator recovery. A late observation error retains known commitment but
withholds delivery state; queued/accepted do not establish confirmed delivery.

Invitation acceptance is independently opt-in through `InvitationAccept`.
Supply the actual native `InvitationService` as `Config.InvitationAccepter`,
current `Sessions` and one shared `identityhttp.KeyedSecretRateLimiter` as
`SecretRate`. Despite the limiter's name, acceptance uses its original-command
API and **forbids Idempotency-Key**. No `Service`, invitation reader, safe or
administrative limiter is needed for acceptance alone. The native owner retains
the exact prepared mutation across phases: admission validates the original
signed challenge ID/lifetime and charges quota before any before-handler hook;
the handler executes that same preparation. The transaction consumes proof with membership,
authority, audit and lifecycle effects. No application domain adapter is needed.
`InvitationProofLimits` defaults to capability's parsing limits; configure the
issuer's matching bounded profile. The public accept token remains32..4096 bytes.

Keep a caller-generated canonical `commandID` before the original attempt.
Acceptance is once: re-posting a consumed proof may conflict and is not recovery.
Persist the returned safe `recovery` binding plus `organizationID`; supply them
with current authentication to native `RecoverAccept`. Recovery never resubmits
or infers success from membership. No HTTP recovery route is selected, and a
bare command ID cannot recover after losing the entire response. An unknown
outcome is not permission to allocate another command or replace the proof.

## Composition

The retained genuine PostgreSQL/HTTPS tests live in the nested `consumer`
test module. From that directory, set `GOLIB_ORGANIZATION_TEST_POSTGRES_DSN` to
an isolated disposable PostgreSQL database and run
`GOWORK=off go test -race -tags=integration -run '^TestInvitation.*GenuineHTTPConsumer$' -count=1 .`.
They consume the authenticated public transport/native modules, not a local
replacement. The ordinary transport module does not depend on Reference.

For the original organization/member operations:

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
| Update | `POST /v1/organization/update` | JSON `organizationID`, exact `organizationVersion`, `name`, `slug`; required original key |
| Get | `GET /v1/organization/get` | Required query `organizationID` |
| List members | `GET /v1/organization/member/list` | Query `organizationID`, optional exclusive `cursor`, `limit` 1..100 (default100) |
| Add member | `POST /v1/organization/member/add` | JSON `organizationID`, target `userID`, `role`, `organizationVersion`, `memberVersion`; required original key |
| Update member role | `POST /v1/organization/member/update` | Same fields as add, with positive exact organization/member versions; required original key |
| Remove member | `POST /v1/organization/member/remove` | JSON `organizationID`, target `userID`, exact positive organization/member versions; **no key** |
| Accept invitation | `POST /v1/organization/invitation/accept` | JSON original `commandID`, `organizationID`, `invitationID`, exact positive `organizationVersion`, `invitationVersion`, private `token`; **no key** |
| Send invitation | `POST /v1/organization/invitation-send` | JSON `organizationID`, exact positive `organizationVersion`, target `recipientUserID`, existing verified `recipientIdentifierID`; required original key |
| Resend invitation | `POST /v1/organization/invitation/resend` | JSON `organizationID`, exact positive read-only `organizationVersion`, `invitationID`, `invitationVersion` 1..MaxUint64-2; required original key |
| Get invitation | `GET /v1/organization/invitation/get` | Required query `organizationID`, `invitationID`; native **owner-only** authorization |
| List my invitations | `GET /v1/organization/invitation/list-mine` | Optional opaque `cursor`, `limit` 1..200 (default100); current verified recipient, no membership required |

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

Create/update/add/member-update/send/resend forward the **single unchanged original key** to the actual native
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

## Invitation discovery and current reads

Select `NewFeature(FeatureConfig{Config: cfg, InvitationGet: true,
InvitationListMine: true})` to expose only those two routes and their concrete
OpenAPI operations. Omitting either flag omits that route and its metadata.
Configure the actual native invitation migrations, delivery status owner and
recipient-page index before selection. The native `Get` remains owner-only:
being the invited recipient, including after acceptance, does not grant it.
Recipient discovery uses `ListMine`, never a caller-supplied recipient/address.

Both reads use the same strict bearer/current-session and shared `rate.safe`
boundaries as other safe reads. For `ListMine`, the native owner separately
revalidates current session, self policy and exact verified recipient identifier
ID/version. Removing
verification or replacing that identifier removes its discoverable invitations;
an invitation or cursor never authenticates anyone or grants membership.

Responses project only invitation ID, organization ID, role, status, version and
expiry, without email, recipient identifiers, creator, capability, delivery
effect/digest/ciphertext or internal authority. `Get` wraps one `invitation`;
`ListMine` always returns an `invitations` array, including when empty, and an
optional `nextCursor`. Status is `pending`, `accepted`, `expired`, `cancelled` or
`rejected`. Native natural expiry projects `expired` at its exclusive boundary.
All retained installed states are discoverable; this is not a pending-only list.

Pages are current-state keysets ordered by bytewise invitation ID, not snapshots.
Return the subject-bound opaque cursor unchanged (at most 512 bytes); it grants
no authority, cannot move between subjects/tenants and is revalidated natively.
Restart the listing to observe additions before the current position. After
native or independently selected HTTP acceptance, member and invitation reads
observe its actual committed state without a positive authority cache.
This read-only selection enables neither invitation mutations nor Reference
composition. Select sending or acceptance independently as described here;
other invitation mutations remain unavailable.

## Invitation sending and current delivery state

The selected send route owns no invitation proof or delivery retry loop. The
native owner allocates the original command and invitation IDs and atomically
commits invitation, single-use proof, encrypted delivery, protected audit and
lifecycle effects. Submit the same exact key and original input for a matching
retry; changed recipient, organization/version or configuration conflicts.
Never supply an address, acting identity, tenant, command ID or invitation ID.

The response keeps `committed`, `commitOutcome`, original `commandID`,
`invitationID` and safe `recovery` scope separate from the current `invitation`
metadata and `deliveryState`. It returns no membership, proof, email, provider
reference or delivery effect ID. A separate current owner-authorized native
read supplies the metadata/status within the original HTTP read deadline. If
that read fails or panics, the response retains the actual original committed
outcome with its error status but omits current metadata; that failure is not
rollback and must not cause a replacement send. Noncommitted/unknown outcomes
do not perform a current projection.

`queued` is durable local admission, `attempting` is a recorded attempt, and
`accepted` is provider acceptance—not confirmed `delivered`. Rejection, bounce,
cancellation, unknown, retry wait, expiry, exhaustion, supersession and transient
failure remain distinct. HTTP retries charge the same shared administrative
budgets and never redeliver proof. Sending does not select HTTP acceptance or
resend. The independently selected native-backed acceptance handler consumes
the delivered proof exactly once.

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

For the original five operations, `State` offers detached principal metadata to
trusted synchronous middleware through the base real pipeline. Detached request headers still
contain credentials: never log or retain them. Hooks cannot rewrite immutable
owner inputs, extend original proof validity, replay stages or emit credential
headers/trailers. After-handler observation means an attempt, not a commit.
All dependencies are borrowed, no goroutines are started, and earlier caller
cancellation wins. Callers retain raw body and server cleanup ownership.

## Tradeoffs / FAQ

- **Cookies, other invitation mutations, teams or active selection?** Not selected.
  These need their own native profile and transport contract, not fallback
  through this one.
- **Does a role or recovery scope grant access?** No. Current native authority
  is checked again; last-owner protection is never a transport decision.
- **Can I use an in-memory fake as shared production rate storage?** No. The
  strict atomic port requires actual strong, durable, indivisible ownership.
- **Does OpenAPI prove durability?** No. Wire tests prove transport; the separate
  genuine native integration proves session/authorization/SQL commit behavior.
- **Who closes borrowed stores?** The application, after requests finish. Closing
  `AdminRateLimiter` only prevents new calls; it does not close its backend.

Public API reference is the Go documentation for `Service`, `InvitationReader`,
`InvitationSender`, `InvitationSendResponse`,
`Config`, `FeatureConfig`, `NewFeatureWithMiddleware`, `AdminRateConfig`,
`AdminRateLimiter`, `State`, and the explicit response DTOs. Release notes are in
[CHANGELOG.md](CHANGELOG.md).
