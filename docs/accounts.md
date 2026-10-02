# Account ownership and safe reads

## API, adoption and limits

This module targets Go 1.27. `Account` is the identity-owned provider link, with
explicit tenant, user, stable account ID, provider, exact issuer/subject and
positive version. It contains no provider tokens. `CredentialRef` is a separate
tenant/user-bound non-secret pointer with a closed credential kind and owning
feature; it is never a verifier, factor, session or bearer.

`ParseAccountID` preserves structurally valid canonical IDs, including ULIDs,
without rewriting them. IDs are case-sensitive and bounded to 128 UTF-8 bytes.
Imported source canonicalization/collision policy still belongs to trusted
directory composition; parsing or constructing metadata grants no authority.

Account issuer metadata accepts bounded HTTPS URIs and federation URNs without
query, fragment or credentials. The protocol owner must validate and register
the exact canonical issuer; identity does not fetch, discover or trust a URI.
Provider subjects are exact, bounded to 512 UTF-8 bytes and never normalized.
Account and credential formatting redact all diagnostic metadata.

`NewAccountService` composes a narrow `AccountRepository`, the exact upstream
authorization service, redaction callback and existing `UserQueryConfig`.
`AccountList` requires the exact current human subject and `identity.account.list`
context supplied by trusted authenticated composition. It authorizes before
primary access, validates a consistent user/account snapshot, checks current
active status and policy, then enforces each account's policy and redaction.
Caller-provided identity metadata is removed before policy evaluation.

The bounded complete-read profile returns at most 100 accounts in strict ID
order. The repository must fail rather than silently truncate a larger set.
`NextCursor` stays empty; stable pagination remains required implementation.
Duplicate IDs and duplicate provider/issuer/subject links are invalid. No provider
network calls occur. Each operation samples the configured clock once, derives
a bounded context and privately copies its public output. Dependencies and
callbacks must honor deadlines and be concurrency-safe; the service owns no
goroutines, locks or transactions.

## Projection and failures

Per-account denials omit that row without exposing a total count. A valid
redaction decision must partition exactly ID, tenant, user, provider, issuer,
subject and version under the current policy/version and registered reason.
Issuer/subject may be omitted. Withholding required identity fields omits the
row; malformed policy or a dependency/cancellation/panic failure withholds the
whole result, not a partial success. Empty success returns an explicit empty
slice. Missing user scope and policy denial share `ForbiddenError`.

## Final-access decision

`CheckAccountUnlink` is a pure policy check, not a mutation or authorization
proof. It accepts an exact primary `AccountAccessSnapshot`, target account and
expected account version with one trusted clock sample. The snapshot contains
at most 100 accounts and 128 `LoginMethod` observations with unique credential
IDs. Every credential reference must match the same tenant/user and registered
kind/owner. Provider methods require an existing account; other kinds cannot
claim provider-account dependency.

A usable independent password, passkey or other provider method can preserve
access. Disabled/unverified/policy-unavailable methods, methods at or after
exclusive expiry, every method depending on the removed account and API keys
cannot. `FinalAccessError` rejects a resulting zero count. An authentication
link requires credential invalidation even when its method was expired.

`LoginMethod.Usable` is an authoritative owner observation incorporating
verification, enablement, policy/factor and provider availability—not a caller
boolean. A public client must never submit this snapshot. The durable unlink
owner must authorize first, re-read all owner eligibility under its own locks,
repeat this exact check and fence user, account, social-link and applicable
credential authority versions in the mutation transaction. Two simultaneous
unlinks must not each rely on the other's soon-to-be-removed credential.

## Tradeoffs, FAQ and pending work

Why not count API keys? They do not replace a human login/recovery method.
Why separate provider links and credentials? A link may be data-only, and one
removed link can invalidate several credential observations.
Why require complete snapshots? A stale or partial count can orphan access.

These tests prove safe core reads and the final-access decision, not durable
link/unlink concurrency. Transactional commands/recovery, implicit/explicit/admin
linking, fresh credential-specific proofs, risk consumption, provider token
cleanup/revocation, stable pagination, SQL and complete Service/catalog/release
evidence remain required. Consumers must not implement these missing platform
workflows themselves. No full identity-platform completion is claimed.
