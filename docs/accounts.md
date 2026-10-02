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

`NewAccountUnlinkService` composes the existing `UnitOfWork`, exact upstream
authorization and capability services, redaction and a primary unlink repository.
Its explicit trusted issuer/audience and maximum proof age (positive, at most
15 minutes) have no defaults. `AccountUnlink` admits only the current human
subject, verifies the opaque signed capability, checks current primary policy
and then executes the closed immutable `AccountUnlinkCommand`. Verification
does not consume the capability. A trusted issuer issues it only after the
required current credential-specific reauthentication; constructing a proof or
grant projection does not establish that authentication.

The signed profile is non-bearer, has exactly one audience, maximum uses one,
literal `identity.account.unlink` purpose, exact account resource, tenant/user,
and exactly nine caveats: command_id, session_id, session_version, user_version,
account_version, social_link_version, credential_version, policy_version and
revoke_provider. Numeric values use canonical decimal and provider choice uses
literal true/false. Future, expired, over-age, reusable or substituted evidence
denies. Session/actor input comes from authenticated platform composition, not
client JSON. The durable owner must revalidate current session/credential/proof
expiry and atomically reserve/finalize one use with the protected transition
and applicable risk evidence; this core layer does not consume them early.

The repository retains social-link tombstone authority after removal, allowing
same-command replay. New stale commands must conflict under the durable owner's
lock; only exact existing commands can replay before CAS. `RecoverAccountUnlink`
requires current exact subject policy and target, calls only primary recovery,
and never performs another unlink. Malformed/mismatched receipts remain unknown.
Known commits survive cancellation or projection failure with output withheld.
Provider observations are immutable initial pending/not-requested intent, never
current external completion. No provider network work occurs in core admission.
The request here is explicit-ID trusted core composition; keyed HTTP admission
and the complete transport/catalog facade still require their owned adapters.

`ApplyAccountUnlink` computes the proposed next state for the durable owner's
locked transition. `AccountUnlinkState` binds the connection's social-link
version and the user's credential authority version to the complete access
snapshot. `AccountUnlinkChange` supplies exact expected user, account,
social-link and credential versions. Zero/overflow versions are invalid;
stale versions conflict. The transition repeats final-access validation, removes
the exact account and all dependent credential references, preserves independent
methods, increments the user aggregate/social-link/tombstone versions and only
increments credential authority when an authentication link was removed.
Input and output slices never alias. Diagnostics redact the entire state.

This is executable domain policy, not `AccountUnlink` public workflow admission
or a commit. The platform command owner must authorize and validate fresh proofs,
lock and re-read complete primary eligibility, then persist the returned state,
tombstone, exact authority events, audit, cleanup intents and immutable command
receipt atomically with applicable one-use proofs/risk. Same-command replay is
checked before changing state. Serial lock ownership is essential: two removals
cannot each reuse a snapshot where the other's method still exists. Provider
revoke choice and pending/rejected/unknown external outcomes belong to the
enlisted workflow; this function makes no provider call or completion claim.

Why not count API keys? They do not replace a human login/recovery method.
Why separate provider links and credentials? A link may be data-only, and one
removed link can invalidate several credential observations.
Why require complete snapshots? A stale or partial count can orphan access.

These tests prove core reads and pure final-access/transition behavior, not
durable link/unlink concurrency. SQL transaction/recovery, actual fresh
credential/provider ceremonies, atomic risk/proof consumption, token cleanup,
stable pagination and complete Service/catalog/release evidence remain required.
Consumers must not implement these missing platform workflows themselves.
No full identity-platform completion is claimed.

## Identity-owned account link admission

`AccountLinkService.AccountLink` composes the exact upstream authorization and
capability services with primary reads and the existing sole `UnitOfWork`.
The command's semantic action is `identity.account.link-token`; reusing that
registered action does not expose or enable an OAuth HTTP route. Feature
orchestration and transport remain separate, opt-in owners.

Three distinct paths are represented by `AccountLinkMode`:

- **Explicit:** exact current human actor equals the target user, with a fresh
  actor-session-bound capability and separately verified provider subject.
- **Implicit:** disabled unless selected with one exact trusted provider-workload
  actor. A signed pre-auth attempt must bind fresh provider evidence, an exact
  currently verified canonical email and its authority/record/verification
  versions. Local identifier state is primary, not profile/cache data. Email
  matching or workload authentication alone never proves that provider use.
- **Administrative:** disabled unless selected with registered reason tokens.
  The verified human actor is preserved separately from the target user. Current
  authorization and a fresh actor-session/provider proof remain mandatory;
  enabling this path or supplying a reason/role never grants permission.

`AccountLinkChange` binds the candidate account's exact tenant/user, provider,
issuer and subject, expected aggregate/record/social-link/credential versions,
mode, optional credential, reason and applicable identifier evidence. A data-only
link preserves credential authority; attaching even a currently unusable
provider credential advances that dimension. Existing access is copied and
conserved. Provider-subject ownership is keyed by tenant/provider/issuer/subject;
every collision denies, including a same-user duplicate. No mode permits
transferring or merging another owner's account. Administrative recovery is not
a forced collision override.

The exact candidate lookup retains record/tombstone history after unlink. New
records expect version zero; a fresh authorized relink expects the current
tombstone and advances it. Old callbacks/imports cannot reset version history.
Primary observations must match the requested key, retain at most 100 accounts
and 128 credential observations, and use the same user aggregate as any implicit
identifier projection. More than the configured complete-read bound fails;
there is no silent truncation or inferred absent subject owner.

### Proof construction and consumption

`BuildAccountLinkProofPayload` owns the canonical issuance shape from a validated
unsigned `AccountLinkProofSpec`; it does not sign, verify, authorize, read a clock
or mint proof authority. Only trusted feature composition with the configured
signing capability may issue after actual registered-provider, session/consent
or verified-implicit mapping checks. These ceremonies remain unfinished feature
work. Never use client-supplied `AccountLinkProofSpec` as the verification result.

The signed non-bearer capability is single-use and bound to one configured
issuer/audience, tenant, target user and account resource. Its lifetime and age
are bounded to five minutes (the explicit configuration may be shorter), with
exclusive expiry. Exactly eight caveats bind intent digest, command ID, actor
ID/kind, session ID/version, pre-auth ID and policy version. Session/pre-auth
presence is encoded as `absent` or `present:<exact-ID>`; empty capability caveats
are invalid upstream. Explicit/admin paths omit pre-auth and require session;
implicit omits session and requires a canonical pre-auth attempt.

The SHA-256 intent digest uses `identity-account-link-v1` plus a NUL, then
four-byte big-endian byte-length prefixes followed by exact UTF-8 fields:
mode decimal; account ID/tenant/user/provider/issuer/subject/version; reason;
expected user/account/social-link/credential versions; matched identifier ID;
verified canonical identifier; expected identifier authority/record/verification
versions; method presence (`absent`/`present`), credential ID/owner/version, and
`<usable-bool>:<UTC-RFC3339Nano-expiry>`. Absent method's last four fields are
empty. Credential kind, tenant/user and account scope are structurally fixed to
the candidate provider link. Decimal integers have no alternate encoding.
This digest is a signed-intent binding, not authority or a privacy/reuse digest.

Verification is read-only and does not consume. The platform-owned durable
adapter must check same-command replay before CAS, lock tenant-wide subject
uniqueness including absent keys, re-read authoritative state, revalidate exact
proof expiry/provider enablement/policy/session/identifier and credential
eligibility, then consume proof/risk with state, exact events/audit, token-vault
participants and the original receipt atomically. Consumers must not provide
these missing domain stores or transaction glue.

### Outcomes, cancellation and recovery

`AccountLinkResult` separates known commitment from permitted disclosure.
Cancellation, output-policy failure or dependency errors never turn a known
commit into rollback. Lost replies/panics after entering the durable owner remain
unknown; do not allocate a new command ID. `RecoverAccountLink` performs only a
current-policy scoped primary receipt read, binding original actor/tenant/user,
mode, account and action; it never re-executes, consumes proof or calls providers.
Receipts carry local admission, not successful provider I/O or current authority.

Link and unlink admission, including recovery, overwrite
`identity.account.id` with the exact typed account ID before current policy
evaluation. Caller-supplied reserved metadata cannot select another account.
Account-specific denial prevents receipt reads; recovery still checks the
returned receipt's original account binding before disclosure.

All dependencies must be concurrency-safe and honor the configured bounded
context. No service-owned goroutine, transaction or second provider-link store
is created. Input collections/pointers must not be mutated concurrently during
a call; typed command accessors and apply output own their copies. Provider
metadata and intent formatters redact diagnostics; no raw token is returned.
The current test owner is a non-durable seam, not PostgreSQL atomicity evidence.
