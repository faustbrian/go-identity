# Native PostgreSQL magic-link composition

This experimental Go 1.27 module composes the existing identity coordinator,
capability issuer, encrypted delivery, risk and session owners. Public signin-only
and explicitly selected signup request, consume and recovery paths are present.
Selected enrolled-MFA login yields an original continuation rather than a
single-factor session; native TOTP completion is composed separately. This is a
backend library, not a login UI or a release-qualified identity product.

## Public request and consumption

`NewRequestService` selects explicit `RequestConfig`, a primary pool and the
local envelope keyring. `Request` binds original browser possession, callback,
address policy and risk; issuance, delivery intent, audit and lifecycle effects
share the existing coordinator transaction. The caller receives a neutral
acknowledgement, not a bearer or selected account. A configured delivery worker
sends only committed encrypted custody through the consumer's bounded sender.

Select `RequestConfig.Signup` and its matching `Possession` policy to admit
`SignupIfAllowed`. An unused mailbox receives a signed prospective creation;
request/delivery creates no user. Existing verified accounts use the normal
signin path without duplicate creation. Occupied ineligible mailboxes remain
enumeration-safe. Consumption alone creates the user, verified email, empty
factor authority, policy authority and session in the protected transaction.
Install kernel registration/acceptance and magic-link registration extensions,
plus the MFA owner's magic-link signup extension, before enabling this profile.
Reuse the same identifier comparison/retirement key history as other account
creation methods. New prospective resends supersede previous unused links in
the original mailbox/browser/policy family, not by newly allocated account IDs.

`NewConsumeService` composes the public explicit-consumption path. It authenticates
the original proof and durable provenance, cookie/origin/callback and current
account/address/factor/policy/risk authority before atomic session issuance.
Inspection does not consume a link. Recovery is credential-free and cannot
redeliver a token. Required but unsupported MFA denies instead of falling back
to a single-factor session.

## Original primary metadata for MFA

After authenticating the original child and stored continuation, use the
capability owner's `ReadMFAMagicLinkParent` to obtain opaque consumed-parent
custody. `RequestService.ReadMFAMagicLinkPrimary` then reads the original committed
request under current history-access policy, decrypts its existing preparation,
reconstructs every signed payload field and matches the complete canonical
digest. It returns the original recipient and `session.MagicLinkAuthentication`,
not a factor proof, current access authority or session credential.

Supply the original restored browser flow and the stored continuation's original
primary authentication time. These are trusted native inputs, not request
overrides. Before charging a factor denial or completing a session, verify the
submitted cookie and use the session owner's consumed-browser guard. Repeat
current recipient/account/factor/policy checks in the protected completion
transaction; historical metadata alone cannot authorize it. No old risk admission
is restored as new permission and no primary bearer is needed again.

## Codec compatibility and adoption

New signin request outputs retain their full command inside an authenticated
`MLR2` origin codec. AAD binds the exact original command scope, generation and
configuration, without needing unrecoverable initiating fields. The existing
journal remains its only persistence owner; no new intent table is installed.
Legacy signin and prospective retry contexts keep their original meaning.
Changing or removing the codec marker cannot relabel ciphertext successfully.

Origin-only reconstruction deliberately refuses legacy signin records lacking
the retained full command. Ordinary retries can still restore those records
with their original input. Upgrade every request writer before enabling MFA
challenge branching, and fail closed on missing origin custody rather than
inventing metadata or asking for another reusable primary credential.

## Security and ownership

Pools, immutable configuration and opaque inputs are borrowed; earlier context
deadlines win over configured finite budgets. No background goroutine or separate
transaction owner is created. Do not log or implicitly serialize metadata,
proofs, cookies, preparation output or reveal-once results. Foreign actors/scopes,
corrupt history and unavailable authority return zero projections. Consumers
supply configuration and bounded policy/provider callbacks, not replacement
domain stores or workflow implementations.

Native public request/delivery/signin, origin reconstruction, legacy restoration
and denial/rollback/retry behavior have focused integration tests. The origin
test's consumed-parent/child tuple is a labeled fixture; its native atomic
production has separate capability-owner tests. Neither proves completed public
MFA login. Complete MFA/reference/HTTP composition and release gates remain.
