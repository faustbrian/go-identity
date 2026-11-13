# OAuth PostgreSQL

Native RP transaction storage and recoverable PKCE custody, under development.
`NewSigninService` and `NewSigninCompletionService` compose existing-account
OIDC signin; `NewLinkService` composes explicit-self password-session linking.
Both use native authority owners and the existing kernel coordinator, not
application-written domain stores. Publication and complete OAuth qualification
remain unfinished.

Configured providers may explicitly select `oauth.ClientSecretPost` as well as
the existing public or Basic profiles. Original native state binds that choice;
credentials are sent only in the HTTPS token form. This does not add a built-in
provider catalog, automatic credential-channel fallback or Apple hybrid flow.

An explicitly configured `oauth.NewGoogleAccountsProvider` accepts Google's two
documented signed ID-token issuer forms only after full upstream verification.
Native linking and existing-account signin use its canonical
`https://accounts.google.com` issuer and exact subject, so the forms cannot create
separate account namespaces. Raw callback query issuers remain canonical.
`ProviderProfile.GoogleAccounts` is frozen into the existing configuration
fingerprint, encrypted transaction snapshot and canonical state binding. A
same-version policy switch cannot reinterpret an in-flight callback or replay;
retain its original configuration or let the original flow expire. The false
selection preserves released strict profile/fingerprint bytes and the existing
RP verifier AAD schema. No new authority, journal, signup or email merge is added.
Controlled signed-token/native PostgreSQL consumers do not claim live Google
interoperability or complete provider-catalog qualification.

## Existing-account signin

This selected profile uses query callbacks, S256 PKCE and nonce-bound OIDC.
The provider's verified issuer and subject must resolve to an already linked
account with its current provider credential. `SignupDisabled` must be true.
There is no implicit signup, email matching, MFA challenge, organization-session
selection, refresh or unlink workflow; enrolled or unknown MFA denies rather
than falling back to single-factor authentication.

Issue the original browser transaction through `session.NewPreAuthIssuer` and
the native `session/postgres.NewPreAuthIssueExecutor`. Its purpose is
`session.PreAuthSessionIssuance`, its action is `identity.oauth.callback`, and
its callback URL is the exact allowlisted application success callback. Bind
the tenant, origin, policy and already resolved `RememberPolicy` there; leave
identifier binding empty. `SigninStartRequest` must carry that exact flow ID,
cookie and Remember policy, not a newly resolved default or a password session.
Its caller is the configured service account acting on that anonymous flow,
not a user chosen before provider verification.

Start and callback require trusted transport `Origin`, `Network` and `Device`.
Device is a bounded browser identity, distinct from the random flow ID and
never a provider claim or request-body override. Callback must retain the
original Device; its Network is trusted attribution for that invocation, not
a provider-selected value. Exact start retries preserve the original network,
device, state, nonce, PKCE and expiry; changed intent conflicts. Current directory
epochs are still checked before delivering a replayed authorization redirect.

Select `risk.PolicyConfig.OAuthProviderDiscovery` explicitly in trusted startup
configuration. Supply the counted, fail-closed audited Authentication evaluator
through `SigninServiceConfig.Risk`; the opt-in omits only the unavailable
identifier dimension for signin-start/callback. Tenant, network and trusted
device counters remain mandatory. `SigninCallbackRateSource` authenticates
original browser/state attribution for an outer provider budget; it does not
reserve state, authorize exchange or replace callback admission.

Install the kernel request-key, preparation/admission, capability, audit,
lifecycle, original-preauth and RP histories before selecting the services.
For an installed session schema, apply both steps from
`session/postgres.OAuthSigninMigrationSource` with permanently allocated
`Version` and later `ValidationVersion`, and the exact installed validated
`PreviousConstraint`. It expands the existing issuance-purpose predicate with
`identity.oauth.callback`, preserving populated rows and original migration
bytes. Expansion uses a bounded exclusive metadata lock without a validation
scan; validation runs separately. Install both steps and retire readers that
cannot admit provider sessions before enabling issuance. Rollback disables
the profile; it does not remove forward history or retained evidence.

`NewSigninCompletionService` takes the native starter and a
`SigninCompletionConfig` with the actual session audience, policy namespace,
issuer and CSRF configuration. `Issuer.Authority` must be nil: provider,
state and browser authentication belong to the native callback owner. It
reserves canonical one-use state before releasing PKCE or exchanging the code,
then retains encrypted, tokenless account/session preparation. Session and
family issuance, original browser consumption, state consumption, exchange-secret
erasure, audit and lifecycle effects share the existing coordinator transaction.
Provider tokens are destroyed rather than persisted as signin credentials.

Only the original newly committed invocation can deliver its session bearer
and CSRF token. A committed callback retry returns the original tokenless
identity/session metadata while the original browser/RP window and current
authority checks permit it; it never discloses another bearer or re-exchanges
the code. A lost or otherwise unknown exchange remains pending: neither retry
nor expiry proves that it failed, and the code is not exchanged again.
Issuer-bound provider denial consumes the original state and erases exchange
ciphertext without exchanging, issuing a session or changing an account; exact
retry returns the original allowlisted error callback.

`SigninCompletionService.RecoverCallback(ctx, query, caller)` observes or
reconciles the original signin command through the existing coordinator.
Use its original command ID, tenant, anonymous flow and service-account actor,
with operation `identity.oauth.callback`; `UserID` and `RecordID` must be empty
and `LinkMode` zero. The caller must match that scope and be authorized by the
configured current `QueryPolicy`. This entry point accepts the signin-completion
profile, not the distinct provider-denial profile. Its `session.IssueResult`
contains only command ID, commit outcome, replay status and retry delay; even
a committed result contains no session, bearer or CSRF token and grants no
current authentication authority. Recovery does not require browser proof or
exchange a code. Live or uncertain exchange remains pending; expired custody
can be reconciled only from the original participants' retained evidence.

Read issued sessions through `session/postgres.NewSessionService` with an
`IdentifierAdmissionConfig` selecting `AuthenticationMethod: "oauth"`,
`CredentialKind: identity.CredentialProvider` and
`CredentialOwner: "identity/oauth"`, plus the same global authority, policy
namespace and audience. The existing primary reader checks the linked provider
credential and exact known-empty factor generation as well as ordinary current
authority; it does not discard the factor dimension. Cookie logout uses the
existing `NewCookieRevokeOneExecutor` with that same profile in its execution
and `SingleFactorSessionAdmissionConfig.Verified` selection, the native reader,
and core cookie sign-out/CSRF services. Revocation remains strictly same-user;
wrong CSRF must not revoke the session.

The direct consumer in
[`reference/social_signin_start_integration_test.go`](../../reference/social_signin_start_integration_test.go)
shows original-preauth issuance, risk configuration, forward migration,
completion, primary read and cookie logout using native owners. It supplies
configuration, not replacement domain stores. This is not automatic selection
by `reference.SocialOAuth`, an HTTP route, or a whole-unit qualification claim.

Construction snapshots configuration but borrows the primary pool, providers,
policy services and clocks; keep them alive and concurrency-safe until calls
finish. The caller owns pool shutdown, provider transport lifetime and bounded
outer contexts. Calls derive their configured timeouts, honor cancellation and
start no worker or background resource. Cancellation after an external attempt
does not establish noncommit. Retain original configuration and state, replay,
PKCE, admission and envelope keys while dependent custody remains recoverable.
Do not log authorization URLs, cookies, parsed callbacks, tokens or secrets;
destroy parsed callback custody after the bounded call on every outcome.

## Explicit account linking

`LinkStart` requires the original fresh password session and synchronizer,
keyed request custody, configured provider/scopes and exact application callback
allowlists. It checks primary directory, credential, policy and known-empty MFA
authority before issuing recoverable state/nonce/S256 custody. Unknown or
enrolled factor state denies rather than selecting a weaker profile.

`Callback` derives its actor from authenticated state and the original browser.
The root journal reserves one-use state before verifier release and exchange;
retained encrypted output resumes without repeating the exchange. Account and
credential changes, encrypted provider tokens and exchange-secret erasure share
the root transaction. Exact committed retry does not require a newly valid
session epoch and never creates a new session. `CallbackRateSource` supplies
only original rate attribution, not exchange or account authority.

Successful linking atomically records `identity.oauth.handle_callback`,
`identity.oauth.link_account` and `identity.account.link` with standard retention
and one correlated causation chain. Known terminal refusals record the same
applicable actions without claiming a mutation. Protected-counter denial erases
the original exchange secrets before exchange; proven rollback can erase them
after final proof expiry without making that proof usable again. Failed cleanup
rolls back terminalization rather than claiming a known refusal.

Backend maintenance can call `EraseExpiredUnused(ctx, maximum, cursor)` to erase
abandoned, expired explicit-link PKCE/state-proof ciphertext even when the browser
never returns. Start with an empty cursor, examine at most 1–100 rows per call,
and continue with its returned cursor until empty. Repeat the sweep later from
the beginning to revisit locked rows. The caller owns scheduling and a bounded
outer context; this service starts no background worker or HTTP route.

Each batch authenticates retained RP metadata and locks its rows before erasure.
Any existing callback command claim excludes that transaction, including pending
or uncertain exchanges; expiry is never evidence that a code was not exchanged.
Claimed rows advance pagination so they do not starve later abandoned rows.
The canonical journal/capability owners remain unchanged. A batch error returns
no count or next cursor; retry from the prior cursor after an unknown commit
acknowledgement. Keep the configured provider and retained keys available until
their custody is drained. This is a maintenance entry point for a trusted backend,
not an end-user operation or a substitute for external-effect reconciliation.

For a known attached callback abandoned beyond the original RP window, use
`RecoverExpiredAttached(ctx, tenant, maximum, cursor)`. It authenticates retained
metadata and enters the existing coordinator's unanimous-negative recovery. No
browser credential, current state proof, grant restoration or second exchange
is needed. Ordinary expired callbacks still deny. Unattached/uncertain exchanges
remain pending; expiry alone never proves noncommit.

This tenant-scoped sweep examines at most 1–100 rows and rejects a cursor from
another tenant. It closes each candidate through its own canonical transaction,
without holding an RP lock ahead of the coordinator's claim-first lock order.
Counts describe acknowledged noncommit observations, not exactly-once erasures;
concurrent sweepers can observe the same outcome. On error, prior counts and
the last completed cursor remain valid. Keep scheduling and pool lifetime with
the trusted backend caller; this operation exposes no HTTP route.

An issuer-bound provider-error response uses the original state and browser too.
It does not synthesize a code or decrypt PKCE. The existing coordinator consumes
the original grant, erases exchange ciphertext and records a denied outcome
with the RP lifecycle transition, then returns the original allowlisted error
callback. Exact retry returns that outcome; replacing the error with a code
cannot exchange or link. Provider text is never surfaced, and cancellation
does not create an identity/session or change the existing password access path.

If denial-secret erasure fails, the transaction retains its pending receipt and
reserved state rather than acknowledging cancellation with secrets left behind.
Retry can finish the original cancellation while its RP window remains valid.
After expiry, `RecoverExpiredAttached` can settle that original claim through
the registered native owner, atomically erasing custody, releasing state and
recording failure; it cannot produce a successful cancellation redirect.

A definitive token-endpoint refusal is authenticated and retained in the same
preparation journal. Retry and historical recovery settle it without another
exchange or a final link grant. A lost response or failure before durable
retention remains uncertain; expiry does not turn that uncertainty into refusal.

Final successful linking uses `PrepareLink` and the neutral `LinkUnitOfWork`:
the ready handoff carries immutable `LinkCommand`/`LinkParticipants`, not an open
transaction. `WithinLink` binds a private authoritative writer, applies the
identity transition and commits every required participant through the existing
coordinator. A provisional `LinkApplication` is not a durable receipt. Handoff
copies share one-use execution and preserve the original earlier deadline.

Install the native kernel account/preparation/erasure and RP/token-vault histories
before selecting the service. The reference backend owns that composition when
`SocialOAuth` is selected; `HTTPSocialOAuth` independently selects routes. Stable
intent custody is separate from retained state, PKCE and envelope rotation keys.
The linking profile does not select signin, refresh or unlinking; native
existing-account signin requires the separate composition described above.

This service also selects the risk owner's `RetainCounterKeyVersions` profile.
Install `risk/postgres.CounterKeyVersionMigrationSource` after protected-counter
history before enabling it. Original charge aliases are retained atomically and
read back through that owner before reconstructing a retry. Retained-key additions
do not replace the original redirect, command, protected network or expiry;
missing original keys or unknown historical metadata deny. New charges continue
to require the full current key set. Request admission time is not new logical
intent, but the original primary time still bounds every authorization and effect.

## Storage ownership

`MigrationSource{Schema: "identity_oauth", Version: allocatedVersion}` supplies
one forward migration for the existing migrations runner after the identity
kernel. It preserves populated identity rows and installs no endpoint. Use a
dedicated unoccupied schema and permanently allocate the version in the owning
composition's history. No destructive down migration is provided.

RP rows distinguish authenticated-user linking from actual anonymous pre-auth
flows. State lookup uses keyed digests. PKCE, canonical state proofs and private
bindings are encrypted; SQL constraints do not authenticate their contents.
The canonical capability participant and kernel journal retain all replay,
reservation, execution and recovery authority. This is not another journal.

Private PKCE custody uses the existing secret-envelope AEAD and core OAuth
verifier, exact RP AAD, separately keyed commitments and original deadlines.
The selected native AAD values are limited to 1024 bytes, matching the upstream
envelope context bound; longer values fail rather than being truncated.
Opening custody alone cannot authorize exchange. Actual callback orchestration
must reserve canonical state and admit the original browser/session first.

No flow, account, session, token-vault, HTTP or whole-unit qualification claim
follows from these storage and cryptographic checks.

## Tests

Run `go test ./...` for custody behavior. The integration-tagged storage tests
require an explicitly provisioned disposable loopback PostgreSQL database named
`identity_test` through `IDENTITY_POSTGRES_TEST_DSN`. They create and remove a
unique child database; never point them at an existing application database.
