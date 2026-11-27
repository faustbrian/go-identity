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

## Production OAuth preview Start and callback

Install `ProxyTransactionMigrationSource` after the base OAuth schema. Select
the identity coordinator's directory, preparation, external-admission and proxy
preparation-erasure histories, and the capability, audit and lifecycle owners.
Configure `NewProxyForwardService` with a production deployment, primary pool,
service actor, policy/authority IDs and retained state and wrapping keys. Pass
the returned service to `oauthproxy.NewProductionCommandCallback` for the same
deployment and exact configured provider and preview targets.

The original transaction must already be durably recorded. Generation can open
its PKCE verifier only after the coordinator acknowledges exclusive reservation
and the generation marker. A provider denial never opens the verifier. The
callback atomically finalizes the original proof, records the known disposition,
erases temporary proof and PKCE custody, and commits `identity.oauth.use_proxy`
with the lifecycle effect. No production user, account or session is created or
updated. A replay cannot disclose a previously committed result. An unknown
outcome returns a redacted reconciliation error and never repeats an uncertain
provider exchange. An exposed callback still needs counted provider-callback
admission at its transport boundary. Selecting the callback alone does not
enable initiation, HTTP or preview session issuance.

`ProxyCallbackRateSource` authenticates the original provider, transaction and
lifetime for that transport's rate budget. Pass the trusted network tenant, not
a tenant from callback parameters. This read does not reserve the original,
release proof or PKCE, or replace the callback's own admission checks.

To enable native initiation, also install the coordinator's
`OAuthProxyStartPreparationErasureMigrationSource` after its forward counterpart.
Construct `NewProxyStartService` with that same forward service and exact OIDC
provider, claims profile, active state key, and production-scoped capability
preparation codec. Select one trusted preview tenant, actor, HTTPS origin and
redirect, recipient, and bearer authenticator. The principal must match the
configured issuer and actor, with the sole configured audience and sole
`identity.oauth.proxy-start` scope.

Call `Start` with the original preview command and transaction, request
fingerprint, and resolved Remember policy. Only the invocation that both
generates the authorization and receives commit acknowledgement can return
`Authorization()` and `Binding()`. Retain that binding in the intended preview
before redirecting the browser. No verifier or grant proof is returned. Exact
committed retries do not reveal another authorization. An unavailable result
does not establish whether the original committed; do not restart with a new
command or transaction to recover its result. This API neither mounts an HTTP
route nor consumes the handoff in a preview session.

Preview databases may separately install `ProxyPreviewBindingMigrationSource`
after their base OAuth history. It only creates an empty expected-binding table
and indexes; it does not select a writer, consumer or route. The preview's
session and capability owners still decide whether a handoff can be used.

Select `NewProxyPreviewService` in the preview with its existing native signin
and session owners. Issue an ordinary `identity.oauth.callback` pre-auth flow
for the exact preview origin, completion URL and resolved Remember policy.
Use that flow in authenticated production Start. Before redirecting the browser,
pass the acknowledged original binding and original cookie to preview `Bind`.
An exact Bind retry does not reissue the original grant.

Pass the returned encrypted handoff and original browser cookie to preview
`Complete`. It never calls the provider. The one-use grant, browser, current
linked account, known-empty MFA, policy, opaque session, audit, lifecycle and
proof erasure use the existing coordinator. Only a fresh acknowledged commit
can return a bearer and a synchronizer token; that delivery retains the earliest
original cutoff. This profile is existing-account signin only and does not
mount HTTP routes, perform implicit signup or add account linking.

## Google One Tap browser start

Install `OneTapCallbackGrantMigrationSource` after `MigrationSource`, using
the same native OAuth schema and a new unused migration version. It adds a
table for encrypted callback proof bound to the tenant, original browser
flow and exact One Tap start command without changing existing RP rows.
Install the kernel request-key, preparation/admission and One Tap erasure
histories, the session One Tap pre-auth histories, and the capability, audit
and outbox contributors before selecting `NewOneTapStartService`. There is no
backfill or down SQL; disabling the service leaves schema and history intact.

Select a trusted tenant, HTTPS origin, service actor, Google callback-mode
provider and the audited, counted risk policy. The application supplies
`onetap.NewBrowserStartRequest` with trusted transport origin, network and
device, resolved Remember policy, browser options and the original retry key.
`Start` performs no Google network call. It commits the original pre-auth
flow, one-use callback grant, sealed proof, audit and lifecycle together.

Only a newly committed start from that invocation returns `Browser()`. Use its
reveal-once token for the supplied blank `__Host-identity_flow` cookie and
explicitly project the permitted browser fields without logging them. Retry
unknown results only with the same original key and unchanged input. A
committed retry returns the original outcome, not another nonce or cookie.
This API does not install HTTP or authenticate a One Tap callback.

### Explicit Google button redirect start

Select `NewOneTapRedirectStartService` with the same trusted start configuration,
the exact registered canonical same-origin HTTPS `Issuance.CallbackURL` and a
zero `Issuance.Cookie`. The endpoint must have a non-root literal path. Supply
the distinct `onetap.NewBrowserRedirectStartRequest` to `StartRedirect`; this
service rejects callback `Start`, and the callback start service rejects
`StartRedirect`. The popup `NewOneTapCompletionService` does not accept a redirect
service; redirect completion is separately selected below.

Redirect start uses the existing request-key, counted admission, atomic session,
capability, audit and lifecycle owners without a new table or replay mechanism.
Its profile binds the exact mode and endpoint in a separate digest domain;
changing the endpoint cannot reuse an original keyed request. Existing popup
fingerprints and prepared callback plaintext remain unchanged.

Only its own fresh committed start returns `RedirectBrowser()`, never `Browser()`.
Use the reveal-once opaque token for the supplied blank, host-only, Secure,
HttpOnly, SameSite=None `__Secure-identity_frontchannel` cookie scoped to the
configured callback path. `Projection` is the validator-owned typed GIS launch:
original client, login URI, base64url nonce, canonical flow-ID button state,
allowed parent origin and unchanged issuance/expiry. It is not a complete GIS
object or a renderer. Button state is a locator, not the opaque cookie or
Google's separate `g_csrf_token` proof. Do not invoke One Tap prompt for this
redirect-button profile or log browser output.

The trusted stable device from the admitted request is retained only inside the
encrypted callback grant for future original-cookie-bound completion. It is
not disclosed in browser output or accepted as a redirect callback hint.
Replay and explicit recovery return historical metadata without browser custody;
unknown, failed or expired delivery releases no cookie token or launch. No Google
endpoint is contacted. Start does not enable callback completion, HTTP decoding,
cookie response handling or live browser interoperability.

## Google One Tap callback and session

Select `NewOneTapCompletionService` with the same configured start owner, the
retained versioned flow-cookie keys, the native session issuer and its separate
CSRF key. Install the One Tap callback session history and its existing
directory, account, authorization and MFA authority dependencies before enabling
completion. Keep the optional hosted-domain restriction tied to the selected
policy version. HTTP routing, request-origin resolution and cookie delivery
remain application responsibilities.

Submit the original flow ID and cookie plus Google's credential and matching
double-submit `g_csrf_token` with the trusted transport context. The callback
resolves an existing linked Google account by verified issuer and subject,
never by email. It requires known-empty MFA authority; it cannot sign up, link
an account or fall back to a single factor when MFA is enrolled or unknown.

On a new commit the native callback consumes the original browser flow and
one-use grant, erases its sealed proof and creates one cookie session. Reveal
the original bearer and CSRF token only for the admitted response and before
the returned `DeliveryValidUntil`; do not derive another deadline. A repeated
browser request cannot disclose either token again. For unknown outcomes use
the returned command ID with authorized `RecoverCallback` in the exact original
flow scope. Recovery returns historical receipt metadata, not authentication.

### Explicit Google redirect completion

Select `NewOneTapRedirectCompletionService` with the original redirect start
service and the same completion configuration, including any trusted exact
`HostedDomain` restriction. Submit `OneTapRedirectCallbackRequest` to
`RedirectCallback`; `Callback` remains popup-only, and the redirect constructor
rejects a popup start service. No HTTP route or provider endpoint is installed.

The request carries the original flow ID and opaque frontchannel cookie, Google's
credential/double-submit values, the exact trusted initiating origin and registered
redirect endpoint, and the trusted current peer address. It has no device field.
Origin, endpoint, mode, bounded credential/CSRF shape and independent original
cookie possession are checked before the original grant's sealed stable device
is available to counted native risk. A popup grant must have no retained device;
a redirect grant must retain the exact bounded device from its admitted start.
The redirect intent has a separate HMAC domain and binds the exact endpoint;
popup intent, session effects and cookie bytes remain unchanged.

Signed credential, signed hosted-domain restriction, existing linked account,
current authorization and known-empty MFA admission still use the existing
owners. Session issuance, original browser/grant consumption and proof erasure
remain one atomic commit. Fresh commitment alone delivers session bearer/CSRF;
replay and `RecoverCallback` expose no credentials or refreshed deadline. This
does not add signup/linking, a browser-selected device, a new replay store, HTTP
decoding or live Google/browser interoperability proof.

## Existing-account signin

The original OIDC profile uses query callbacks, S256 PKCE and nonce binding.
An explicitly supplied `oauth.OAuth2UserInfoFacts` provider selects the separate
OAuth2/UserInfo variant: full additional facts are authenticated in existing
encrypted configuration/state, with a distinct registered actual callback URI.
Use `oauth.ParseOAuth2QueryCallback` at that trusted route; do not route it through
the strict OIDC parser or assume HTTP/Reference automatically selects it.
UserInfo observation expiry and original access-token expiry are retained,
never renewed during restore/replay. No provider nonce or ID-token claims are
invented. Existing OIDC JSON and verifier AAD bytes remain unchanged.
Explicit GitHub OAuth-app selection also authenticates its closed token/resource
policy in the same snapshots and callback admission. Before enabling it, apply
both forward phases from `TokenVaultOptionalExpiryMigrationSource` after the
installed vault history, using two unused consecutive versions in its existing
namespace. This preserves old migration bytes/positive rows and adds paired SQL
NULL expiry for ordinary GitHub tokens. Existing OIDC/GitLab writers still require
positive expiry; restore/replay never turns zero into a TTL or fresh evidence.
See the providers module's GitHub profile for rollout and rollback constraints.
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

## Explicit account unlink

Select `NewUnlinkService` with the existing `LinkService` and a real
`password/postgres.AccountUnlinkPrimarySource` on the same native primary
pool. Install the kernel's account-unlink preparation and validation histories
and the password owner's `AccountUnlinkReauthenticationMigrationSource` before
enabling this profile. Its partial index is built in a bounded transaction;
if that step times out, the earlier expansion remains recorded.

Issue a fresh password proof for `identity.account.unlink`. Use the exact
linked account versions and known-empty MFA generation, original session and
cookie synchronizer (for cookie transport), and a new command ID. Retain those
values for an exact retry. The command consumes the password proof, removes
local encrypted provider tokens and invalidates dependent credentials together,
while requiring working independent password access. For an uncertain result,
call `Recover` with the original command, account, tenant and user under current
authorization. Neither operation requests remote provider revocation.

## Stored provider grant refresh

Construct `NewProviderRefreshService` from an existing `LinkService` and the
IDs of the confidential OAuth2/UserInfo providers that may refresh using POST
client authentication. This does not enable HTTP, OIDC refresh, or session
rotation. Apply the protected-counter and
`postgres.OAuthProviderRefreshErasureMigrationSource` histories, both
`TokenVaultOptionalExpiryMigrationSource` phases, and the
`ProviderRefreshReceiptMigrationSource` in the OAuth schema before opting in.

Call `Refresh` from trusted transport with the account ID, expected stored
grant version, current owning password session, cookie CSRF token, origin,
network, and `identity.account.refresh-token` authorization context. The
service selects the configured provider and derives the original command key
from the account and grant version; neither can be overridden by the request.

The result contains command and vault versions, access expiry on success, or
`Rejected` when the provider definitively refused the original grant. Refusal
retires local custody; it does not claim remote revocation. For an uncertain
result, retry the same account and original grant version. Retained history
never grants a second provider attempt or renews the original session and
deadline; a current owning session may read an already committed receipt.
Neither successful nor uncertain results expose access or refresh tokens.

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
