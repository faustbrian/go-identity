# Native passkeys

## Passkey-only deployment

Set `Passkey.Standalone` with an explicit immutable bootstrap tenant set,
bounded risk/audit timeouts and risk policy ID. Select `Passkey.Signup`,
`Session.Passkey` and real `DurableAdmission` for the PostgreSQL-only graph.
No password, OTP, delivery sender, templates, envelope keys or delivery workers
are required or configured. The standard construction sequence is unchanged:
`ComposeStores` -> `ComposeProviders` -> `ComposeWorkers` (no worker arguments)
-> `ComposeFeatures` -> apply selected native migrations -> `Initialize` ->
`NewServer`. Readiness checks the actual selected owners; skipping migrations
does not make a usable server.

For the HTTP signup -> read/logout -> identifier-free signin journey, also
select `HTTPPasskey.Signup`, `Signin`, `Discoverable`, `DiscoverableOnly` and
optionally `Inventory`, plus `HTTPPreAuth`, `HTTPRate` and `HTTPSession`.
`Passkey.KeyedOptions`, signed browser-device configuration, five-minute flows,
matching session/CSRF keys and `PasskeyDiscovery` risk opt-in remain required.
No email parser is needed: identified mode and identifier fields are rejected.
The existing signup and signin wire contracts below remain unchanged.

Select the installed session predecessor `session_issuances_purpose_v2` for a
new passkey-only graph. Existing deployments retain their original predecessor
and migration history; this is not permission to rewrite deployed checksums or
convert a password deployment by deleting its historical configuration. Native
kernel/session, known-empty factor authority, risk, authorization, audit,
outbox, WebAuthn/passkey and HTTP rate schemas are still real prerequisites.
The common kernel registration schema is not a password workflow.

This finite standalone profile requires signup and supports discovery, safe
inventory and session read/logout. Password-proof enrollment, label management,
deletion and mixed password/OTP/delivery selections fail construction rather
than being silently ignored. Passkey-proof management remains a later profile.
Conditional browser presentation is not selected here, and no UI is provided.
The actual public construction/configuration and fresh/populated-kernel-upgrade
journeys are executable in `TestReferencePostgresPasskeyStandalone`.

## Retained existing-account deployment

With `Passkey.Standalone` nil, select `StoreConfiguration.Passkey` only when its password signin, session and
password-verification owners are configured. This profile composes public
`go-passkey/postgres` rather than accepting application domain stores, protocol
verifiers or transaction callbacks. Nil selection exposes no passkey handle.

The selected path is:

1. Register and verify an account, then sign in through the existing baseline.
2. Use the selected cookie password-verification owner to obtain an exact
   `identity.passkey.register-options` proof. Retain original session and CSRF.
3. Call `Passkeys().RegistrationOptions`; transfer its committed options to the
   authenticator. Obtain a distinct `identity.passkey.register-verify` proof.
4. Call `Register` with that proof, original ceremony, raw browser response and
   bounded display label. Protocol credential, kernel reference, stable opaque
   handle, metadata, audit and lifecycle finalize through the real native owner.
5. Retain `PrepareFlow`/`IssueFlow` custody, browser cookie and remember choice.
   Request `AuthenticationOptions`, then call `Signin` with its original
   verified email, ceremony and genuinely signed authenticator response.
6. Use this same selected handle's `Get`, `List` and `SignOut`. Cookie logout
   requires the newly issued synchronizer; a password synchronizer is not a
   substitute. Original recovery returns metadata, never another credential.

Set `Session.Passkey = true` to additionally admit this issuer through
`FeatureSet.Sessions()` and independently selected `HTTPSession` read/logout
routes. This opt-in uses the same native RP/current-authority owner as the
separate passkey handle; it does not try a password reader after denial.
The existing session HTTP origin policy remains authoritative for logout;
the authenticator origin is not an implicit trusted HTTP origin. False retains
native-only reads/logout and does not silently extend common session admission.

For identifier-free signin, explicitly set `risk.PolicyConfig.PasskeyDiscovery`
when constructing the graph's authentication policy (`DurableAdmission.Policy`
in the PostgreSQL-only profile). After the same `PrepareFlow`/`IssueFlow`, call
`DiscoverableAuthenticationOptions` with `native.DiscoverableSigninRequest`,
then `DiscoverableSignin` with `native.DiscoverableSigninCompletion`. Neither
input accepts an email, user, tenant or RP selector. Only the genuinely verified
resident credential and user handle resolve identity. Options and completions
cannot switch between identified and identifier-free modes. The default false
policy denies identifier-free calls without disabling identified signin.
The three-target discovery admission profile currently requires the durable
PostgreSQL risk owner; it is not qualified for the four-target Valkey profile.

## Configuration

### Selected HTTP profile

`StoreConfiguration.HTTPPasskey` independently selects `Registration`, `Signin`,
`Inventory`, `Update`, `Delete` and explicit `Signup`. `Discoverable` additionally opts signin into identifier-free
input; the native authentication risk policy must also permit discovery. Nil
exposes no passkey routes or metadata. This is backend transport, not a UI.

For enrollment/signin select `Passkey.KeyedOptions` and the existing
`HTTPPreAuth` signed device profile. HTTP enrollment requires both native action
primaries to select cookie transport; direct native bearer selection remains
available when HTTP enrollment is off. Both enrollment and signin must retain
the same exact trusted origin as HTTP device initiation. Signin additionally
retains its flow-cookie tuple and canonical five-minute flow lifetime.
The RP must match the effective
HTTPS deployment origin, not a socket address hidden behind a proxy. Select
`Session.Passkey` for signin/inventory; `HTTPSession` separately enables common
read/logout. The graph reuses the configured password-signin email parser,
including its local-part rules and fixed nontransitional domain IDNA.

The finite public journey is:

1. Obtain a fresh action-specific proof through `POST /v1/password/verify`.
   `POST /v1/passkey/register-options` takes closed JSON `proofID`, the session
   cookie, signed device cookie, exact Origin/CSRF and one `Idempotency-Key`.
2. Retain `commandID` as the original ceremony ID and send `options.publicKey`
   to the authenticator. A matching retry returns only original command/outcome
   metadata, with no `options` field.
3. Obtain the distinct register-verify proof. `POST /v1/passkey/register-verify`
   accepts `proofID`, a fresh `commandID`, original `ceremonyID`, raw browser
   `response` and optional `label`. It rejects `Idempotency-Key`.
4. Initiate `POST /v1/session/preauth-issue` with `method:"passkey"` and optional
   boolean `remember` (`false` explicitly selects a browser session). Retain
   the original flow cookie, `flowID` and signed device cookie.
5. `POST /v1/passkey/signin-options` takes one `Idempotency-Key`, that original
   browser custody and `mode:"identified"` plus `identifier`, or the explicitly
   selected `mode:"discoverable"` without any identifier. Its retry semantics
   are the same as enrollment options.
6. `POST /v1/passkey/signin-verify` adds a fresh `commandID`, original
   `ceremonyID` and raw browser `response`; no retry-key/remember/tenant/user/RP
   override is accepted. Only a fresh known commit delivers the owned session
   cookie and `X-CSRF-Token`.
7. `GET /v1/passkey/list` returns bounded safe self metadata. Use the common
   session read/logout routes when separately selected.

Inventory shares an already selected session/MFA/email safe limiter. If none is
selected, configure its explicit inventory rate namespace, emergency bound and
bounded degradation recorder; competing ownership is rejected. Mutation routes
share auth and verification rate identities. All native risk, original expiry,
current authority and atomic-consumption checks remain mandatory. HTTP signup is
a separate explicit profile below; conditional UI, MFA fallback and browser
interoperability are not claimed by the enrollment/signin profile.

### Label management

Select `Passkey.Management = &PasskeyManagementConfiguration{Primary: ...}`
with exact action `identity.passkey.update`, the chosen proof audience and
maximum age, and explicit native cookie or bearer transport. Register that
action/audience in `PasswordVerification.Native.Targets`. Leave primary CSRF
keys absent for graph injection. Management requires `Passkey.KeyedOptions`;
it reuses that same configured kernel request-key owner and dedicated input
correlation keys, not another workflow journal. Native management requires a
genuine password-session proof with known-empty secondary factors; a passkey
session or age flag is not a replacement.

Obtain a safe credential reference and metadata version from `List`. Call
`Passkeys().Update` with that reference, expected version, exact UTF-8 display
name, original signed primary/session/CSRF and one typed idempotency key. Leave
primary command/record IDs empty: the native key owner allocates the sole
original command. Authorization must allow that exact self-user operation,
its request admission and historical disclosure. Only a fresh acknowledged
commit returns safe `Credential`; matching retries return original receipt
metadata without that projection. Retain original input/key after an ambiguous
outcome; never allocate a replacement operation to recover it.

Set `HTTPPasskey.Update` independently for `POST /v1/passkey/update`. Native
management must select cookie transport. Closed JSON contains `proofID`,
`referenceID`, positive `expectedVersion` and `name`; the sole retry key is one
`Idempotency-Key` header. Send the original password-session cookie, its
`X-CSRF-Token` and exact trusted Origin. No device ceremony, browser command,
tenant, user or RP override is accepted. The graph supplies real proof/session
readers and the existing shared HTTP secret-rate backend/namespace/key. Other
passkey operation groups stay independently selected. A rename neither revokes
otherwise valid sessions nor changes protocol keys, counters or authentication
versions; the same passkey can perform a new genuine signin afterward.

### Credential removal

Select `Passkey.Deletion = &PasskeyDeletionConfiguration{Primary: ...}` with
exact action `identity.passkey.delete`, proof audience, maximum age and native
cookie or bearer transport. Register that action/audience in
`PasswordVerification.Native.Targets`; leave primary CSRF keys absent for
graph injection. `Passkey.KeyedOptions` and the graph's actual configured
`PasswordReset` request/completion owner are required. Label management and
HTTP reset routes are not prerequisites. Recovery policy/realm must match the
selected password-session authority; another passkey is not recovery.

Use `Passkeys().Delete` with a safe inventory reference, its metadata version,
fresh signed delete-specific password proof, original session/CSRF and one
typed idempotency key. Leave primary command/record IDs empty. Authorization
must allow the exact self operation, request admission and original disclosure.
The native owner rechecks current account, credential, factor and configured
email/password recovery authority in the protected transaction; it consumes
the proof, erases the protocol key, disables the identity reference and advances
passkey authority with required audit/outbox effects atomically. Affected passkey
sessions deny; the unrelated password session remains usable. Local authenticator
storage is not erased. Reference lifecycle versions are independent of the
inventory metadata version. Results, including original-key retries, contain
durability metadata only, never replacement secrets or a credential projection.

Set `HTTPPasskey.Delete` independently for `POST /v1/passkey/delete`. Native
deletion must select cookie transport. Closed JSON contains `proofID`,
`referenceID` and positive `expectedVersion`; one `Idempotency-Key` header owns
retry custody. Send the original password-session cookie, `X-CSRF-Token` and
exact trusted Origin. The existing shared keyed secret limiter applies before
native deletion; no device ceremony, command/tenant/user override or private
recovery engine is introduced. Disabled selection advertises no deletion route.

`PasskeyConfiguration.Protocol` fixes tenant, RP, origins, challenge key and
bounded duration before any browser input. `RPNamespace` is a deployment scope,
not a caller-selected field. This profile supports resident-required UV/none/
ES256 credentials and known-empty secondary MFA. It does not downgrade a
configured secondary factor to a passkey-only session.

Register both exact enrollment actions and their audience in
`PasswordVerification.Native.Targets`. `OptionsPrimary` and
`RegistrationPrimary` select those distinct actions, audience, maximum proof
age and transport. Leave their CSRF keys absent: cookie composition injects the
actual selected password-verification keys. Freshness is genuine signed action
custody, not a boolean or a session-age assertion.

### Original-key options

Leave `KeyedOptions` nil to preserve the existing keyless native profile.
To select original-key options, call `NewPasskeyKeyedOptionsConfiguration` with
the deployment namespace, a dedicated nonzero random 32-byte lookup key and
dedicated native token-digest/CSRF-digest keys; assign the result to
`Passkey.KeyedOptions`. These input-correlation keys must not be live session
lookup or synchronizer keys. Keep them stable while mappings are retained.
The opaque configuration hides key bytes even in nested diagnostics. The graph
injects its existing current query-policy authorization, clock and revision;
there is no application-provided journal, store or duplicate admission engine.

Use `KeyedRegistrationOptions`, `KeyedAuthenticationOptions` or
`KeyedDiscoverableAuthenticationOptions` with the same original request key and
browser/proof custody on retries. Leave the request command ID empty so the
native request-key owner allocates the original command. Enrollment additionally
leaves `Primary.RecordID` empty. Only a fresh committed winner has options whose
`TransferJSON` can reveal the challenge once. A matching replay retains its
original command/outcome and has no options; it does not renew a proof, flow or
ceremony. Current authorization must explicitly cover options request admission
in addition to native execution and historical disclosure.

`RegistrationRateSource`, `SigninRateSource` and
`DiscoverableSigninRateSource` authenticate original ceremony custody and return
its original rate ID, immutable policy lifetime and precisely one genuine user,
canonical identifier or anonymous-flow rate dimension. A flow is not a user.
These are sensitive metadata reads, not authentication or an unconsumed-validity
lease: retained spent metadata cannot authorize a second mutation or reveal.
The actual native completion independently checks current authority and consumes
its original ceremony/proof/flow atomically. Startup, tenant and shutdown guards
apply to all these entry points.

`Protected` supplies native risk configuration with the graph's existing schema,
the protected command's revision, retained keys, command counter policy and
lockout enforcement. Protected command revision and anonymous authentication
admission are different scopes and need not be the same policy instance.
No supplied counter store is accepted. `Risk.Evaluation` is absent for injection
of the graph's real counted/audited authentication owner.

`Flow` selects the original browser initiation and exact signin action. Its
cookie follows the session owner's `__Host-identity_flow` profile. `Issuer`
and `CSRF` must match the selected session cookie and retained read/logout keys.
Leave clocks absent for injection of that graph's session authority clock.
All keys/callbacks remain borrowed startup input; constructors snapshot their
owned values. Never log or serialize this configuration or authentication data.

## Installed histories and lifetime

Use `ReferenceMigrationPlan` and `ReferenceMigrationApply`, selecting the existing
baseline owners plus `passkey/postgres` and `webauthn/postgres`. The graph appends
actual owner histories, including WebAuthn's native discovery suffix and exact
password action/session issuance allowances. It does not copy DDL or create a
second migration engine. Preserve installed mapping1/signin2 unchanged; this
native version appends metadata3 for inventory even when management is off.
Selected management additionally appends password proof suffix41 after40.
Selected deletion appends proof suffix42 and retains41 even when runtime label
management is disabled. These forward allowances preserve existing signed and
consumed proof records; never rewrite applied checksums to enable removal.
Apply these forward histories before adopting the updated inventory reader;
old binaries may continue authenticating but old inventory readers cannot
project the current label version after a rename.
`MigrationSource()` alone is not the complete selected
independent-owner catalog. Apply before `FeatureSet.Initialize` or serving.

`SessionPredecessor` pins the actual existing session-issuance CHECK, such as
`session_issuances_purpose_v3` for password signin. Retain the deployment's
selected predecessor; incompatible neighboring history changes fail rather
than rewriting an already applied passkey checksum. Populated upgrades preserve
existing accounts, passwords, sessions, proof records and migration prefixes.

Handles can be obtained before initialization, but every operation requires
successful startup and its configured tenant. Earlier cancellation/deadlines
win; `Close` cancels/drains active work and permanently denies retained handles,
including recovery. A separate password/other-method reader is never tried
after a passkey denial.

## Executable consumer proof and limits

From this module, with the authorized task-owned PostgreSQL fixture:

```sh
go test -race -tags=integration -count=1 \
  -run '^TestReferencePostgresPasskey(Native|PopulatedUpgrade|Discoverable|DiscoverablePopulatedUpgrade|CommonSessionHTTP|KeyedOptions)$' .
```

Agent runs additionally set task-owned disposable Go caches. The fixture uses
`IDENTITY_REFERENCE_POSTGRES_PORT`. Actual registration, captured verification
delivery and password signin precede fresh reauthentication and the passkey
journey; none of those domain records or proofs are fabricated. Only HIBP/email
external IO and raw none/ES256 authenticator responses are controlled seams.

Native composition and passkey HTTP transport are separate selections. Existing `Sessions()`
and HTTP session routes do not implicitly adopt the new method. The common
session HTTP tests cover identified and identifier-free signin, fresh install
and populated upgrade, wrong-CSRF/foreign-origin denial, original cookie
deletion and both native/HTTP post-logout rejection over real loopback TLS.
The keyed-options journey additionally covers both modes on fresh and populated
installations, matching metadata-only retries, authenticated original rate
sources and genuine completion into that same usable session/read/logout path.
Native and HTTP management/removal journeys are also executable:

```sh
go test -race -tags=integration -count=1 \
  -run '^TestReferencePostgresPasskey(HTTP)?(Management|Deletion)$' .
```

These exercise actual fresh and populated-upgrade registration/verification,
enrollment/assertion, signed rename/delete proofs and original-key retry. Removal
also proves passkey-session denial and retained password-session read/logout;
native removal runs without label management too. Conditional signin,
completed secondary MFA and organization profiles remain required work. This
profile is not complete M16, full release qualification, deployment or a UI.

## Native passkey-first signup

Set `Passkey.Signup` to a `PasskeySignupConfiguration` on the existing selected
native deployment. Its `Flow` has action `identity.passkey.register-verify`,
the session execution policy ID/revision, original trusted origin/callback,
remember policy, flow-cookie policy and lookup key. Leave `Flow.Clock` and
`Risk.Evaluation` absent. Supply `Risk.ConfigurationID` and retained evidence
keys. The graph binds provider assessment to `Protected.CommandCounters.Policy`,
not the potentially different anonymous-authentication policy revision. Native
reservation remains the sole protected attempt owner; no provider or HTTP
callback can replace it. `Signup=nil` keeps signup unavailable.

Use the public handle in this order:

1. `PrepareSignupFlow(ctx, session.PreAuthPrepareInput)` and `IssueSignupFlow`
   retain the original tenant, browser cookie, remember choice and expiry.
2. `KeyedSignupOptions` with empty command ID and an original request key
   commits one real resident-registration ceremony. Its trusted caller is the
   configured service actor on the original `identity.anonymous-flow` resource.
   `SignupOptions` is the explicit keyless native alternative.
3. Give the actual creation options to the authenticator, retain the ceremony,
   and call `Signup` with genuine response bytes and a distinct original command.
   No account, email/password or stable handle exists before verification.
4. Fresh acknowledged commitment alone delivers the session/CSRF pair. With
   `Session.Passkey`, the same graph's common session read/logout can use it.
   Existing discoverable signin can then authenticate this new account.

Matching options retries and `RecoverSignupOptions` return original metadata
only. `RecoverSignup` additionally retains the original completion command and
ceremony; original-cookie possession and current query authorization remain
mandatory even when historical execution has consumed/expired the flow.
Recovery never retries verification or reconstructs a challenge or session.

Apply the selected owned migration plan before initialization. Signup extends
native mapping history with context4 and passkey session history with purpose2,
plus separate forward kernel-registration, factor-provenance and counter
histories. Existing checksums/rows stay unchanged. Readiness requires the actual
successor constraints; deleting or renaming them fails closed. This selects
native account creation within the existing deployment, not a standalone
password-free deployment configuration. HTTP signup requires the separate
selection below.

`TestReferencePostgresPasskeySignup` exercises fresh and populated upgrades,
genuine signup/read/logout/new discoverable signin, three lifecycle events,
absence of fabricated identifiers/passwords, retries/recovery and missing-schema
readiness. It is a Reference profile, not full M16 or release qualification.

## Explicit HTTP passkey-first signup

Select `HTTPPasskey.Signup` alongside native `Passkey.Signup`,
`Passkey.KeyedOptions`, `Session.Passkey`, shared `HTTPRate` and `HTTPPreAuth`
with its signed browser-device profile. Signup's flow must use the canonical
five-minute lifetime and the exact existing HTTP initiation Origin/cookie tuple.
The current graph still requires its existing native deployment configuration;
the new account itself needs neither email nor password.

1. `POST /v1/session/preauth-issue` with
   `{"method":"passkey-signup","remember":false}`. Retain original `flowID`,
   flow cookie and signed device cookie. Remember is resolved here once.
2. `POST /v1/passkey/register-options` with
   `{"mode":"signup","flowID":"<original-flow>"}`, both cookies, exact Origin
   and one `Idempotency-Key`. A fresh winner alone returns the creation options;
   matching retries return original command metadata without another challenge.
3. Give `options.publicKey` to the authenticator. Post to
   `/v1/passkey/register-verify` with `mode:"signup"`, the original `flowID`,
   original options command as `ceremonyID`, a distinct original `commandID`,
   genuine raw WebAuthn `response` and optional display `label`. Retain both
   browser cookies and Origin; completion forbids `Idempotency-Key`.
4. Fresh acknowledged commitment alone returns `registered:true`, `signedIn:true`,
   command/session metadata, the secure session cookie and `X-CSRF-Token`.
   Use independently selected common session read/logout. The same credential
   can subsequently use the distinct `passkey` pre-auth method and discoverable
   signin; neither step invents an identifier or a password fallback.

Signup rejects ambient session cookies, session CSRF, proof IDs, email/password,
user/tenant/RP and remember overrides. If enrollment is also enabled, its closed
proof-ID/session/synchronizer request stays unchanged and has no `mode` field.
One descriptor/handler pair dispatches the explicit disjoint variants, never a
fallback after denial. OpenAPI describes both request/security alternatives and
conditional synchronizer use. `SignupRateSource` reads only original anonymous
flow/create-ceremony metadata; native completion still revalidates and consumes.
Historical/unknown outcomes disclose no challenge or authentication.

`TestReferencePostgresPasskeyHTTPSignup` covers fresh and populated upgrade
composition with genuine HTTP initiation/registration, schema-checked wire,
metadata-only retry, atomic account/credential/session events, session read/logout
and fresh discoverable signin. These profiles do not close all M16 variants or
whole-unit release qualification.
