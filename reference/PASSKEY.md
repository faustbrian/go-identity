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
than being silently ignored. Session-assertion label management is separately
selected below; the password-proof management restriction is unchanged.
Conditional browser presentation is separately selected below; no UI is provided.
The actual public construction/configuration and fresh/populated-kernel-upgrade
journeys are executable in `TestReferencePostgresPasskeyStandalone`.

### Browser interoperability journey

`TestBrowserReferencePasskeySignupManagementRecovery` selects the same public
PostgreSQL graph with an isolated Chromium browser. Browser `fetch` owns the
actual HTTPS Origin, secure/HttpOnly cookies and original CSRF continuation;
`navigator.credentials` and native JSON conversion produce the registration
and assertion responses. No Go signer, injected credential/private key,
request interceptor or application-owned domain store supplies the journey.

The selected resident-UV/ES256 profile covers signup, second-key enrollment,
rename, removal, invalidated-session rejection, surviving-key discovery signin,
original removal recovery, last-key protection and session read/logout. It runs
internal and USB CTAP2.1 virtual-authenticator profiles against fresh and
populated-upgrade PostgreSQL. The recovery device uses USB because Chromium
allows only one internal virtual authenticator in an environment.

From `reference/`, run against an explicitly disposable local PostgreSQL cluster
with `IDENTITY_REFERENCE_POSTGRES_PORT` set and the task-owned Go caches described
in the repository contributing guide:

```sh
export WEBAUTHN_BROWSER_BINARY='/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
go test -race -tags=integration,browser \
  -run '^TestBrowserReferencePasskeySignupManagementRecovery$' -count=1 .
```

The fixture generates its own short-lived TLS certificate, trusts only that
certificate's SPKI in the isolated browser, maps `identity.example` to loopback,
and removes its browser profile/processes. It does not change system trust or
use a personal browser profile. Runtime versions are recorded in test output.
Virtual-device results are not physical platform/roaming hardware certification,
conditional-autofill interaction proof, Ed25519 or enrolled-MFA qualification.
Those remaining profiles and complete module release gates remain separate.

## Current-passkey-session rename

Set `Passkey.SessionManagement` to
`&reference.PasskeySessionManagementConfiguration{Transport: session.CredentialCookie}`
or explicitly select bearer transport. `Passkey.KeyedOptions` is required. The
graph supplies its actual protocol, current session/directory/factor/passkey
authority, authorization, protected risk, coordinator and retained cookie-CSRF
keys. Do not supply a password proof, domain store, replay journal or transaction
callback. This additive selection works with `Passkey.Standalone` and the
retained deployment; `Passkey.Management` keeps its separate password-proof API.
The existing mapping1/signin2/metadata3 histories remain unchanged.

After migration apply and `Initialize`, obtain `Passkeys()`, then its
`SessionManagement()` handle. The nested handle preserves the native contract:

1. Use `Passkeys().List` to obtain the safe target reference and current positive
   metadata version under the actual current passkey session.
2. Call `UpdateOptions` with `passkey.SessionUpdateOptionsRequest`, preserving
   original session/cookie-CSRF custody, self-user `identity.passkey.update`
   context, intended reference/version/label, trusted origin/network and one
   original key. Transfer the genuine options once to the authenticator.
3. Call `Update` with `passkey.SessionUpdateCompletion`, the unchanged original
   request, returned ceremony ID, genuine UV assertion and a **distinct completion
   key**. Both requests occupy the protected update namespace, so one key cannot
   represent both bodies. The native owner consumes the assertion and performs
   the label CAS, current-authority/risk checks and required audit/lifecycle in
   the sole existing transaction. No session or reusable proof is issued.
4. Read the updated inventory and continue session read/logout or fresh signin.
   Matching retries return the original receipt only; retain the same key/body
   for uncertain-outcome reconciliation rather than requesting new authority.

The guarded handle denies before initialization and after graph `Close`,
including historical recovery. Cookie transport requires the actual original
synchronizer, not another session's token. Session, target/version/name, RP,
origin and network substitution deny. Native selection advertises no new HTTP
route or metadata; `HTTPPasskey.Update` remains the existing password-proof
endpoint. Explicit `HTTPPasskey.SessionUpdate` selects the alternative
password-free cookie profile below. Browser UI, passkey-only deletion/recovery and additional enrollment
are separate profiles. `TestReferencePostgresPasskeySessionManagement` proves
the public graph from real HTTP signup through native rename and HTTP
read/logout/fresh signin on fresh and populated-upgrade PostgreSQL without
password, OTP or delivery configuration.

### Opt-in HTTP session rename

Set `HTTPPasskey.SessionUpdate=true` alongside the native cookie-mode
`Passkey.SessionManagement`, `Passkey.KeyedOptions` and `Session.Passkey`.
The graph uses its actual session reader, CSRF keys, guarded management handle
and shared `rate.secret` limiter. Selecting both `HTTPPasskey.Update` and
`SessionUpdate`, a bearer native owner, or missing native/CSRF ownership fails
construction. No browser-device cookie or password verifier is required.

POST `/v1/passkey/update` with the current session cookie, exact Origin,
stored `X-CSRF-Token` and one original `Idempotency-Key` header. The options
body is `{"phase":"options","referenceID":"<inventory reference>","expectedVersion":1,"name":"Personal key"}`.
Deserialize `options.publicKey` and obtain a genuine UV assertion. Complete
at the same endpoint with the same reference/version/name, `phase:"complete"`,
`ceremonyID` equal to the options response's `commandID`, and WebAuthn
`response`. Use a **distinct** original completion header key. Both phases
retain the same protected update action; body proofID/command/tenant/RP and
credential overrides are forbidden. Changing the bound session, Origin or
trusted client network is not a supported continuation.

Only fresh options disclose the challenge; only fresh committed completion
returns safe updated metadata. Replays disclose original command metadata
without renewing authority or issuing authentication. Retain original inputs
and keys to recover unknown outcomes. The selected OpenAPI describes these
closed variants. `TestReferencePostgresPasskeyHTTPSessionManagement` traverses
real HTTPS signup, action-bound UV rename, inventory/read/logout and fresh
signin on fresh/populated PostgreSQL; it does not certify browser interoperability.

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

### Conditional presentation

The guarded `Passkeys()` facade exposes `ConditionalAuthenticationOptions` and
`KeyedConditionalAuthenticationOptions` over the same native discoverable owner.
Enable its existing `PasskeyDiscovery` policy. No additional ceremony mode,
schema, authority, lifetime or request-key namespace is introduced. Ordinary
and conditional native presentations of an original key share one command;
retries/recovery never reconstruct the challenge or authentication.

Set `HTTPPasskey.Conditional = true` together with `Discoverable` and `Signin`
for the opt-in HTTP projection. It also works with `Passkey.Standalone` and
`DiscoverableOnly` without password/OTP/delivery configuration. Continue to send
`mode:"discoverable"` to the same signin pair. Fresh options add
`options.mediation:"conditional"` beside `options.publicKey`; completion still
verifies the ordinary discoverable assertion. Identified options are unchanged
when selected, and disabling conditional selection retains the prior wire.

Use the original flow/device cookies, Origin and remember choice, plus the
original header-only options key. Replays expose command metadata, not another
challenge or session. Applications must check browser support and deserialize
`publicKey` before `navigator.credentials.get()`. The server cannot prove the
browser's actual mediation and does not implement UI. Native expiry, UV,
current authority, shared risk, CSRF and cookie/logout semantics are unchanged.
`TestReferencePostgresPasskeyConditional` exercises fresh/populated PostgreSQL
with both browser and persistent sessions through the actual HTTPS graph.

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
native removal runs without label management too. Passkey-session management,
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

## Current-session additional enrollment

Select `Passkey.SessionEnrollment` with
`PasskeySessionEnrollmentConfiguration{Transport: session.CredentialCookie}`
or the explicitly selected bearer transport. `Passkey.KeyedOptions` is required;
the graph supplies actual owners and retained cookie CSRF keys. This works with
`Passkey.Standalone` without password, OTP or delivery configuration. Apply the
selected native histories, including WebAuthn migration 5, before initialization.
No new coordinator, application proof, migration SQL or domain store is supplied.

Obtain `FeatureSet.Passkeys()` then `SessionEnrollment()`. The guarded handle
keeps fixed tenant, initialized startup, cancellation and graph shutdown lifetime.
Its native profile is separate from password-proof enrollment and exposes no
new HTTP selection or browser UI:

1. Build `passkey.NewSessionEnrollmentRequest` from actual session credential,
   original CSRF for cookies, self-user `identity.passkey.register-options`
   caller, intended optional label and trusted origin/network.
2. `EnrollmentAssertionOptions` uses the original A idempotency key. Transfer
   genuine UV options once and obtain an assertion from the current session's
   authenticator.
3. `RegistrationOptions` accepts the opaque authorization with unchanged intent,
   A ceremony/assertion and a distinct B key. Native assertion consumption and
   resident-registration creation commit together. Transfer options once.
   A buffering consumer uses `RegistrationOptionsForDelivery` for the same B
   operation plus A's immutable absolute expiry. Check that nonzero ceiling
   after hooks alongside session, request and B validity; B's later TTL cannot
   replace it. Retry/error returns no options and zero expiry.
4. Change only caller action to `identity.passkey.register-verify`. `Register`
   accepts opaque completion with original B ceremony, actual registration
   response and one stable original C command ID, **without** an idempotency key.
   Protocol, kernel reference, mapping/label and required effects commit together.
5. Read safe inventory and use either key for discoverable signin/read/logout.
   Adding the key does not issue a session or invalidate the original session.

`SessionRegistrationRateSource` reads authenticated original C ceremony/user
dimensions for challenge-rate admission without creating commands, charging
native risk, consuming proof or renewing expiry. Metadata is not a validity lease;
completion still revalidates all current owners and the original A expiry.

Preserve exact A/B keys and C command/ceremony/intent after uncertainty. Matching
committed retries disclose durability metadata only, not replacement options or
credentials. Current session/CSRF remains necessary, including historical reads.
Specs/`Bindings` are deliberate unredacted projections: do not log them. The
profile requires known-empty MFA, resident UV/none/ES256 and self-user authority;
enrolled-MFA, organization and other protocol profiles remain separate work.

### Opt-in HTTP additional enrollment

Set `HTTPPasskey.SessionEnrollment=true` alongside native cookie-mode
`Passkey.SessionEnrollment`, `Passkey.KeyedOptions` and `Session.Passkey`.
Missing native/CSRF ownership, bearer native mode and simultaneous password-proof
`HTTPPasskey.Registration` fail construction. This branch needs no HTTP pre-auth,
browser-device cookie or password verifier; selecting Signup/Signin separately
retains their original browser requirements. The same shared options and
verification rate owners serve all selected registration variants.

With the current secure cookie, exact Origin and stored `X-CSRF-Token`:

1. POST `/v1/passkey/register-options` with an original header-only key and
   `{"mode":"session","phase":"assertion","label":"Additional key"}`.
   Obtain a genuine UV assertion from the session's authenticating key.
2. POST the same endpoint with a **distinct** original header key, unchanged
   label, `mode:"session"`, `phase:"registration"`, the original A command as
   `ceremonyID` and the assertion as `response`. Obtain resident registration
   from the fresh returned creation options. B retains A's original expiry.
3. POST `/v1/passkey/register-verify` with unchanged `mode`/label, one original
   canonical C `commandID`, B command as `ceremonyID` and registration `response`.
   This phase forbids `phase`, `proofID` and `Idempotency-Key`.

Retries retain original metadata without new challenges, credentials, cookies
or synchronizers. Current session/CSRF and unchanged native intent remain
mandatory. Native-only selection advertises no session-enrollment wire variant.
`TestReferencePostgresPasskeyHTTPSessionEnrollment` exercises genuine HTTPS
signup, all three phases/retries, two-key inventory, either-key signin/read/logout
and revoked original-session retry denial on fresh/populated PostgreSQL. It is
not browser/authenticator interoperability or full M16 qualification.

## Current-session resident-key removal

Explicitly select `Passkey.SessionDeletion` with
`PasskeySessionDeletionConfiguration{Transport: session.CredentialCookie}` or
`session.CredentialBearer`, alongside `Passkey.KeyedOptions`. The graph supplies
the actual session, self-user delete policy, protected risk, protocol and native
transaction owners. Cookie transport uses the graph's original CSRF keys.
The passkey-only deployment needs no password, email or OTP recovery owner.
Native selection alone enables no delete HTTP route or metadata.

After initializing the selected owned histories, obtain
`FeatureSet.Passkeys()` and its guarded `SessionDeletion()` handle:

1. Call `DeleteOptions` with `passkey.NewSessionDeleteRequest` carrying the
   current credential, original cookie CSRF when selected, self-user
   `identity.passkey.delete` caller, exact inventory reference/metadata version
   and trusted origin/network. Retain the original options key and ceremony.
2. Obtain genuine action-bound UV, then call `Delete` with
   `passkey.NewSessionDeleteCompletion`, the unchanged intent and a distinct
   original completion key. The sole native Work removes the target, consumes
   the assertion, advances passkey authority and commits required effects.
3. Existing affected passkey sessions deny. Authenticate with the surviving key
   and use `RecoverDelete` with the original command and target for metadata-only
   recovery. The invalidated original session cannot recover or obtain options.

Another independently usable resident ES256 key must remain. Removal can target
the authenticating key or a sibling; last-key removal denies. No password,
delivery or OTP fallback is inferred. Inventory metadata, kernel-reference and
protocol versions remain independent. Unknown is not rollback: retain original
command/keys/input, authenticate with a surviving key and recover; never restart
removal automatically. Recovery issues no credential, challenge or session.

Install WebAuthn history through migration 6, including both compound target
snapshots and its profile constraint. The graph appends it without rewriting
installed histories; readiness detects missing successor storage. Handles retain
graph initialization, fixed-tenant lifetime and shutdown guards. Original read
and ceremony expiry are not renewed by retries, history reads or hooks.

`TestReferencePostgresPasskeySessionDeletion` exercises actual HTTP signup,
native second-key enrollment, genuine removal, revoked-source denial, surviving-
key signin, original metadata recovery, last-key protection and read/logout for
cookie/bearer selection on fresh/populated PostgreSQL. The current selected
removal transport is native; no removal browser/UI or full M16 qualification is
claimed. Password-proof `Passkey.Deletion` remains independent and unchanged.

### Opt-in HTTP resident-key removal

Select `HTTPPasskey.SessionDeletion` independently with native cookie
`Passkey.SessionDeletion`, `Passkey.KeyedOptions`, `Session.Passkey`, original
CSRF keys and shared HTTP rates. This uses the canonical
`POST /v1/passkey/delete`; password-proof `HTTPPasskey.Delete` is mutually
exclusive. Session-only removal selects no pre-auth/device-cookie dependency.
All phases require exact mapped HTTPS host/Origin, current session cookie,
`X-CSRF-Token` and one header-only `Idempotency-Key`.

1. Send `phase:"options"`, `referenceID` and inventory `expectedVersion` with
   the original options key. Only fresh success returns genuine UV options.
2. Send `phase:"complete"`, unchanged reference/version, original `ceremonyID`
   and genuine `response` with a different completion key. Fresh success returns
   original durability metadata, not a credential, cookie or synchronizer.
3. After removal invalidates the source session, sign in with the surviving
   key. Send `phase:"recover"`, the original target/version and original
   completion `commandID` with the new session/CSRF. The header key is used only
   for shared rate admission in this phase; it allocates no command and cannot
   restart removal. Recovery returns original metadata and no options history.

Retain original keys/command/intent on unknown outcomes; never automatically
repeat removal. Options and original positive-read expiry survive all hooks.
Subsequent requests with the invalidated source session deny, including recovery.
No body identity, RP, proof, session, network or retry-key override is accepted.
Inventory metadata versions do not replace kernel lifecycle versions.

`TestReferencePostgresPasskeyHTTPSessionDeletion` proves actual HTTPS signup,
second-key enrollment, UV removal, stale-intent/CSRF/Origin and old-source denial,
surviving-key HTTP signin, metadata recovery, last-key protection and read/logout
against fresh/populated PostgreSQL, validating request/results against the
selected OpenAPI. This is backend HTTP proof, not browser/authenticator or full
M16/release qualification.
