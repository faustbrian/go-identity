# Native existing-account passkeys

Select `StoreConfiguration.Passkey` only when its password signin, session and
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

`StoreConfiguration.HTTPPasskey` independently selects `Registration`, `Signin`
and `Inventory`. `Discoverable` additionally opts signin into identifier-free
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
current authority and atomic-consumption checks remain mandatory. No HTTP signup,
conditional UI, deletion, MFA fallback or browser interoperability is claimed.

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

This is native passkey reference composition with opt-in common session HTTP
read/logout, not passkey enrollment/signin HTTP transport. Existing `Sessions()`
and HTTP session routes do not implicitly adopt the new method. The common
session HTTP tests cover identified and identifier-free signin, fresh install
and populated upgrade, wrong-CSRF/foreign-origin denial, original cookie
deletion and both native/HTTP post-logout rejection over real loopback TLS.
The keyed-options journey additionally covers both modes on fresh and populated
installations, matching metadata-only retries, authenticated original rate
sources and genuine completion into that same usable session/read/logout path.
Passkey enrollment/signin HTTP,
signup, conditional signin, credential rename/delete, completed
secondary MFA and organization profiles remain separate required work. This
profile is not complete M16, full release qualification, deployment or a UI.
