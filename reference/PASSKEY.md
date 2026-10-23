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
second migration engine. `MigrationSource()` alone is not the complete selected
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
