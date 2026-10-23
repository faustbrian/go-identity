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
  -run '^TestReferencePostgresPasskey(Native|PopulatedUpgrade)$' .
```

Agent runs additionally set task-owned disposable Go caches. The fixture uses
`IDENTITY_REFERENCE_POSTGRES_PORT`. Actual registration, captured verification
delivery and password signin precede fresh reauthentication and the passkey
journey; none of those domain records or proofs are fabricated. Only HIBP/email
external IO and raw none/ES256 authenticator responses are controlled seams.

This is native reference composition, not passkey HTTP transport. Existing
`Sessions()` and HTTP session routes do not implicitly adopt the new method;
use the selected passkey handle for its read/logout profile. Passkey HTTP,
signup, identifier-free/conditional signin, credential rename/delete, completed
secondary MFA and organization profiles remain separate required work. This
profile is not complete M16, full release qualification, deployment or a UI.
