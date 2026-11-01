# Configured workload OAuth profile

This is an explicitly selected PostgreSQL-only Reference profile, not the full
OAuth/OIDC server or a browser login backend. It composes Golib's own protocol
and native transaction owners through the same public construction graph.
Keep the supported human-authentication profiles separate; incompatible mixed
selections fail before serving rather than silently dropping a feature.

## Configuration

- Select `StoreConfiguration.OAuthWorkload`. Its public protocol configuration
  contains only configured confidential `client_secret_basic` workload clients.
  The owning native constructors validate scopes, resource, client verifiers,
  key history, TTLs and operation budgets. The client cannot select an arbitrary
  tenant, user or service account in a request.
- Supply the exact existing authorization service to native coordinator/request
  policy and `ReferenceConfig.Policies.Authorize`. All five `PolicySet` members
  remain mandatory; the graph does not replace them with permissive defaults.
- Declare immutable `BootstrapTenantIDs` and `GlobalAuthorityID` explicitly.
  Admission tenant scopes do not create directory authority. Every configured
  workload tenant must be declared and selected in `DurableAdmission`.
  `PolicyNamespace` must be exclusive to service accounts, not shared with
  human-subject namespaces; the authorization scope has no subject-kind key.
- Supply stable retained fingerprint, request, token, intent and encryption
  keys. `ReferenceDependencies.EnvelopeKeys` is the caller-owned native
  `*keyring.Provider`; PostgreSQL remains caller-owned too. Never regenerate
  custody on restart or serialize this configuration into diagnostics.
- Select the real `clock.System` value for protocol and command-policy clocks.
  Test-clock overrides are not accepted by this production profile.
- Select `HTTPOAuthWorkload` separately. At least one of `Token`, `Introspect`
  and `Revoke` must be true. Introspection also requires the native
  `OwningClientIntrospection` selection. Configure the shared strict `HTTPRate`
  backend and its namespace/budgets; there is no local outage fallback.
- The issuer must exactly match the configured HTTPS host and canonical
  `/oauth2/token`, `/oauth2/introspect` and `/oauth2/revoke` locations. Apply
  the existing trusted tenant resolver/network policy, not client-supplied
  forwarded identities. No discovery endpoint is registered implicitly.
  Reference's tenant-bound HTTP profile requires an issuer `TenantHosts`
  binding, and every configured workload tenant must equal that binding.
  Public-only hosts and conflicting client tenants are rejected before serving
  so HTTP admission, rate accounting and native authority cannot disagree.
  Native-only selection retains independently bound multiple workload tenants.

The executable configuration in
[`oauth_workload_integration_test.go`](oauth_workload_integration_test.go)
uses only public constructors, deployment configuration and explicit policy.
Its external fixture provides PostgreSQL, not replacement domain stores or
handwritten migration installation.

## First installation

1. Call `ComposeStores`, `ComposeProviders`, zero-config `ComposeWorkers`,
   `ComposeFeatures` and `NewServer` in their documented order. Construction
   opens no listener and performs no migration or authority bootstrap.
2. Explicitly plan and apply the selected native histories through
   `ReferenceMigrationPlan` and `ReferenceMigrationApply`, including owners
   `identity/postgres`, `identity/risk/postgres`, `authorization/postgres`,
   `audit/postgres`, `outbox/postgres`, `outbox/postgres/identity`,
   `oauth-server/postgres` and, when selected, `rate-limit/postgres`.
   Retain the original command, complete plan and idempotency key on uncertainty.
3. Before startup, the trusted offline operator calls
   `StoreSet.BootstrapOAuthWorkloads`. This stages only configured service-account
   authority at epoch one in one transaction. Existing scopes conflict rather
   than reset, including epochs greater than one. It is not an HTTP operation
   or an automatic missing-authority repair.
4. Call `FeatureSet.Initialize`. It reads current directory and workload
   authority without creating any and proves the selected immutable envelope
   key with a managed, noncredential encryption/decryption round trip. Failure
   leaves the graph unready; probes do not generate keys or cache authority.
   Check `Server.Readiness`, then expose
   `Server.Handler` through the caller's bounded HTTPS server.

On restart, retain configuration and custody, check the installed histories,
and call `Initialize`; do not repeat bootstrap. A bootstrap commit error is
not success. `Initialize` can reconcile whether every scope exists authoritatively
without replaying creation. Missing, disabled or unavailable authority denies.
Normal traffic and readiness never apply migrations or repair state.

## Consumer lifecycle

Use form-encoded POST with one HTTP Basic authentication channel:

- `/oauth2/token`: `grant_type=client_credentials`, a registered `resource` and
  a subset of the client's configured scopes. Success returns a finite opaque
  access token, never a refresh token or human session.
- `/oauth2/introspect`: `token` and optional `token_type_hint=access_token`.
  Only the authenticated owning client can inspect its token. Responses are
  uncached current-authority observations, not reusable validity leases.
- `/oauth2/revoke`: the same token fields. Successful revocation has an empty
  response; subsequent introspection is exactly `{"active":false}`.

Authority epoch advancement invalidates existing tokens. It does not permanently
deactivate the configured workload: fresh issuance may use the new current
epoch. Tenant disabling and unavailable authority deny according to the native
owner. Required audit/outbox failure rolls back the protected mutation rather
than returning a bearer. No credential or internal failure detail belongs in
errors, logs, traces or examples.

`StoreSet.Close` cancels/drains owned operations and permanently denies retained
handlers and `FeatureSet.OAuthWorkloads()` native handles. That native handle
exposes `Token`, `Introspect` and `Revoke` without selecting HTTP and checks
initialization/lifetime on every call. It does not close the caller's PostgreSQL
pool or key provider. The
profile starts no background worker or listener; the caller schedules lifecycle.

## Scope and adoption limits

Nil selection retains old routes and migration bytes. This profile selects no
password, OTP, delivery, session, device or separate consent-lifecycle history.
The native OAuth base retains its empty human-capable tables; no human or
consent records are created to enable workloads. Existing shared
kernel/risk history remains unchanged; explicit independent owner suffixes
carry new workload requirements. Unmanaged objects or incompatible installed
histories are not adopted silently.

Managed-client administration, code/PKCE, refresh, restricted exchange, OIDC,
device authorization and full mixed Reference composition are separate retained
platform requirements, not capabilities advertised by this profile.
