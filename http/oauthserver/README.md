# Opt-in workload OAuth HTTP

Go 1.27 development profile. This optional module connects the public native
OAuth service to the existing identity HTTP router. It owns transport and
canonical HTTP rate policy, not client credentials, grant storage, authorization,
transactions, cryptography or recovery. The selected workload journey has been
exercised against actual public native PostgreSQL owners over HTTPS. Reference
integration, published HTTP consumption and full module qualification remain
unfinished.

## Selected endpoints

- `Token`: `POST /oauth2/token`, confidential `client_credentials` only.
- `Introspect`: `POST /oauth2/introspect`, owning-client RFC 7662 disclosure.
- `Revoke`: `POST /oauth2/revoke`, owning-client RFC 7009 revocation.

Each endpoint is independently selected. Omit the feature entirely for empty
selection; disabled routes and OpenAPI entries are absent. No discovery,
authorization, client-management, code, refresh, token-exchange, OIDC, browser
cookie or device route is selected by this profile.

Construct `NewFeature(ctx, FeatureConfig{...})` with a real configured native
`*oauthserver.Service`, trusted `NetworkConfig`, one borrowed strong rate store,
immutable deployment namespace, trusted clock and bounded handler duration.
The service's configured discovery projection must declare the exact issuer
and selected canonical endpoint paths; it is inspected without IO, not served
as a metadata endpoint. The network policy must include that issuer host.

Pass the returned feature to `identityhttp.NewOperationDescriptors`, then
`identityhttp.NewRouter` using the same network configuration. `NewHTTPServer`
owns raw header/read/write/shutdown limits. Handlers and borrowed dependencies
must remain alive until serving is drained; this feature starts no goroutines
and does not close their stores.

## Credentials, rate and outcomes

Only one RFC 6749 `client_secret_basic` header is accepted. Form-encode the
client ID and secret separately before constructing Basic authentication;
there are no body/query credentials, ambient-cookie fallback or idempotency-key
channel. Forms are closed and duplicate-free, at most 16 KiB raw/decoded,
within the configured field/header/URI limits. Trusted HTTPS issuer, host,
proxy and full-IP attribution come from the existing resolver.

IP admission precedes client verification. The native current-client owner
then verifies credentials before the authenticated-client debit; incorrect
secrets cannot exhaust the authenticated client's bucket. Token limits are
120/IP/minute and 60/client/minute. Introspection/revocation share
240/IP/minute, 120/client/minute and, for a tenant-bound issuer,
600/tenant/minute. Counters are primitive-owned and shared across instances;
there is no local outage fallback or implicit refund. Native protected-risk
and final current-authority checks remain mandatory after HTTP admission.

Only fresh known-committed issuance can return the access bearer. Unknown,
replayed, canceled or failed results disclose neither tokens nor internal
command IDs. HTTP does not reconstruct lost credentials, retry mutations or
claim rollback on cancellation. Inactive introspection exposes only
`{"active":false}`. Known successful revocation returns an empty 200 response;
unknown/foreign tokens retain native non-enumerating behavior.

Responses are bounded and no-store. Native errors are mapped to closed OAuth
codes without diagnostics or credential echoes. Invalid clients receive 401
with a Basic challenge; rate exhaustion receives 429 with bounded Retry-After;
unavailable authority receives 503. Admission success is not a reusable proof
or resource-server authorization, and must never replace final native checks.

## Development checks

Use task-owned disposable Go caches and `GOWORK=off`:

```sh
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
go mod tidy -diff
```

Transport tests use the real core authenticator and rate primitive at explicit
storage seams. Separate development integration evidence uses actual native
PostgreSQL owners and HTTPS: issuance, owning-client introspection, revocation,
inactivity after authority withdrawal, unavailable authority/rate-store denial
and rollback when the required outbox effect fails. No human user or consent is
created. That evidence does not establish Reference composition, published HTTP
consumption, complete M32 or release qualification.
