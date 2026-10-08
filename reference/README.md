# Identity reference composition

**Development checkpoint:** this module currently implements only the
PostgreSQL-journaled, TLS Valkey velocity store graph and optional native OTP
Send/delivery composition. The complete reference server, HTTP features,
readiness, migration
Check/Plan/Apply workflow and identity journeys remain unimplemented here.

## Quick start

Supply a caller-owned `go-postgres` pool and one
`VelocityStoreConfiguration`, then construct the sealed graph:

```go
func compose(pool *postgres.Pool, velocity reference.VelocityStoreConfiguration) (reference.StoreSet, error) {
    return reference.ComposeStores(
        reference.StoreConfiguration{Velocity: velocity},
        reference.ReferenceDependencies{PostgreSQL: pool},
    )
}
```

The named modules are `github.com/faustbrian/go-postgres` and
`github.com/faustbrian/go-identity/reference`. Configuration selects the schema,
unique tenant allowlist, positive primary/recovery timeouts, a lease at most one
minute, batch (1–1000; reference 100) and maximum records (1–100000). Recovery
timeout must be less than the lease. `Native` selects the deployment namespace,
stable replay secret, risk policy, complete retained digest-key history,
canonical `rediss://DNS:port` endpoint, TLS name/preferences, explicit PEM trust,
opaque copied credential, bounded native timeout/pool and `standalone` topology.
The primary receives those exact namespace/secret/policy/key values internally.

Construction performs no network IO or migration. Explicitly install the
returned `MigrationSource()` using the existing `go-migrations/v3` PostgreSQL
backend and runner before recovery. No private SQL runner or copied migration
history is provided. Kernel versions remain 1–9; reference velocity uses the
permanent allocation 1000–1011. Do not silently adopt a differently allocated
existing ledger. Full reference migration planning remains future work.

Call `stores.RecoverVelocity(ctx, tenant)` explicitly. It returns no counter
store until the actual primary journal has a full hour of coverage, all original
terminal records are restored and acknowledged, and the exact native publication
is confirmed and activated by the primary. A fresh empty journal is **not**
healthy. After genuine warmup, another explicit recovery can establish the
covered cut. There is no automatic polling, health renewal or hidden retry.

Use the returned `risk.CounterStore` with `risk.NewCounterCoordinator`; the
owned store records durable intent before its single native mutation and
retains the original outcome through that exact primary receipt. Retain a known
committed result even if a later error denies positive admission. Pending or
unknown outcomes never permit redispatch.

Call `stores.Close(ctx)` to cancel and join recovery and close owned native
connections. Close the caller-owned primary pool separately, after its users
have finished. No handler, health/readiness endpoint or background worker is
created by this development slice.

Successful recovery also retains that exact counter owner for the forthcoming
feature-composition path. Its internal deferred connection rejects requests
before recovery, during a new recovery generation and after shutdown. A failed
new generation cannot fall back to the previous activation. Routing adds no
retry or renewal and preserves the native owner's original outcome declaration.
The optional OTP profile uses this connection internally; it does not accept a
caller-written risk evaluator or counter store.

## Optional OTP Send composition

Select both `StoreConfiguration.OTP` and `StoreConfiguration.Delivery`, with
deployment envelope keys and a bounded sender in `ReferenceDependencies`.
The delivery profile must enable state tracking and use production policies.
Risk uses the velocity graph's exact policy and retained keys. This checkpoint
supports velocity-only admission: required unsupported signals fail composition
rather than receiving permissive stand-ins.

Compose in order with `ComposeProviders(stores)`,
`ComposeWorkers(stores, providers, workerConfigs...)`, then
`ComposeFeatures(stores, providers, workers)`. These stages perform no network
IO and start no goroutines. Every selected tenant needs a real delivery worker
for the selected OTP provider version. All handles share the store lifetime;
foreign, reused or incomplete graphs are rejected.
All workers share the strictest retained sender-concurrency ceiling before
claiming. Dedicate the sender instance to this graph; unrelated graphs or direct
callers require their own shared capacity control.

`StoreSet.MigrationSource()` preserves kernel 1–9 and risk 1000–1011 exactly.
Selecting OTP/delivery appends owner-produced kernel 1012–1018, OTP 1100–1103,
pre-auth session 1200–1201, distinct authenticated session 1210, delivery
1250–1254 and authorization authority 1300. Selected delivery cancellation uses
1255, receipt metadata uses 1256, authenticated receipt commands use 1257, and
reconciliation uses 1258–1260. Receipt metadata is included whenever receipt
tracking, authenticated receipts or reconciliation needs it; unselected
extensions remain absent. Shared session schemas reuse one base; OTP, session
and risk owners must otherwise use distinct schemas. Unselected profiles
contribute no schema. These are
new permanent reference allocations, not changes to applied history. Keep the
selected schemas, global authority and `OTP.BootstrapTenantIDs` unchanged after
apply; later tenant onboarding uses owned lifecycle APIs. Bootstrap tenants are
copied explicitly and are not inferred from velocity scopes. An empty set grants
no bootstrap tenant authority.

**Migration limitation:** independent audit/outbox histories and the complete
Check/Plan/Apply coordinator remain unimplemented. The joint integration fixture
still installs upstream schemas explicitly; its runtime evidence does not prove
consumer adoption of this source. Do not deploy this partial profile or substitute
consumer-written migration glue. Existing fixture-installed objects without
matching native records are unmanaged state, not permission to baseline them.

Once selected schemas exist, `features.Initialize(ctx)` registers native
metadata without warming risk or sending messages. Obtain the public Send
interface with `features.OTP()`. Calls before initialization, before valid risk
activation, for unselected tenants or after closure deny. Exact committed
receipts can replay through a reconstructed initialized graph without a fresh
counter debit; fresh requests still require activation. `workers.ProcessDeliveryOne`
performs one explicit bounded native step; callers supply scheduling, not a
replacement delivery workflow. Queue acceptance does not prove provider delivery.

Audit delivery fails closed. A lost decision gets one idempotent retry of its
original immutable event; durable audit-outage handoff remains unimplemented.
Authenticated-session parity, joint unknown-outcome recovery, complete operator
APIs and full reference acceptance remain outstanding.

## API reference

- `StoreConfiguration`: one immutable selected configuration input; copied at
  composition and never retained as caller-owned TLS/secret slices.
- `VelocityStoreConfiguration`: explicit transport, custody, scopes and
  traversal bounds. Zero does not select defaults.
- `ReferenceDependencies`: borrowed PostgreSQL and selected envelope/sender resources.
- `OTPSendConfiguration`, `DeliveryConfiguration`: explicit native workflow profiles.
- `ComposeStores`: the sole store construction entry point; validates without IO.
- `StoreSet`: sealed shared-lifetime result, not caller-constructible.
- `StoreSet.MigrationSource`: pure upstream-owned migration contributions.
- `StoreSet.RecoverVelocity`: one bounded, fail-closed recovery/activation.
- `StoreSet.Close`: permanent cancellation and bounded joining; repeated calls
  are safe, and a deadline does not reopen ownership.
- `ComposeProviders`, `ComposeWorkers`, `ComposeFeatures`: one sealed selected graph.
- `FeatureSet.Initialize`, `FeatureSet.OTP`: explicit startup and public Send access.
- `WorkerSet.ProcessDeliveryOne`: one explicit native delivery step, without polling.

Formatting is redacted and JSON/text serialization is denied for composition
inputs and handles. See Go documentation for exact errors and lifetime semantics.

## Security and adoption tradeoffs

PostgreSQL is authoritative; Valkey is an ephemeral projection. Recovery never
debits a counter or creates mutation intents. It restores original values,
observations and absolute expiry, not refreshed windows. Live primary ownership,
unknown history, corruption, missing native custody, lost acknowledgements,
incomplete coverage or exhausted bounds grant no store. Later counter calls
recheck the exact original primary/native chain without resetting its expiry.
No SQL transaction spans native IO.

Tenant scopes are selected at deployment, not accepted dynamically from requests.
Only one in-flight recovery per selected tenant is permitted; different selected
tenants can proceed concurrently. The primary owns cross-process exclusion.
Local configuration and copied handles do not grant takeover authority.

This slice deliberately does not renew healthy leases or reconcile a foreign
owner's opaque live marker. Existing handles become unavailable at their
original activation expiry. Cross-process recovery, continuous workers and
additional deployment topologies remain release work. Do not treat this module
as a production-ready login service.

## FAQ

**Why doesn't an empty deployment immediately accept traffic?** It cannot prove
the previous maximum window contained no unresolved work. The authoritative
journal lifetime starts at real insertion time, never one hour in the past.

**Can I inject a journal, health checker or effect callback?** No. The concrete
owned adapters are constructed once with paired opaque authorities. Dependencies
contain deployment resources, not a consumer-written identity workflow.

**Does the historical-origin integration fixture prove fresh bootstrap?** No.
It tests joint mechanics conditioned on established coverage. Only the separate
actual one-hour lane can prove genuine fresh warmup.

## Verification and release notes

Integration tests require isolated loopback PostgreSQL and authenticated TLS
Valkey. They reject missing fixture inputs. The actual warmup test requires
`IDENTITY_REFERENCE_REAL_WARMUP=1` and a timeout exceeding one hour. No tests
contact existing application services. Exact coverage, mutation, interoperability,
clean-consumer and complete reference acceptance gates remain release requirements.
See [CHANGELOG.md](CHANGELOG.md).
