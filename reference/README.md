# Identity reference composition

**Development checkpoint:** this module currently implements only the
PostgreSQL-journaled, TLS Valkey velocity store graph. The complete reference
server, HTTP features, provider/worker composition, readiness, migration
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

## API reference

- `StoreConfiguration`: one immutable selected configuration input; copied at
  composition and never retained as caller-owned TLS/secret slices.
- `VelocityStoreConfiguration`: explicit transport, custody, scopes and
  traversal bounds. Zero does not select defaults.
- `ReferenceDependencies`: deployment resources only; currently PostgreSQL.
- `ComposeStores`: the sole store construction entry point; validates without IO.
- `StoreSet`: sealed shared-lifetime result, not caller-constructible.
- `StoreSet.MigrationSource`: pure upstream-owned migration contributions.
- `StoreSet.RecoverVelocity`: one bounded, fail-closed recovery/activation.
- `StoreSet.Close`: permanent cancellation and bounded joining; repeated calls
  are safe, and a deadline does not reopen ownership.

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
