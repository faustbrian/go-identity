# Ephemeral identity risk — Valkey

**Development checkpoint, not an executable counter store.** The module targets
Go 1.27. The owned Authentication risk prerequisite and public OTP Send are not
complete. There is no public store constructor, mutation API or healthy default.

## Current behavior

Private command preparation accepts only authentic core ephemeral commands
whose immutable policy identity and every retained digest key match the local
configuration. It rejects protected-command authority and zero epochs.

All keys of one atomic command use a single HMAC-derived tenant hash tag.
Deployment namespace and tenant are framed separately; dimension aliases retain
the core's versioned keyed digests. Keys contain no raw destination, network,
device, tenant or attempt. Stable replay identity binds tenant, operation and
attempt independently of the changing intent fingerprint, so changing input
cannot evade conflict detection by selecting a new replay key.

The dedicated namespace key must remain stable across dimension-key rotation.
Missing retained aliases fail preparation. This check does **not** prove
historical retirement or make a new epoch healthy. A tenant's multi-dimension
decision requires co-location; per-dimension sharding is not an atomic fallback.

Strict private reply decoding requires the exact fingerprint and complete ordered
post-state, canonical bounded decimal integers, exact window duration and
original server observation. It never samples a new clock. Malformed, foreign,
partial or imprecise numeric replies return `ErrOutcomeUnknown` without positive
facts; only a complete explicit noncommit declaration returns noncommit.

The private dispatch boundary rejects invalid/cancelled inputs before IO,
derives a 100ms..10s bound without extending the caller's earlier deadline,
and sends one prepared plan exactly once. Transport errors and incomplete
acknowledgements are unknown, with redacted diagnostics and no retry. A complete
acknowledged commit remains committed after cancellation or expiry of the
adapter's own deadline; the accompanying error prevents clean admission even
when the caller's longer deadline is still live. A complete pre-write
unhealthy-epoch response is noncommit plus unavailable, never clean admission.
Current dispatch tests replace the
transport boundary; they do not prove a Valkey script or real server mutation.

## Native fixed-window script

The embedded production Lua now implements a single prepared multi-dimension
debit. Its keys include health, replay, eight capacity probes and up to sixteen
digest aliases: at most twenty-six supplied keys in one slot.
Each dimension has one logical root. New versions point to its oldest retained
root; old and new writers increment the same count without summing aliases or
sliding the window. Conflicting roots and unproven retirement fail closed.

Server `TIME` controls microsecond `[start, expiry)` windows; physical TTLs round
up to milliseconds without extending the logical boundary. Matching replay
returns the original complete snapshot and observation without writes or TTL
renewal. Changed fingerprints cannot charge the same replay identity again.
All existing types, bounded fields and logical roots are checked before debit.
A capacity reservation or pending replay fence prevents another debit after a
script error with partial effects; such an error is unknown, not rollback. Every
allocation uses a single `SET PXAT`, so even failure before the following command
cannot leave a new record without expiry.

The private profile caps active replay entries at **4096 per tenant/epoch** and
retains each for **one hour**. Each attempt has eight fixed probes into those
slots. Probe exhaustion rejects before mutation and can occur before all 4096
slots are occupied; there is no hidden retry or alternative attempt ID. Expiry
needs no scan or growing index. Duplicate replay never refreshes a reservation.
Active entries are never evicted, and counts are never saturated. After retention,
the existing PostgreSQL journal must still prevent redispatch of old attempts.
The script does not independently grant that authority or publish health.

Offline tests execute the exact embedded Lua with only Redis commands replaced.
The test-only Lua 5.1 VM is `github.com/yuin/gopher-lua` v1.1.2, MIT licensed,
upstream revision `b87eac29661715e48e1a2868d76b853e0e757c4c`, pinned by `go.sum`.
It is not imported by production code or a substitute Valkey engine. Update it
only after upstream/license review and rerunning the script assertions. Tests
do not certify native timing, concurrency, replication, cluster routing or OOM
behavior. Real Valkey and full recovery/public activation remain unfinished.

Protocol references: [EVAL](https://valkey.io/commands/eval/) and
[TIME](https://valkey.io/commands/time/). Every accessed key is supplied in
`KEYS`; script source is fixed rather than generated per command.

## Ownership and operations

Native transport preparation also includes a private bounded RESP2 frame reader.
It validates a whole frame before forwarding a length header to an allocating
client parser: at most 4096 wire bytes, 128 bytes per string, 32 elements per
array, 64 total nodes and four nested array levels. Malformed or partial input
poisons the stream without forwarding that frame or preserving IO diagnostics.
Only one connection reader may use it; connection deadlines and closing remain
the connection owner's responsibility. RESP3, pushes and large management or
discovery replies are excluded from this private profile. The reader is not yet
wired to a native client; no connection or supported-topology claim follows.

Valkey will own ephemeral windows only. `risk/postgres` retains durable intent,
results and recovery leases/pages; it does not become a second counter store.
There is no native transport, lifecycle event, audit or background work yet.
Private dispatch invokes its bounded execution seam but
establishes no health or replay-publication authority.

The planned native transport is the existing foundational Valkey client, not
cache or rate-limit single-key admission composed into non-atomic operations.
Live server-time/TTL/cardinality evidence, no hidden retries, `noeviction`
readiness and journal-fenced healthy publication remain required.
No standalone, replicated or cluster runtime support is claimed at this stage.

## Adoption, examples and FAQ

Do not compose this checkpoint into a running identity service. Continue using
the core `risk.CounterCoordinator` contract; its store is not implemented here
yet. There is intentionally no example that fabricates a healthy epoch or
application-owned recovery callback. Executable public examples follow the
real native store and authoritative recovery implementation.

**Does matching command preparation allow OTP issuance?** No. It is a storage
plan, not a current risk decision, bearer, epoch receipt or execution permission.

**Does missing state mean zero attempts?** No. Loss/reset must remain unavailable
until the existing PostgreSQL recovery authority proves replay and publication.

**Are release gates passed?** No. Real infrastructure/topology, journal replay,
rotation history, cancellation/ambiguity, events/lifecycle, exact coverage and
mutation, clean-consumer/source-pin and release checks remain pending.
