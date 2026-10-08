# Ephemeral identity risk — Valkey

**Development checkpoint, not an executable counter store.** The module targets
Go 1.27. The owned Authentication risk prerequisite and public OTP Send are not
complete. There is no public store constructor, mutation API or healthy default.

## Current behavior

The native owner can check current eligibility without dispatching a debit.
It authenticates the existing healthy custody, reads only the exact confirmed
marker under bounded server-time and transport-continuity checks, and rechecks
current primary eligibility afterward. Missing, altered, expired or merely
published markers deny; the check never repairs state or renews expiry. This is
the required native check for journal terminal readback, not permission to resend
pending/unknown attempts or an activated public store. Atomic debit independently
rechecks the exact marker at its effect boundary.

Private command preparation accepts only authentic core ephemeral commands
whose immutable policy identity and every retained digest key match the local
configuration. It rejects protected-command authority and zero epochs.

All keys of one atomic command use a single HMAC-derived tenant hash tag.
Deployment namespace and tenant are framed separately; dimension aliases retain
the core's versioned keyed digests. Keys contain no raw destination, network,
device, tenant or attempt. Core `VelocityReplayIdentity` preserves PostgreSQL
uint64-framed attempt bytes and binds tenant, operation, phase and
attempt independently of the changing intent fingerprint, so changing input
cannot evade conflict detection by selecting a new replay key.

The private physical layout is now `irv2`, separating it from the never publicly
activated `irv1` raw-attempt-derived layout. Old health/replay keys cannot enable
or reconstruct this profile; there is no fallback or automatic migration.
Both adapters must select the same stable namespace and replay key. This byte
compatibility does not authenticate history or complete recovery composition.

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
requires an independently retained exact confirmed marker, and sends one
prepared mutation plan exactly once. The atomic script compares the complete
marker before returning even an old replay; epoch-only requests are rejected.
This private input is not a public authority constructor. Transport errors and incomplete
acknowledgements are unknown, with redacted diagnostics and no retry. A complete
acknowledged commit remains committed after cancellation or expiry of the
adapter's own deadline; the accompanying error prevents clean admission even
when the caller's longer deadline is still live. A complete pre-write
unhealthy-epoch response is noncommit plus unavailable, never clean admission.
Current dispatch tests replace the
transport boundary; they do not prove a Valkey script or real server mutation.

The private owned current-admission crossing authenticates a genuine core
command against its configured layout and the exact tenant/namespace recovery
chain. It checks the distinct current-primary eligibility before native IO,
derives the original confirmed marker without caller-selected time or epoch,
and rechecks primary eligibility after the effect. It invokes no replay-only
checks after activation. A later primary failure preserves any acknowledged
effect while denying admission; it never retries or renews custody. This is not
a public store: the composition owner must durably journal intent before this
crossing and conserve its returned result afterward. That ownership and public
composition remain unfinished.

## Private native transport

The private standalone transport now sends the exact embedded EVAL through
adapter-owned synchronous RESP2 IO. It validates a canonical `rediss` DNS endpoint,
explicit credentials, verified TLS 1.2 or newer and caller-owned trust roots,
then clones the TLS configuration. Construction performs no IO or health
publication. Credential formatting is redacted and serialization is rejected.

One physical connection and one command owner per slot enforce the configured
1..200 connection bound. Capacity waiting, dialing, TLS, startup and EVAL share
the caller's earlier deadline or the configured 100ms..10s limit. Cancellation
closes blocked IO; shutdown permanently rejects new work, cancels active work,
closes idle connections and joins its cancellation callbacks within its bound.
There are no background client workers, discovery, redirects, reconnects,
caching or automatic mutation retries. AUTH must receive exact success; HELLO 2
must confirm RESP2 and standalone mode before any EVAL. Request encoding is
binary-safe and bounded to 32768 bytes before allocation. The bounded RESP2
reader protects startup and mutation replies before decoding. Complete acknowledged outcomes
survive late cancellation, but cannot grant timely admission.

Each effect is bracketed by two bounded read-only profile EVALs on that same
owned connection. The script reads selected `INFO` sections and requires a
primary with no connected replicas, `noeviction`, a nonzero server run ID and
a canonical eviction counter. Credentials therefore also need permission for
`INFO`; inability to read the profile fails closed. The first eligible run ID
and eviction count remain fixed for the transport's lifetime. Reconnects and
old metadata returning cannot replace the baseline. Once acquired, any observed
profile uncertainty/loss is terminal for that transport. In-flight operations
recheck this shared condition after cleanup. An attributable mutation reply
survives a later profile failure, but the error prevents clean admission.
These are three EVALs total (two read-only and one effect), never a mutation
retry, all under the original operation deadline.

The protocol fields follow [Valkey INFO](https://valkey.io/commands/info/) and
the [8.0.0 command definition](https://github.com/valkey-io/valkey/blob/8.0.0/src/commands/info.json).
The profile reads are **not atomic with the effect**. They do not attest
selective deletion, flush/fence reinstatement, statistics laundering or every
possible loss between reads. A new transport alone cannot confer health; full
recovery and current PostgreSQL healthy eligibility still require owned
composition before public activation.

Offline tests exercise the synchronous transport and verified TLS through
memory-only `net.Pipe` fixtures. The integration-tagged
`TestOwnedCurrentAdmissionLiveValkey` also exercises a disposable TLS Valkey
8.0.0 standalone server: recovery-marker transitions, matching replay with
unchanged payloads and absolute expiries, concurrent debits, current-primary
denial and missing-marker denial. It uses simulated primary custody; it does
not prove PostgreSQL/Valkey composition, replicated/cluster topology,
journal-fenced recovery or public store activation. Those remain required.

## Native fixed-window script

### Private recovery effects

Private `ownedRecovery.publish` consumes the configured opaque covered closure,
not projected fields or an ordinary stable cut. It verifies the original
primary lease/cut before IO, checks the namespace, and atomically replaces only
the exact existing replay fence with `published` custody retaining the original
epoch, generation, owner, exclusive expiry, keyed cut ID, applied position,
traversal bounds, continuous journal start and one-hour maximum. Empty covered
history is valid but still requires an existing native fence. Missing/reset,
conflicting or expired fences deny; identical publication retries return the
same digest without writes or expiry changes. Only an attributable reply plus
final original-primary checks exposes `VelocityPublication`. Lost or late
acknowledgements expose none and never trigger a resend.

The private native confirmation path now retains an opaque acknowledgement of
its exact successful marker transition after final primary checks, under one
unchanged deadline. A lost/late acknowledgement or observed continuity loss
returns no custody and is never implicitly retried. Its historical facts can
be consumed by the primary activation owner, but cannot certify current
eligibility or bypass the exact-marker/native-continuity debit checks.

Publication is **not primary confirmation or usable health**. Bare epochs and
`published` markers cannot authorize mutation. The private engine recognizes
only a bounded, non-expired `confirmed` cut representation, including when
reading old mutation replies. Private `ownedRecovery.confirm` now writes that
representation only from current exact primary confirmation and the matching
existing published marker. It uses its native issuer's own derived verifier,
checks primary custody before and after IO, preserves every cut field and the
original logical/physical expiry, and never repairs a missing marker. Exact
explicit retries are read-only; ambiguous effects never trigger a resend.
No public healthy store exists. This marker makes the private mutation engine's
exact-match predicate eligible, not safe public admission: confirmed marker
syntax or equality alone does not establish surviving counters or primary
healthy state. The script's expected-marker check is now implemented; joint
primary healthy eligibility and
native boot/fence continuity across reset remain required before activation.
This checkpoint proves a fenced marker transition, not survival of all earlier
restored counters after eviction/reset or supported Valkey interoperability.

Recovery now has separate fixed native scripts for fence installation/renewal
and restoration. The owned recovery boundary initializes/renews its fence
explicitly before traversal. Per-record restoration never invokes fence
installation: a disappeared live fence denies without repairing the marker or
any counters, including matching replay. Initialization is not permission to
resume old applied progress after loss; the complete composition must restart
recovery from primary-owned zero progress before a new projection can activate.

A fence binds the boot epoch,
exact uint64 generation, random owner and original microsecond expiry. Native
server time rejects expired effects even while physical TTL rounding retains
the key. Same-generation renewal requires exact current custody and a later
expiry; takeover requires expiry and a strictly greater generation. Matching
installation replay performs no write or TTL renewal.

Restoration runs only under the exact live `replaying` marker. It restores
cumulative counts with monotonic original windows rather than increments or
summing snapshots; delayed declarations cannot roll a counter backwards.
Expired snapshots are not resurrected. Original complete mutation replies and
replay retention are preserved. Bounded capacity checks and all record validation
precede writes. Partial restore failures leave the marker replaying; a later
owned reconciliation can repeat known committed history without another debit.
The native transport performs no automatic resend and accepts only an exact
attributable acknowledgement within its deadline.

Private owned recovery now consumes the core's issuer-bound lease/history
contract. Trusted composition retains native issuance separately and derives
its journal verifier from that issuer. Original tenant, namespace, attempt,
aliases, policy and dimension-addressed snapshots are reconstructed without
preparing a fresh command or recovering raw identifiers. Pending/unknown,
foreign ownership and missing retained aliases never reach native IO.
After exact fenced native restoration, current primary ownership is rechecked
before issuing an acknowledgement of that original history. Explicit primary
noncommit additionally requires a read-only fenced native absence proof: any
retained attempt root or matching directory entry denies, including conflicting,
unresolved or corrupt state. This proof neither clears state nor refreshes TTL.
Failed, late or ambiguous effects expose no acknowledgement and are not resent.

These are private effect boundaries, not a complete recovery service. They do
not persist applied journal progress, establish cross-store clock bounds or
publish health. Journal-backed concrete composition, writer-fenced healthy
publication and public store activation
remain unfinished. Tests execute the exact Lua and verified TLS using offline
boundaries; real Valkey interoperability remains unproven.

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
