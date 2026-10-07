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

## Ownership and operations

Valkey will own ephemeral windows only. `risk/postgres` retains durable intent,
results and recovery leases/pages; it does not become a second counter store.
There is no native transport, server mutation, expiry, lifecycle event, audit or
background work yet. Private dispatch invokes its bounded execution seam but
establishes no health or replay-publication authority.

The planned native transport is the existing foundational Valkey client, not
cache or rate-limit single-key admission composed into non-atomic operations.
Server time, exact TTL ownership, cardinality limits, no hidden retries,
`noeviction` readiness and journal-fenced healthy publication remain required.
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
