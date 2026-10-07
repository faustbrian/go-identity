# Owned velocity recovery custody

This private package carries immutable original journal facts between Golib's
owned PostgreSQL journal, native Valkey projection and reference composition.
It is not a public application integration API, another journal, a replay
engine or a health authority. It has no storage, clock, retry or goroutine.

The durable owner constructs a lease only after an acknowledged primary lease,
and supplies an exact-receipt, context-bounded, concurrent-safe checker. History
is constructed only from reread authenticated original records. Native recovery
must check that exact lease and enforce its native fence before any effect.
An acknowledgement can be created only after an attributable native result;
the primary owner must independently authenticate and persist ordered progress.
Neither an acknowledgement nor applied progress establishes healthy state.

Pending and unknown history cannot produce an effect acknowledgement. Original
windows and counts are copied, never refreshed. Snapshot order need not match
policy order; dimensions must match exactly once. Accessors clone slices.
Diagnostics are redacted and serialization is forbidden. There is no public
secret accessor: fact access requires importing this Go `internal` package.

Go internal visibility is an ownership boundary, not protection from malicious
code deliberately installed within the owned module tree. Only owned adapters
may construct these handles; consumer callbacks must never receive constructors
or fact-access functions. Full reference composition remains under development.
