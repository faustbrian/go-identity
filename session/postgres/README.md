# PostgreSQL session storage

Experimental Go 1.27 durable adapter. Forward-only migrations and bounded
primary `Get`/digest `Lookup` reads preserve complete native session records,
resolved lifetime limits, original nanosecond timelines, full uint64 authority
versions and revocation tombstones. **Issuance, shared-coordinator Apply,
rotation, recovery, cleanup, devices and online authority enforcement are not
implemented yet. This is not a login/session-authentication service.**

## Adoption and API

`NewRepository(pool, Config{Schema: "identity_session", MaximumDuration:
time.Second})` accepts the caller-owned `go-postgres` PRIMARY pool. It performs
no IO. Apply migrations first and close the pool only after all calls finish.

`MigrationSource{Schema: "identity_session", Version: 10}` returns one atomic,
forward-only install. The version is an example: the platform composition owns
its permanent allocation in the single `go-migrations` history. Compose this
source with the installed kernel history and run the owned migrations Runner
and PostgreSQL backend. The kernel's `identity.users` table is a prerequisite.
Never use independent competing ledgers, renumber applied versions or silently
adopt an occupied schema. `public`, `identity`, `information_schema`, `pg_*`
and noncanonical schema names are rejected. There is no destructive down SQL.

`Get(ctx, tenant, sessionID)` and `Lookup(ctx, tenant, session.TokenDigest)`
return a structural `StoredSession`. Both use one joined primary query and a
finite read budget. Earlier deadlines win; cancellation, deadline, absence and
unavailability are redacted. No SQL diagnostic or partial record escapes.

## Security and tradeoffs

- These are trusted storage APIs, not unauthenticated public endpoints.
- A found record is **not** authentication, authorization or current-validity
  evidence. Deny revoked records/families and compare every applicable current
  authority before accepting a credential. Neither timestamp nor construction
  proves a source read or renews the original freshness bound.
- The returned native session retains its original family version. The current
  family's version/status are separate facts; they never replace the snapshot.
- Only tenant/version-bound digests are indexed. Raw bearer tokens and opaque
  authenticated proofs are never stored or reconstructed. All returned digest
  bytes are compared in constant work; database lookup is not constant latency.
- Schema-versioned bounded JSONB stores one complete explicit native projection.
  Missing, null, unknown and malformed fields fail closed on reconstruction.
  JSON numbers are decoded directly into integers, never through float64.
- UTC, fixed-width nanosecond text preserves exact timeline precision and
  bytewise expiry ordering. Standard PostgreSQL timestamptz would round these
  native timestamps. Expiry indexes are preparation, not an implemented cleanup.
- Protect database access, backups and retention: non-bearer authentication
  metadata and authority scope keys still correlate users. Do not log records,
  digests, query arguments or driver diagnostics.
- PostgreSQL uniqueness/FKs enforce exact tenant/session/digest and parent
  relationships. Cross-tenant absence does not disclose a foreign record.

## Operations, verification and FAQ

Use the `integration` build tag and an explicit task-owned loopback
`IDENTITY_SESSION_POSTGRES_TEST_DSN` for tests. Missing selected infrastructure
fails, never skips. Unit and fuzz tests cover reconstruction; integration tests
use the real owned migration runner and PostgreSQL. Their parent-table fixture
does not replace eventual full-kernel/reference composition evidence.

**Can this adapter issue or authenticate sessions?** Not yet. Reads reconstruct
structural data only. Final proof consumption and effects must use the sole
identity PostgreSQL coordinator; no private issuance transaction is supplied.

**Can a revoked session become active on reload?** No: retained record and family
tombstones are returned explicitly. Reading them never alters state or authority.

**Can a deployment change remember-me defaults for existing sessions?** No:
reconstruction retains all resolved durations and rejects values needing new
defaults or clamping.

See `CHANGELOG.md`. Complete mutation, coverage, API/catalog, clean-consumer,
kernel/reference composition and release gates remain pending.
