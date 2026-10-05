# PostgreSQL session storage

Experimental Go 1.27 durable adapter. Forward-only migrations and bounded
primary `Get`/digest `Lookup` reads preserve complete native session records,
resolved lifetime limits, original nanosecond timelines, full uint64 authority
versions and revocation tombstones. Native family revocation now participates
in the sole identity PostgreSQL coordinator. **Issuance, rotation, cleanup,
devices and online authority enforcement are not
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

To enable native revocation, use
`RevocationMigrationSource{Base: MigrationSource{Schema: "identity_session", Version: 10}, Version: 11}`
with an additional permanent version greater than the base in the same history. This
forward-only migration adds retained mutation bindings without changing the
original session install or live records. The original two-field
`MigrationSource` remains unchanged and returns only the read-only install.
Register the repository alongside the owned kernel, audit and outbox
contributors. Its descriptor is `identity.session.store` version 1 and it
declares only the implemented `identity.session.revoke-family` schema.

`MapCommand(session.NewRevokeFamilyCommand(...))` maps the closed native
command's complete expected-version intent. Prepare a native feature plan with
subject `session_family`, security action `identity.session.revoke`, lifecycle
`session_family.revoked.v1`, exact expected/successor versions and selected
standard (or privileged protected) retention. The coordinator checks registry,
budgets, digests and the native owner's mandatory declarations before reserving.
Only its `ApplyFeature` invokes the registered repository. Direct `Apply` on a
borrowed, foreign or returned Work fails; the constructor accepts no coordinator,
transaction or registry. Authorization belongs to the owning service, before
reservation. This trusted adapter is not a public revocation endpoint.

Revocation changes exactly one owned active family's tombstone and version,
never its sessions' original snapshots. Missing, stale, already-revoked and
foreign-owner targets return redacted conflict without disclosing foreign
existence. Exact same-command replay is handled before mutation by the sole
coordinator. Required audit/lifecycle effects and retained mutation evidence
commit with the transition. Errors require coordinator Abort; a failed commit
stays Unknown until primary recovery proves its original result. Recovery reads
retained exact command bindings, never infers success from current family state.
No adapter cleanup prunes those bindings; their journal FK prevents premature
command retirement. Retention/privacy retirement remains a later owned policy
boundary, not permission to treat pruned evidence as noncommit.

`Get(ctx, tenant, sessionID)` and `Lookup(ctx, tenant, session.TokenDigest)`
return a structural `StoredSession`. Both use one joined primary query and a
finite read budget. Earlier deadlines win; cancellation, deadline, absence and
unavailability are redacted. No SQL diagnostic or partial record escapes.

`RequireSession(ctx, work, Config{Schema: "identity_session", MaximumDuration:
time.Second}, frozenSession)` borrows the owning transaction's query cursor
(`identitypostgres.Work` or a trusted primary `pgx.Tx`). Freeze the exact original
session in the owning command before reservation. The native query compares
physical indexes, complete stored snapshot, authentication linkage and lifetime
without replacing any field. It requires active session/family state and exact
versions, takes share locks on both, and checks database time **after** acquiring
those locks. Earlier caller/Work deadlines win; rows close before return and
locks remain until the original coordinator commits or aborts.

This is only session-owned admission, not full session authentication. Native
participants must still check current global/tenant/user/identifier/credential,
authorization and every applicable organization/factor/passkey authority, plus
authentic proof and final temporal validity. Passing a pool/autocommit queryer
cannot prove protected admission. The owning native participant must fence
scope/lifetime and poison/abort Work on every failure, including ignored denial.
No bearer, authority lease, policy decision, refresh or new session is returned.
Missing/revoked/expired/unequal rows deny uniformly with `identity.ForbiddenError`;
invalid inputs and storage/corrupt rows retain redacted typed classifications.

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
Native revocation tests additionally compose the actual full kernel migrations,
populated session upgrade and real contributor/coordinator. Audit/outbox SQL
seams prove atomic rollback and visibility, not production adapter interoperability.

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
