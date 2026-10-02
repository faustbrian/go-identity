# Identity PostgreSQL

Experimental Go 1.27 module implementing `identity.UserQueryRepository` using
the owned `go-postgres` pool. Tenant and user IDs are matched exactly; lifecycle
states and the full uint64 version range are preserved. Reads are primary-only,
bounded and uncached. Configure primary endpoints explicitly.

Construct with `NewRepository(pool, Config{MaximumDuration: time.Second})`, then
compose it through `identity.NewUserQueryService` for policy and redaction.
The caller owns pool shutdown. No globals or background goroutines are created.
Driver errors are discarded rather than exposed through `errors.As` or logs.
Cancellation and deadline classifications remain observable.

## Current development boundary

`MigrationSource{}` owns `identity.users` with `tenant_id`, `user_id`, `status`
and `version`. Compose the source with the existing `go-migrations/v3` Runner
and PostgreSQL backend before constructing the repository. The source creates
no private ledger or migration runner. Initial install requires an unoccupied
`identity` schema and runs atomically. Replayed migrations preserve populated
data; destructive downgrade is unsupported. Future changes append history.

It is not yet an adoptable complete durable identity adapter. Do not
write application-owned identity tables or transactions to bridge that gap.
Commands, snapshots, attributes, imports, lifecycle cascades, audit/outbox,
reconciliation and the shared transaction coordinator remain unfinished.

The appended command-claim migration installs the global ID claim and scoped
journal foundation. Private admission runs inside the future Coordinator's
transaction, never commits independently, and does not grant mutation authority.
Exact replay selects the stored fingerprint-key version; missing retained keys
or missing scoped rows fail closed. Retired IDs conflict permanently. The owned
full journal state/result fields, participant plans, leases, retirement policy
and recovery still require implementation.

The private codec maps all seven current core command variants, including
account link/unlink and all identifier actions, through typed accessors. It uses the closed
`identity-command-v1` deterministic encoding profile, framed HMAC-SHA-256
digests for all private fields, and stored-key regeneration on rotated-key
replay. Directory IDs retain their exact validated representation, including
ULIDs; random command IDs become fixed-width byte strings. Attribute times
must be microsecond-exact within PostgreSQL years 1..9999; no rounding is
performed. Equivalent whole-field replacement ordering does not change intent,
but list ordering does. No raw command, name, image or attribute value enters
persisted collision fields. Invalid command values fail closed.
Provider subjects/issuers, identifier values and the complete authenticated
capability authority are represented by framed keyed digests. Capability owns
its canonical payload representation; the adapter never JSON-serializes core
commands or consumes a proof during encoding. Proof header/key metadata, all
version fences, link modes, credential references, provider-revocation choice
and session/pre-auth continuations are included. A changed authenticated proof
is changed intent, not an implicit recovery credential. The claim phase does
not yet reserve or finalize proof use with a domain mutation.
The encoder follows [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949.html);
full protocol interoperability and release evidence remain pending.

The third forward migration extends the existing command journal with private
pending ownership, positive generation/attempt counters and database-time lease,
heartbeat and creation/update fields. Matching live reservations return bounded
retry delays; expired reservations acquire a new generation inside their caller's
transaction. Heartbeats cannot renew expired or stale ownership. A takeover is
not public apply authority: all declared participants must still be rebound in
that same transaction before the future Coordinator can commit it. No private
helper owns commit/rollback or infers a terminal result from lease expiry.
Foundation-only rows keep NULL ownership metadata and remain readable by older
claim code; the new reservation path rejects them until authoritative recovery
can prove their history. This migration does not fabricate ownership, classify
them as aborted or enable terminal rows without complete safe receipts.

The fourth migration enables committed/aborted rows only with a positive
supported receipt version, bounded body, database terminal time and closed
classification. Private terminalization locks and rechecks live generation and
owner; it never commits independently. Exact replay returns the original typed
receipt, not current user authority. Core `CommandResult.Validate` owns receipt
invariants; the private version-1 JSON storage representation rejects unknown
fields, duplicates, alternate spelling, lossy values and trailing input by
requiring exact re-encoding. JSON is not used for command fingerprints.
Retained attribute instants are encoded from an owned UTC copy and must be
microsecond-exact within PostgreSQL UTC years 1..9999. Second-offset time zones
cannot lose offset seconds in JSON, and caller-owned receipt values are untouched.
Receipts may retain authorized profile/attribute snapshots and private identifier
intent digests; treat this restricted replay storage as identity data under
retention/access policy, never logs, metrics or transport responses. Encoding
validates bounded core values before allocation; decode rejects bodies over
8 MiB. Required audit/participant staging and public scoped recovery are not yet
implemented, so private terminal SQL is not a conforming composed mutation API.

### Domain begin admission

Private domain-begin admission now revalidates the retained-key global claim,
locks the scoped pending journal and verifies generation, owner and lease using
database time read after lock waits. A key rotation with the retained original
key preserves admission; changed intent, stale/foreign/expired ownership and
terminal rows never become apply authority. Missing history or keys fails
closed. The future Coordinator owns rollback on every failure and bounds Work
by the remaining lease; this private snapshot neither renews validity nor
begins/commits/rolls back a transaction or invokes participants. Public Work
and complete Begin orchestration are still unavailable.

### Contributor registration

Contributor identities can now be composed with
`NewContributorRegistry([]Contributor{...})`. The registry snapshots 1..64
trusted compile-time adapter descriptors once, preserves composition order,
rejects nil/typed-nil, duplicate contract IDs and conflicting versions, and
allows only exact registered descriptors in private command admission. Owners
are bounded lowercase printable ASCII; contract IDs are bounded printable ASCII;
neither admits whitespace or normalization. Composition roots own canonical
IDs and contributor lifetimes. Returned `Descriptors()` slices are caller-owned
copies and registry reads are concurrent-safe. Implementations remain open to
independent modules. This is identity admission only: no transaction phase,
typed participant input, Work, Coordinator, late registration or commit API is
provided. Unsupported phase combinations and foreign plan rejection remain
part of the forthcoming complete Coordinator, not guarantees of this constructor.

### FAQ

- Can I use a replica? No; the repository's primary consistency contract is
  required for security composition.
- Are reads authorization? No; use the identity query service.
- Can I request extra fields? Only `id`, `tenant_id`, `status` and `version`
  are supported; unknown or duplicate fields are rejected, not ignored.
- Is the pool closed by the adapter? No; the application retains ownership.
- Is this released? No. Full adapter implementation and release gates remain pending.

## Integration testing

`go test -tags integration ./...` requires `IDENTITY_POSTGRES_TEST_DSN` pointing
to an explicitly disposable loopback PostgreSQL cluster with database
`identity_test` and database-creation permission. Each invocation creates and
removes its own random database; it never drops the supplied seed database.
Missing infrastructure fails the selected lane rather than skipping it.

PostgreSQL `numeric` with scale/range checks preserves all uint64 versions and
rejects fractional values; a scale-constrained type would round before checks.
See [PostgreSQL numeric semantics](https://www.postgresql.org/docs/18/datatype-numeric.html).
