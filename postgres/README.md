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
