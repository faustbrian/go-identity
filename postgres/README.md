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

The first read implementation expects `identity.users` with `tenant_id`,
`user_id`, `status` and `version`; owned migrations are the next implementation
step. It is not yet an adoptable complete durable identity adapter. Do not
write application-owned identity tables or transactions to bridge that gap.
Commands, snapshots, attributes, imports, lifecycle cascades, audit/outbox,
reconciliation and the shared transaction coordinator remain unfinished.

### FAQ

- Can I use a replica? No; the repository's primary consistency contract is
  required for security composition.
- Are reads authorization? No; use the identity query service.
- Can I request extra fields? Only `id`, `tenant_id`, `status` and `version`
  are supported; unknown or duplicate fields are rejected, not ignored.
- Is the pool closed by the adapter? No; the application retains ownership.
- Is this released? No. SQL integration and full release gates remain pending.
