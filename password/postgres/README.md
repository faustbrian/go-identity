# Password PostgreSQL adapter

Development checkpoint: owned forward-only password material storage and a
consistent primary credential reader. Coordinated registration, changes,
rehash, reset, history and deletion/recovery participants remain unimplemented.
There is deliberately no independent setter or application-written workflow.

## Composition

1. Install the identity kernel and its credential-reference migration history.
2. Install `MigrationSource{}` through the owned `go-migrations/v3` Runner and
   PostgreSQL backend, using the permanent `identity_password` ledger namespace.
   Existing unmanaged schema objects fail rather than being adopted. History is
   forward-only; keep version 1 unchanged across upgrades.
3. Construct the reader using an existing caller-owned **primary-only**
   `go-postgres.Pool` and the password owner's constructed primitive policy:

```go
reader, err := passwordpostgres.NewRepository(pool, passwordpostgres.Config{
    MaximumDuration: time.Second,
    HashPolicy: selectedPasswordPolicy,
})
if err != nil { return err }
// Supply reader as password.VerifierConfig.Repository.
```

The module is `github.com/faustbrian/go-identity/password/postgres` and package
name is `passwordpostgres`. Core verifier composition still requires an exact
current-policy dummy hash, explicit byte/time bounds and trusted clock.

## Ownership and security

- `ReadPasswordCredential` takes a trusted tenant and already canonicalized
  kernel account ID, without email/phone lookup or normalization.
- One SQL statement joins material, kernel reference, user status and the
  credential epoch. Material/reference versions must agree. Full uint64 values
  round-trip without narrowing; inactive eligibility is preserved, not restored.
- The exact encoded hash retains algorithm parameters. The primitive parses it
  under the selected owner's verification limits, including permitted legacy
  profiles; this adapter never hashes, verifies or chooses issuance policy.
- Hash transfer is bounded in SQL before client allocation. Missing scope is
  `password.ErrCredentialAbsent`; corruption, missing schema and storage failures
  are redacted `password.ErrPasswordWork`. Cancellation/deadline errors survive.
  Do not expose missing-credential classification through an enumeration-prone
  endpoint; the core verifier owns neutral comparison results.
- Returned `CredentialSnapshot` uses the core's opaque immutable custody. Its
  explicit hash projection is sensitive: never log it or raw driver errors.
- Reads neither cache nor create a proof/freshness lease, and perform no mutation,
  provider calls or network retries. Core comparison rechecks primary state; a
  protected command must still recheck authority and coordinate all effects.
- The repository owns no background work and never closes the borrowed pool.
  Keep it alive until calls finish. Each call derives its explicit bounded
  lifetime; earlier caller deadlines win. Zero repository/configuration denies.

The material table's tenant/account primary key supplies lookup and uniqueness;
its FK retains the kernel reference. No extra covering index or performance
improvement is claimed. Deletion needs the future coordinated participant rather
than an independent delete or cascading loss of credential state.

## Native verification and remaining work

The integration lane requires a task-owned disposable loopback PostgreSQL 18.4
cluster and fails when absent; it never silently skips. It installs real kernel
and password histories and exercises the public core against the real reader.
Synthetic material is not provider/interoperability or migration-import proof.

Complete transactional lifecycle, schema-health/reference composition, populated
legacy migrations, backup/restore, exact coverage/mutation, production-shaped
benchmarks, clean consumer and release qualification remain pending.

See [CHANGELOG.md](CHANGELOG.md).
