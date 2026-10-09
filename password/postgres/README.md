# Password PostgreSQL adapter

Development checkpoint: owned forward-only password material storage and a
consistent primary credential reader plus native existing-password material
replacement/recovery. Registration, authenticated change composition, rehash,
reset, history and deletion remain unimplemented.
There is deliberately no independent setter or application-written workflow.

## Composition

1. Install the identity kernel and its credential-reference migration history.
2. Install `MigrationSource{}` through the owned `go-migrations/v3` Runner and
   PostgreSQL backend, using the permanent `identity_password` ledger namespace.
   Existing unmanaged schema objects fail rather than being adopted. History is
   forward-only; keep installed version 1 unchanged across upgrades. Version 2
   adds retained, hash-free replacement-effect bindings and supports populated
   version-1 upgrades. Install kernel `CredentialReplacementMigrationSource`
   before enabling the native replacement profile.
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

## Existing-password material replacement

Register this exact repository as the `identity/password/postgres` contributor
in the kernel coordinator. Its sole current `FeatureOperations` declaration is
the existing-password change storage profile, schema `password-change` version
1. Construct `identity.NewFeaturePasswordHashCommand` with the eight exact
`kernel.CredentialReplacementFields`, original binding and the already generated
verifier. Scalar hashes, hash-free commands and undeclared fields are rejected.
Select the original protected audit, credential subject and `password.changed.v1`
lifecycle with exact reference predecessor/successor. The existing outbox owner
must implement `kernel.CredentialReplacementLifecycleContributor` and persist
both staged lifecycle and the independently owned replacement successors.

The repository's pure `ValidateFeatureCommand`/`CredentialReplacement` methods
enforce the configured current issuance algorithm and selected work parameters.
`ApplyFeature` runs only during this exact instance's native coordinator
invocation, after the kernel has locked active user/reference authority. It
locks owned material, bounds transfer before allocation, checks the full-width
material/reference predecessor and parses existing material under legacy read
limits. One CAS changes version, exact verifier bytes, algorithm and monotonic
update time, then inserts original-command evidence in the same `Work`. It does
not write kernel tables, perform cryptographic work, invoke a policy callback,
begin/close a transaction or retry. Earlier deadlines win; cancellation survives.

Only the coordinator commits the provisional receipt together with kernel
versions, audit and outbox. Retained material effects complement its journal,
not a second success authority. Recovery matches original scope/transition;
missing effects prove native noncommit, while conflicting/missing infrastructure
is unknown. A later password replacement cannot erase the original effect or
receipt. Do not prune effects independently of command-owner retention, deletion
and legal-hold rules; that lifecycle remains pending.

This is a **trusted persistence seam, not an authenticated password-change
endpoint**. Reauthentication/proof consumption, HIBP/reuse, session invalidation,
durable generated-hash preparation and browser transport still need the real
password workflow composition. Do not provide application-written stores or
workflows to bridge those unfinished contracts.

## Native verification and remaining work

The integration lane requires a task-owned disposable loopback PostgreSQL 18.4
cluster and fails when absent; it never silently skips. It installs real kernel
and password histories and exercises the public core against the real reader.
Synthetic material is not provider/interoperability or migration-import proof.

Complete transactional lifecycle, schema-health/reference composition, populated
legacy migrations, backup/restore, exact coverage/mutation, production-shaped
benchmarks, clean consumer and release qualification remain pending.

See [CHANGELOG.md](CHANGELOG.md).
