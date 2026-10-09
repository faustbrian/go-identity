# Password PostgreSQL adapter

Development checkpoint: owned forward-only password material storage and a
consistent primary credential reader plus native existing-password material
replacement/recovery and native authenticated password change. Registration,
rehash, reset, history and deletion remain unimplemented.
There is deliberately no independent setter or application-written workflow.

## Original reauthentication records

Migration 3 adds immutable original signed password-verification storage, bound
to the original kernel command. `Repository.Reauthentication(ctx, proofID)`
implements `authentication.ReauthenticationSource` using a bounded primary-only
read. The globally unique proof ID supplies the lookup key; indexed tenant/user
must match the complete upstream record. Pending, aborted and absent commands
return `authentication.ErrInvalidProof`, never a provisional original.

Signature bytes, full-width versions and original nanosecond timestamps retain
their exact values. Closed canonical bytes reject duplicate/unknown fields,
foreign scope and corrupt or oversized payloads. No private signing key, raw
password, hash, session bearer or renewable validity lease belongs in this table.
The upstream authenticator owns configured evidence-key verification, exact-use
and freshness validation; this reader does not authenticate signatures or check
current credential/session authorities. An expired original remains historical
data, not renewed permission.

The native service below issues originals; password change consumes them in the
protected transaction. No independent writer, automatic cleanup, replay framework or application-written
proof store is introduced. Lifecycle/retention must be coordinated before this
profile is released; original records cannot be removed independently of their
command history. The native SQL fixtures prove retrieval and installed schema
constraints. One-use protected mutation remains separate from verification.

## Native password reauthentication

`NewReauthenticationService(pool, config)` composes the real password verifier,
primary session lookup, kernel coordinator, authorization engine, risk admission,
security audit and lifecycle outbox. Install their owned migration histories,
including password migration 3, before use. The configuration is trusted startup
input: select the password single-factor session profile, independent lookup,
identifier/risk and Ed25519 evidence keys, bounded verifier/dummy-hash policy,
current authorization/query policies and an exact target allowlist. The constructor
does no IO and never creates schema or starts background work.

`Verify(ctx, request)` accepts opaque source bearer/password custody, a trusted
tenant and human caller, trusted network/device provenance and an allowed target.
It derives the account abuse dimension rather than accepting a client-selected
digest. Authentication counting and audit precede real password comparison.
Wrong, blocked or changed credentials return a neutral result with no proof.
Protected execution locks and rechecks original directory, credential,
authorization, session/family and material authority through the sole kernel
transaction. The original signed proof, mandatory audit and lifecycle event
commit together. Verification neither extends the source session nor consumes
the proof. Unsupported organization, factor and source-method profiles deny.

The result's sole `authentication.ReauthenticationProof` is released only after
a new known commit and final freshness checks. TTL is positive and at most 15
minutes, capped by original session and credential lifetime. Destroy the caller's
password after the call. Never serialize or log requests, configuration, keys,
raw driver errors, bearer values or verifier material.

When an outcome is unknown, retain its server-generated command ID and use
`Recover(ctx, tenant, commandID, caller)` under current disclosure policy.
Recovery accepts no password/bearer and reports original outcomes without
reissuing proof, renewing freshness, recharging risk or retrying the mutation.
A failed protected transaction leaves no proof or lifecycle event; a known
rollback includes its required terminal failure audit. An audit outage can
prevent terminalization and therefore remains unknown rather than being called
successful or certainly aborted. Do not automatically resubmit the password.

The pool and callbacks remain caller-owned and must support concurrent use.
Earlier caller deadlines win; the service owns no goroutine or retry loop and
never closes the pool. This backend composition is not an HTTP endpoint or a
completed password-reset workflow. Retention, all-factor composition and
release qualification remain pending.

## Native authenticated password change

`NewPasswordChangeService(source, config)` borrows a configured native
reauthentication source and composes the upstream signed-proof validator, core
password screening/preparation and native protected counters. Install additive
password migration 4 and the selected risk counter migrations. In the source's
session namespace install the unchanged base history, then
`CSRFMigrationSource`, `OTPMigrationSource`,
`CredentialContinuationMigrationSource` and `PasswordChangeMigrationSource`
in permanent forward-only migration slots. Upgrade relevant session readers
before enabling continuation; older readers reject its stored profiles.
The source must
allow the exact purpose `identity.password.verify`, action
`identity.password.change` and configured audience. Select explicit HIBP policy,
bounded provider collection and the source's existing password primitive.

`Change(ctx, request)` accepts the original opaque bearer, original signed proof,
new owned password secret and trusted caller/network scope. It denies current
password reuse and rejects incorrect proof bindings. HIBP collection and hashing
run before SQL locks; original provider observations are checked again against
primary time without refreshing their timestamps or calling providers in Work.
The proof's original expiry and configured maximum age bound the remaining
operation. Destroy the caller's secret when the call returns.

The sole kernel transaction consumes the original proof exactly once, updates
password material and credential/user authority, and writes mandatory audit and
lifecycle outbox effects. Rollback restores proof availability and material;
the protected risk attempt is not refunded. Original signed record bytes remain
unchanged. Startup `SessionDisposition` selects preserve, revoke-other or
revoke-all; `MaximumSessions` limits the complete active-state set, not each page.
Zero values select **revoke-all**, including the source, and a cap of 100000.
Requests cannot override policy. The original command freezes the selection and
limit; exceeding the cap rolls back all effects, including proof consumption.

Preservation continues eligible single-factor password sessions against the
exact successor reference and credential epoch without changing historical
authentication, login freshness, activity/lifetime, remember policy, bearer
lookup, session/family versions or CSRF state. Stale/expired/family-denied
supported sessions revoke; an unsupported preservation profile denies the whole
transaction rather than manufacturing authority. Revoke-other keeps the source
and terminally revokes others; revoke-all also revokes the source. Fresh password
reauthentication over a continued bearer uses its effective credential version,
not the original login version. `AuthorityInvalidated` describes predecessor
credential authority, not revocation of every continued session.

Session effects and their original-command recovery evidence share the existing
password transaction; applications supply neither a session store nor a second
transaction. Retained evidence survives live session cleanup. Administrative/
reset replacement, history, other-factor preservation and complete lifecycle
qualification remain in development.

Retain the result's server-generated command ID. Unknown outcomes must be resolved
with `Recover(ctx, exactQuery, caller)`, not automatic password resubmission.
Recovery uses original committed effects under current disclosure policy and
accepts no password, bearer or provider callback. Positive successor/authority
results require a known commit. This is backend composition, not an HTTP endpoint
or full password lifecycle/release qualification.

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
endpoint**. Use the native service above for authenticated change; do not expose
this lower-level seam directly. Browser transport and the remaining password
lifecycle still need their owned composition. Do not provide application-written
stores or workflows to bridge those unfinished contracts.

## Native verification and remaining work

The integration lane requires a task-owned disposable loopback PostgreSQL 18.4
cluster and fails when absent; it never silently skips. It installs real kernel
and password histories and exercises the public core against the real reader.
Synthetic material is not provider/interoperability or migration-import proof.

Complete transactional lifecycle, schema-health/reference composition, populated
legacy migrations, backup/restore, exact coverage/mutation, production-shaped
benchmarks, clean consumer and release qualification remain pending.

See [CHANGELOG.md](CHANGELOG.md).
