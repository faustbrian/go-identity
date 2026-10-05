# PostgreSQL session storage

Experimental Go 1.27 durable adapter. Forward-only migrations and bounded
primary `Get`/digest `Lookup` reads preserve complete native session records,
resolved lifetime limits, original nanosecond timelines, full uint64 authority
versions and revocation tombstones. Native family revocation now participates
in the sole identity PostgreSQL coordinator. Explicitly configured native
authenticated issuance now checks current owners and atomically stages records
and original proof use. Owned authenticated cookie issuance now composes real
audit/outbox effects with the core's commit-gated token custody.
**General bearer issuance, browser-container policy,
rotation, cleanup, devices and complete session profiles remain unfinished.
Single-factor stateful opaque validation now has owned primary composition;
this is not yet a complete login service.**

## Single-session native revocation

The explicitly configured `NewRepositoryWithIssueAdmission` contributor also
supports the closed `session.NewRevokeOneCommand` variant. Install the additive
`RevokeOneMigrationSource` at a permanent version after the family history,
merging it with issuance and kernel migrations in the existing single history.
It does not rewrite historical SQL or populated session records.

Mapping retains the complete original record, policy and authority vector.
The sole coordinator checks the exact registered invocation; the adapter locks
current directory, credential, authorization, target and family state before
mutating only the target. The physical record/version remains its original
snapshot; `session_revocations` retains the terminal version successor and
command binding independently of payload cleanup. Audit and lifecycle effects
share that transaction. Missing infrastructure and ambiguous/corrupt recovery
evidence never prove noncommit or authorize another transition.

This currently supports active single-factor self-service targets with the
configured owner profile, not anonymous/factor/passkey or administrative
variants. Construction and structural mapping do not authenticate a caller:
the owned public revocation service must still supply opaque current caller
admission and policy before reservation. Public idempotent signout and revoked
or expired-target management remain required work. No bearer is issued here.

## Owned stateful authentication

`NewSessionService(pool, SessionServiceConfig{Repository: ..., Profile: ...,
Validation: ...})` returns the core service with the owned primary reader.
Select `session.StorageStatefulOpaque`, audience, retained digest keys, trusted
clock and explicit bounded read/clock budgets. The profile is the same trusted
single-factor deployment/method/credential-owner profile as native admission.
Repository's budget cannot exceed validation's. Construction has no IO.

`Get` performs exact tenant/digest lookup across at most four retained key
versions and denies ambiguity. It checks live session/family tombstones, exact
owner-derived scope keys, directory status/epochs, user security and identifier
epochs, exact credential ID/kind/owner/version/expiry and current authorization
epoch through public owner APIs. It never substitutes aggregate CAS versions,
original authentication metadata or a stored record for current authority.
Identifier projection uses its owner's finite 128-record bound; incomplete or
corrupt owner state denies rather than becoming a partial positive result.

The earliest read-start sample precedes token lookup. Evidence lasts at most
20 seconds from that sample, capped by credential and session expiry and the
core uncertainty deduction. Copies and delayed responses do not renew it.
Missing infrastructure fails closed; there is no stale cache fallback.
Authentication does not grant authorization, update activity, refresh a token,
consume a proof or perform any durable mutation. Reuse requires the core
result's private-custody `ValidateAt` with trusted current time.

Apply kernel directory/status/identifier/credential, authorization-authority
and session migrations first; this constructor does not bootstrap them.
Borrow the primary pool until all calls finish. The service starts no
goroutines and supports concurrent calls. Organization, factor, passkey and
anonymous profiles explicitly deny until their separate owners compose.
Browser credential extraction, CSRF and container policy remain HTTP/core
responsibilities. Full native rotation, remaining profiles and release gates
remain pending.

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
declares `identity.session.revoke-family`; the default constructor does not
register issuance.

## Protected native issuance

`NewRepositoryWithIssueAdmission(pool, config, IssueAdmissionConfig{...})`
freezes a trusted single-factor self-service profile: deployment authority,
authorization namespace, audience, authentication method and credential
kind/owner. Configure the coordinator's trusted final-authentication authority
and namespace separately. Neither profile comes from request input.
Organization, factor and passkey profiles deny until their native owners are
composed; no applicable authority is dropped from the original record.

Compose `IssueMigrationSource{Base: RevocationMigrationSource{...}, Version: ...}`
with kernel proof-use, directory, status/credential and authorization-authority
migrations in one ordered permanent history. Issuance evidence survives session
payload cleanup and cannot be silently pruned during command reconciliation.

Map the closed `session.SessionCommand` with `MapCommand`, then use the
coordinator's `PrepareAuthenticatedCommandPlan`/`ReserveAuthenticatedCommand`
with the same original opaque final-authentication proof. Ordinary reservation
rejects issuance even when its structural command is valid. The adapter compares
every original proof field and complete snapshot, locks current native owners,
preserves original family issuance time and denies absent/stale/revoked families.
A genuinely new family requires version1; concurrent uniqueness waits cannot
overwrite a retained family or reset its authority. The same Work persists
family, session, proof use, native issuance evidence, audit and lifecycle.
Final comparison includes the complete stored session and primary expiry.

No raw bearer is generated, stored or returned by these adapter methods.
Replay returns retained command metadata, not another credential. This native
path is a prerequisite for the core issuer's reveal-once bearer custody and
container policy, not a replacement for that unfinished service. Integration
checks use the production session repository and real PostgreSQL; test-owned
audit/outbox contributors prove transaction atomicity, not complete production
delivery composition. Full coverage, mutation and release gates remain pending.

### Owned authenticated cookie issuance

`NewIssueExecutor(pool, IssueExecutorConfig{...})` owns composition of the native
repository, kernel coordinator and production audit/outbox contributors. Supply
the primary pool, `Repository` configuration, trusted `Profile`, retained
`Coordinator` keys/final-authentication namespace, existing `Authorization`
service, trusted `Clock`, `PolicyID`, positive `PolicyVersion` and
`AuditRetentionVersion`. Execution work uses the coordinator's 1ms..30s
maximum duration or any earlier caller deadline. Synchronous detached kernel
cleanup may outlive that deadline; each cleanup phase has its own bounded
coordinator budget, rather than one whole-call return deadline. Dependencies are
borrowed, immutable and concurrency-safe; construction performs no IO and
never runs migrations. Apply the kernel proof-use, directory/status/credential,
authorization-authority, native session/issuance, audit and generic/identity
outbox migrations first. Missing storage fails closed.

Pass this executor to `session.NewSessionIssuer` with the **same** trusted
authenticator, independent session digest key, explicit cookie policy, token
size and duration. The core generates and privately retains the original token
in `Prepare`; the adapter receives only its opaque `IssueRequest` and exact
digest-bound native record. Applications supply neither stores, transactions,
registries nor workflow orchestration. Current self-service identity and policy
are derived from the original authenticated command, not request-selected
decision attributes. Issuance currently supports the configured single-factor
profile; organization, factor, passkey and anonymous variants remain unavailable.

The executor checks current access before reservation. The native participant
checks all selected authority dimensions under the protected transaction before
effects and again before commit. Session, family, proof consumption, retained
issuance evidence, audit and lifecycle notification commit together. Core
delivery reveals the token only after a new exact committed result; cookie
attributes have an empty value until an explicitly authorized transport combines
them with that token. `ExecuteIssue` historical replay and `RecoverIssue` never
deliver credentials. Recovery compares complete original input and current
access, uses only the existing primary journal/recovery owner and cannot reserve
missing input, renew live leases or refresh original proof authority.

Retain the original safe request/proof for exact-input recovery and fingerprint
keys/policy versions while an outcome may require reconciliation. Never prepare
a new token to retry an uncertain command. After a process restart,
`RecoverIssueCommand(ctx, exactRecoveryQuery, trustedCurrentCaller)` returns
historical command metadata without original proof or token custody. Supply all
original safe scope fields and the independently authenticated current caller,
not request-selected actor/tenant overrides. Current policy governs disclosure.
Missing/denied commands are indistinguishable; recovery never reserves them.
Live pending remains observational; expired pending uses the kernel's frozen
participant reconciliation, and missing/conflicting evidence remains unresolved.
Successful reconciliation does not return a session or any bearer/cookie and
does not authorize retrying issuance. Structural
historical sessions are not current authentication evidence. Browser maximum
session/container policy, rotation, session authentication and complete login
composition remain required future work. Real PostgreSQL integration covers the
owned executor and production audit/outbox path, unlike the contributor-only
transaction fixture above. Full release coverage/mutation gates remain pending.

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
## Native privacy eligibility

`NewRepositoryWithPrivacyExportAdmission(pool, config, profile)` explicitly
opts the same store into `identitypostgres.PrivacyExportAdmissionContributor`.
Use trusted deployment, policy namespace, audience and method/kind/owner fields
as for identifier eligibility below. Existing constructors remain opted out of
privacy; this constructor does not enable identifier admission.

`CheckPrivacyExport` reads only the exact selected live invocation. It derives
all applicable primary owner keys from the original session and compares the
request's expected **user security authority version**, not the identifier or
aggregate identity version. Initial and final checks keep the same original
session, credential linkage and authority versions; privacy allocation cannot
refresh them. Directory, user/credential and authorization checks precede the
complete session/family share locks and primary-time expiry check. There is no
pool fallback, independent transaction, write, bearer issuance or policy engine.

The current native profile denies organization, factor and passkey applicability
rather than omit their owners. Complete multi-owner platform support is still
required. Eligibility alone is not fresh reauthentication, one-time proof
consumption or queued export admission. Public privacy execution remains closed
until native proof, all contributor cuts, effects and recovery are composed.

# Native identifier eligibility

`NewRepositoryWithIdentifierAdmission` explicitly enables the same repository
as `identitypostgres.IdentifierAdmissionContributor`. Existing `NewRepository`
remains opted out. Register the same instance for the store descriptor and the
plan's separate read-only role; do not register a second duplicate store owner.
The constructor accepts only the primary pool, existing schema/read budget and
trusted deployment/authorization/audience/credential profile, never Work,
coordinator, registry, callbacks or an application-written domain store.

`Repository.CheckIdentifier` can run only under the selected live coordinator
invocation. It reads the exact command-bound session ID/version, checks every
required scope key, then uses the existing global/tenant, user/credential and
authorization owners before locking and rechecking the exact session/family
record and primary-clock expiry. Owner locks remain until the original Work
closes. Session projection reads acquire no locks before those owners; the
complete post-lock comparison rejects intervening changes. No replica,
autocommit fallback, independent transaction or network callback is used.

Initial comparison uses the original snapshot. Final comparison changes only
the identifier epoch supplied by the kernel's exact Work-owned mutation receipt;
the stored snapshot, credential ID/version, original proof metadata, issued time
and accepted activity stay unchanged. Reading a record does not authenticate its
bearer or manufacture fresh reauthentication. This eligibility check is not a
policy Allow, one-time proof consumption or complete workflow authorization.
Public protected identifier execution remains disabled pending those phases and
durable recovery composition.

`SessionAuthorityKeys` uses visible-ASCII canonical IDs under the session
owner's existing profile. Family keys bind tenant/user/family; session keys add
session ID. Versioned, length-framed SHA-256/base64url avoids delimiter aliases.
Compare these keys together with `identitypostgres.KernelAuthorityKeys` and
authorization's `AuthorityScope.Key`. Keys contain no versions or positive
validity evidence and must not be logged. Historical custom keys are rejected
by this profile, never silently transformed or adopted from a newer epoch.

Configure the exact authentication method and credential kind/owner used by the
issuer. Currently only single-factor sessions without organization/factor/
passkey applicability are eligible. Anonymous, multifactor and passkey-owned
sessions deny even if optional dimensions were omitted. Present unsupported
dimensions also deny; they are not skipped. Full support remains required in
the platform and needs the actual corresponding owners, not a configuration
override. Zero/malformed profile and missing pool/configuration are InvalidInput;
foreign, stale, revoked and unsupported sessions deny uniformly as Forbidden;
corrupt storage and unavailable primary reads are redacted Unavailable. Earlier
caller/Work deadlines win, and cancellation/deadline classifications remain.
