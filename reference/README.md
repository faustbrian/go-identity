# Identity reference composition

**Development checkpoint:** this module currently implements only the
PostgreSQL-journaled, TLS Valkey velocity store graph and optional native OTP
Send/delivery composition with opt-in single-factor OTP sign-in. An IO-free
`NewServer` now exposes exact health/readiness probes and opt-in original-flow
HTTP initiation and selected email OTP Send/signin/recovery over that same graph.
Optional `PasswordReset` composes the native public request/completion/recovery
service with graph-owned risk and encrypted delivery; `HTTPPasswordReset`
selects its two routes using the existing signed-device and primary rate owners.
The selected PostgreSQL/TLS-Valkey integration journey proves reset delivery,
completion, predecessor-session revocation, old-password rejection and usable
replacement-password login. Full release and remaining reset failure-path
qualification are not complete.
Fresh dependency readiness is available for this selected graph; remaining
HTTP features and complete identity journeys remain unimplemented. Selected-module
migration Check/Plan/Apply and durable native command resume are available as
explicit store operations, not automatic startup behavior.

Reset currently requires the selected OTP/delivery graph and uses one of its
configured session schemas. Supply `PasswordResetConfiguration.Native` with
the native password profile, HIBP/password policy, issuer custody, current
authorization and explicit bounded callbacks; leave its risk evaluation and
request delivery owner/renderer unset so composition supplies the existing
owners. After explicit initialization, `features.PasswordReset()` returns the
public workflow port. Calls before initialization, after closure or outside
configured tenants deny. HTTP remains independently opt-in and requires the
existing `HTTPPreAuth.Device` and `HTTPRate` selections. Disabled reset HTTP
exports neither routes nor operation metadata.

The native reset integration uses the owned observed HIBP checker and signal
provider with the native PostgreSQL audit adapter,
with only fixed-endpoint HTTPS response IO substituted by synthetic fixtures.
It proves prefix-only padded requests and denial before protected effects for
breaches, malformed responses, outages and redirects; a zero-count padding row
permits the clean replacement. Replay performs no additional provider request.
Select `Native.CollectReset` with `Native.Screening.Collect` nil for attributed
screening. Its original binding and authenticated issuer challenge supply audit
identity without transport reconstruction or a fabricated attempt. Required
query/match/rejection records are checked in native storage. Synthetic lost
acknowledgement denies even a clean candidate; unchanged records reconcile
idempotently without screening again. This is consumer integration evidence,
not live provider interoperability, real audit transport-disconnect qualification
or a durable audit-outage backlog. A host selecting a different failure policy
must retain original records through the existing audit protocol, not invent a
second identity journal or silently accept undelivered required events.

`PasswordSignin` independently selects the native password login/recovery port,
available as `features.PasswordSignin()`. Supply `PasswordSigninConfiguration.Native`
with the native verifier, signing/flow/session keys and exact password original-
flow profile; leave `Native.Risk.Evaluation` zero for graph-owned counted risk.
Query/admission policy and revision must match this graph's authorization owner.
The current composition requires OTP's selected consuming session storage base,
but does not authenticate using OTP or accept its different original-flow action.
Startup, tenant and shutdown guards apply equally to login and recovery. No
password signin route is implicitly enabled. Native password material has one
independent migration history shared with reset; selected signin additionally
installs the native session-issuance purpose extension without rewriting either
workflow's existing history. The native integration journey authenticates an
existing session before reset and denies that same bearer afterward, then proves
replacement-password login. Its original password-flow setup is an explicit
native fixture: the current HTTP initiation profile remains OTP-specific, and
password-flow HTTP initiation/signin routes remain separate composition work.

Use selected-owner Check/Plan/Apply for reset installation, rather than only
the legacy shared `MigrationSource()`. Independent native histories install
kernel replacement/reset effects, password material, factor authority,
capability provenance and session reset effects without changing the installed
shared prefix. HTTP completion additionally selects native atomic rate receipts.
Pending kernel prerequisites must be explicitly selected; installed compatible
prerequisites are reused. Existing accounts are not implicitly assigned empty
factor authority: unreconciled authority continues to fail closed.

## Quick start

Supply a caller-owned `go-postgres` pool and one
`VelocityStoreConfiguration`, then construct the sealed graph:

```go
func compose(pool *postgres.Pool, velocity reference.VelocityStoreConfiguration) (reference.StoreSet, error) {
    return reference.ComposeStores(
        reference.StoreConfiguration{Velocity: velocity},
        reference.ReferenceDependencies{PostgreSQL: pool},
    )
}
```

The named modules are `github.com/faustbrian/go-postgres` and
`github.com/faustbrian/go-identity/reference`. Configuration selects the schema,
unique tenant allowlist, positive primary/recovery timeouts, a lease at most one
minute, batch (1–1000; reference 100) and maximum records (1–100000). Recovery
timeout must be less than the lease. `Native` selects the deployment namespace,
stable replay secret, risk policy, complete retained digest-key history,
canonical `rediss://DNS:port` endpoint, TLS name/preferences, explicit PEM trust,
opaque copied credential, bounded native timeout/pool and `standalone` topology.
The primary receives those exact namespace/secret/policy/key values internally.

Construction performs no network IO or migration. Explicitly install the
returned `MigrationSource()` using the existing `go-migrations/v3` PostgreSQL
backend and runner before recovery. No private SQL runner or copied migration
history is provided. Kernel versions remain 1–9; reference velocity uses the
permanent allocation 1000–1011. Do not silently adopt a differently allocated
existing ledger. Prefer the explicit Check/Plan/Apply operations below for
complete selected-owner migration coordination.

Call `stores.RecoverVelocity(ctx, tenant)` explicitly. It returns no counter
store until the actual primary journal has a full hour of coverage, all original
terminal records are restored and acknowledged, and the exact native publication
is confirmed and activated by the primary. A fresh empty journal is **not**
healthy. After genuine warmup, another explicit recovery can establish the
covered cut. There is no automatic polling, health renewal or hidden retry.

Use the returned `risk.CounterStore` with `risk.NewCounterCoordinator`; the
owned store records durable intent before its single native mutation and
retains the original outcome through that exact primary receipt. Retain a known
committed result even if a later error denies positive admission. Pending or
unknown outcomes never permit redispatch.

Call `stores.Close(ctx)` to cancel and join recovery and close owned native
connections. Close the caller-owned primary pool separately, after its users
have finished. No handler, health/readiness endpoint or background worker is
created by this development slice.

Successful recovery also retains that exact counter owner for the forthcoming
feature-composition path. Its internal deferred connection rejects requests
before recovery, during a new recovery generation and after shutdown. A failed
new generation cannot fall back to the previous activation. Routing adds no
retry or renewal and preserves the native owner's original outcome declaration.
The optional OTP profile uses this connection internally; it does not accept a
caller-written risk evaluator or counter store.

## Optional OTP Send composition

### Optional HTTP rate storage

`StoreConfiguration.HTTPRate` selects one native strict PostgreSQL backend and
the HTTP owner's fixed authentication/delivery policies. Supply a namespace,
nonzero 32-byte identifier key and explicit duration bounds: each of maximum
duration, timeout, lock timeout and rollback timeout is 1ms–2s; timeout must not
exceed maximum duration, and lock/rollback must not exceed timeout. Configure
the caller pool with `search_path=public`: the native adapter owns unqualified
SQL and cannot safely share an ambiguous search path. Callbacks that change
connection search paths violate this deployment requirement.

Construction freezes configuration without database IO or schema installation.
Check/Plan/Apply includes the native version-one migration in the independent
`identity_http_rate` history; `MigrationSource()`'s existing shared prefix is
unchanged. Nil selects neither the backend nor its migration. Graph shutdown
permanently denies later admission but leaves the caller pool owned by the
caller. This prerequisite does not by itself prove HTTP readiness or a complete
browser-login journey.

### Selected server construction

After `ComposeStores`, `ComposeProviders`, `ComposeWorkers` and
`ComposeFeatures`, call `NewServer(config, dependencies, features)` with the
same caller-owned PostgreSQL pool. Construction performs no IO, callbacks,
migrations, startup or goroutine creation. Supply the exact complete upstream
`identity.PolicySet`: authorization must be the same comparable service handle
bound into the graph, and all four identity callbacks are required. No member
is replaced or defaulted. For noncomparable service implementations, supply a
pointer handle consistently to both configuration stages.

The current profile accepts only `PostgresWithValkey`, explicit transport
limits/hosts, a non-nil bounded tenant resolver, and disabled bootstrap and
startup migration application. Migration lock timeout is 1ms–5m and command
retention 1h–87600h; worker concurrency is 1–1024, lease/drain bounds 1s–1h.
Enabled provider entries are rejected until their native selection is composed,
rather than silently omitted. The required PostgreSQL-only deployment profile
and complete worker/server lifecycle remain future implementation work.

`StoreConfiguration.HTTPPreAuth` opts into `/v1/session/preauth-issue` and its
OpenAPI operation. It requires selected OTP original-flow issuance and
`HTTPRate`; nil contributes neither route nor metadata. Supply the shared
eventual-session lifetime policy; optional browser-device configuration selects
the existing non-authenticating correlation codec. Native issuer configuration
owns origin, cookie, callback, action and policy. No application handler, rate
backend or domain-store override is accepted.
Selected HTTP initiation requires the canonical five-minute `OTP.PreAuth.FlowTTL`;
other lifetimes are rejected during composition, before rate admission or native
preparation. Direct native issuance retains its existing 1–10-minute profile.

`StoreConfiguration.HTTPEmailSignin` selects `/v1/otp/send`, `/v1/otp/signin`
and `/v1/otp/signin/recover` with their native OpenAPI operations. Nil exposes
none of these routes or metadata. Selection requires `OTP.Signin`,
`HTTPPreAuth` with its dedicated browser-device profile, and `HTTPRate`.
Supply email-owned address normalization plus trusted actor, policy revision
and target. Send and signin query policies must share the same authorization
handle and revision; the native issuer owns session cookie and audience.
Network JSON limits must admit at least 44 fields, including digest array
elements in the recovery envelope, and nesting depth at least 3; smaller limits
fail construction. Use explicit bounded body and decoded sizes.
No application handlers, stores or workflow callbacks supply these operations.
Recovery returns the historical committed outcome, never another session
cookie or CSRF credential. The selected HTTPS integration exercises initiation,
Send/replay, native delivery, consuming signin and recovery against PostgreSQL
and TLS Valkey; it is not full-platform or positive-readiness evidence.

The tenant resolver runs synchronously with a bounded request context after
trusted network resolution and before a workflow. Its nonempty result must
equal the tenant bound to the exact configured host; errors, panics,
cancellation, missing tenants and conflicts deny without credentials or raw
callback errors. Resolvers must honor cancellation and be concurrency-safe.
The router freezes host policy and OpenAPI metadata at construction.

`Handler()` returns the owned standard-library handler. `OpenAPI()` exposes
detached native document snapshots. Only `GET /healthz` and `GET /readyz` are
probes; no `/v1` aliases exist. Health is process liveness, not store readiness.
Readiness denies before initialization, during recovery and after closure. Each
bounded observation checks every selected native migration owner and the current
original PostgreSQL journal/TLS Valkey custody for every configured tenant.
Missing or incompatible schema, unavailable stores and expired ownership deny.
Probes do not debit counters, repair state, renew leases or refresh evidence.
A successful probe is a momentary observation of this selected graph, not
permission to bypass credential checks or proof of full-platform readiness.
Healthy velocity recovery requires historical coverage of the maximum configured
window; a fresh journal cannot skip that warmup. Recovery remains explicit when
original ownership expires. Readiness does not run it automatically.
Initialize features and deploy migrations explicitly; graph closure prevents
later workflow admission without taking ownership of the caller pool.
This constructor is not a completed login/reference-server milestone.

### OTP and delivery selection

Select both `StoreConfiguration.OTP` and `StoreConfiguration.Delivery`, with
deployment envelope keys and a bounded sender in `ReferenceDependencies`.
The delivery profile must enable state tracking and use production policies.
Risk uses the velocity graph's exact policy and retained keys. This checkpoint
supports velocity-only admission: required unsupported signals fail composition
rather than receiving permissive stand-ins.

Compose in order with `ComposeProviders(stores)`,
`ComposeWorkers(stores, providers, workerConfigs...)`, then
`ComposeFeatures(stores, providers, workers)`. These stages perform no network
IO and start no goroutines. Every selected tenant needs a real delivery worker
for the selected OTP provider version. All handles share the store lifetime;
foreign, reused or incomplete graphs are rejected.
All workers share the strictest retained sender-concurrency ceiling before
claiming. Dedicate the sender instance to this graph; unrelated graphs or direct
callers require their own shared capacity control.

Select `OTP.Signin` with the native `otp/postgres.SigninConfig` to enable
`features.OTPSignin()`. Nil leaves the handle unavailable and contributes no
consuming migrations. Sign-in uses the existing Send owner, selected tenant
allowlist and store lifetime; it is unavailable before `features.Initialize`
and after store shutdown. No route, worker or listener is started implicitly.
The sign-in profile must use the same global authority and user policy namespace
as Send and requires its pre-auth session configuration. Its bounded policy
must authoritatively deny single-factor issuance when MFA is required; this
profile does not implement MFA continuation.

Use the public `otp.SigninService` with original Send possession and challenge
code. Successful new commitment returns the session credential and CSRF token
once. Preserve its recovery handle for `RecoverSignin`, including ambiguous
outcomes; recovery returns original history without redelivering credentials.
The native adapter owns atomic challenge/pre-auth consumption, session issuance,
audit and lifecycle effects. Consumers supply configuration and bounded policy,
not domain workflow callbacks or stores.

Selected OTP signin also exposes `features.OTPSigninSource()` for code-free
original identifier discovery through that same native owner. Supply original
Send/pre-auth possession and trusted caller; current primary policy and recipient
are checked without an attempt debit or session effect. Use the sensitive
projection only for trusted transport rate admission, never client output or
login authority. Startup, tenant and shutdown guards apply to retained readers.

Select `OTP.PreAuth` to obtain `features.PreAuth()` for original flow initiation.
Its fixed deployment origin/callback/service actor and retained cookie key
version are explicit configuration; action, policy and native namespace are
derived from the same OTP owner. Resolve the shared `session.RememberPolicy`
before `Prepare(ctx, input)`, retain the preparation's unchanged `Command`, then
call `Issue`. Only a fresh successful commitment delivers a reveal-once token
and credential-free secure cookie metadata. Recovery returns historical outcome,
never another token or renewed lifetime. The graph must be initialized; unknown
tenants and closed graphs deny. No SQL, workflow callback or HTTP route is
consumer-owned. Nil leaves initiation absent. Compose transport separately.

The integration suite composes this selected handle with the public
`http/session.NewPreAuthFeature` and `http.NewRouter` over real HTTPS. It checks
original committed PostgreSQL flow identity/timestamps, secure cookie custody,
startup/shutdown denial, and independently constructed HTTP owners sharing a
strict PostgreSQL IP budget. Its rate-schema installation and owner selector
are test fixtures, not a production reference constructor or migration
contributor. Final `NewServer` composition and the complete OTP browser login
journey remain pending.

Initiation adds the owner-produced version 1420 to the permanently named native
`identity_preauth` ledger, not the shared `MigrationSource`. Install through
the existing reference Check/Plan/Apply APIs selecting `identity/session/postgres`
after its shared prerequisites. The existing native global command/lock owner
coordinates both histories. This permits later sign-in selection without an
earlier pending gap. Module numeric versions summarize maxima; only compatible
status proves every participating history is complete. Plan step `FromVersion`
belongs to its `SourceDigest` history. Existing deployment histories are unchanged.

`StoreSet.MigrationSource()` preserves kernel 1–9 and risk 1000–1011 exactly.
Selecting OTP/delivery appends owner-produced kernel 1012–1018, OTP 1100–1103,
pre-auth session 1200–1201, distinct authenticated session 1210, delivery
1250–1254 and authorization authority 1300. Selected delivery cancellation uses
1255, receipt metadata uses 1256, authenticated receipt commands use 1257, and
reconciliation uses 1258–1260. Receipt metadata is included whenever receipt
tracking, authenticated receipts or reconciliation needs it; unselected
extensions remain absent. Consuming sign-in appends OTP 1400 and session
1411–1416, with 1410 only for a distinct sign-in session schema. Existing Send-only histories
remain unchanged. Shared session schemas reuse one base; OTP, session
and risk owners must otherwise use distinct schemas. Unselected profiles
contribute no schema. These are
new permanent reference allocations, not changes to applied history. Keep the
selected schemas, global authority and `OTP.BootstrapTenantIDs` unchanged after
apply; later tenant onboarding uses owned lifecycle APIs. Bootstrap tenants are
copied explicitly and are not inferred from velocity scopes. An empty set grants
no bootstrap tenant authority.

`stores.ReferenceMigrationCheck(ctx, ReferenceMigrationCheckRequest{Modules:
[]ModuleID{"identity/postgres", "identity/risk/postgres"}})` performs bounded
read-only discovery. It never prepares a ledger or acquires apply ownership.
Statuses contain current/required versions and compatible, required, dirty or
incompatible state. Only selected canonical IDs are accepted; caller current
versions are forbidden. Each requested owner's complete physical history is
validated. Missing records with owned objects, including empty schemas, are
unmanaged/incompatible rather than permission to baseline them.

Selected OTP/delivery also includes `identity/otp/postgres`,
`identity/session/postgres`, `identity/delivery/postgres`,
`authorization/postgres`, `audit/postgres`, `outbox/postgres` and
`outbox/postgres/identity`. The last three retain their original independent
histories in native namespaces `audit`, `outbox` and `identity_outbox`
(`public.golib_migrations_<namespace>`). Audit fresh-role preflight must share
its history's native `InstallFresh` transaction; existing role collisions are
not ownership proof or permission for adoption.

`stores.ReferenceMigrationPlan(ctx, ReferenceMigrationPlanRequest{Modules:
[]ModuleID{"identity/postgres", "identity/risk/postgres"}})` returns a detached
canonical plan without writes or apply locks. Modules contain sorted current
versions; steps retain native order and owner-local previous versions. A valid
zero-step plan has a nonzero digest; any error returns no usable plan. Pending
prerequisites must be explicitly selected, while completed prerequisites need
not be selected. In particular, the interleaved shared kernel/risk history
cannot be reordered or filtered into an invalid suffix. Lifecycle outbox
planning also discovers the root outbox prerequisite and rejects an unselected
pending root. Independent histories follow shared, audit, outbox, lifecycle
order; later unselected shared owners are not implicitly appended.

Plans bind whole participating native sources, ownership guards, audit fresh
preflight and persisted ledger metadata. V1 uses domain-separated SHA-256 with
big-endian uint64 numbers/counts, length-prefixed strings and fixed 32-byte
digests. No SQL, process identity or observation time is exposed. Returned
collections belong to the caller; mutation invalidates the digest and never
changes future results. Different ledgers are separately discovered snapshots,
not a global atomic snapshot. Apply rediscovers under ownership and
validate the complete value before writing, including no-op plans.

### Explicit operator Apply and recovery

Set `StoreConfiguration.Migrations` to a `MigrationApplyPolicy` containing
trusted deployment `TenantID`/`ActorID`, a stable nonzero 32-byte `LookupKey`,
and a positive `CleanupTimeout` at most one minute. `LockTimeout` defaults to
30 seconds, with explicit values from one second to five minutes. The velocity
profile's `PrimaryTimeout` also bounds the entire operation, including lock
acquisition; a longer lock budget cannot extend that outer deadline. Nil policy
keeps Apply disabled without affecting read-only Check/Plan. Do not expose the
operator policy or operation as an unauthenticated HTTP endpoint.

Supply the complete unchanged plan, globally unique command ID (16–128 ASCII
letters/digits/underscore/hyphen) and an owned `identity.IdempotencyKey`:

```go
result, err := stores.ReferenceMigrationApply(ctx,
    reference.ReferenceMigrationApplyRequest{
        CommandID: commandID, Plan: planned.Plan, IdempotencyKey: retryKey,
    })
```

One native advisory ownership interval and physical connection cover every
participating namespace. Before any command, ledger or schema write, Apply
checks all participating native histories, unowned-object guards and the exact
rebuilt plan, including self-consistent but truncated/reordered submissions.
Each native batch commits SQL, its original ledger rows and command attribution
together. Fresh audit preflight and its whole history share one transaction.
No migration SQL is copied or executed by a reference-owned runner.

Inspect `result.Result.State()` and the safe typed `MigrationError`; dirty,
incompatible, locked, pending and unknown are not success. Only `MigrationApplied`
proves complete current command attribution. `Receipts()` returns a detached
sorted contributor prefix; a no-op has no applied-step receipts. A later failure
does not erase earlier durable work, and a partial result is not a usable
readiness claim.

Persist the **original complete plan**, command ID and retry key in the operator
deployment workflow. Retry exactly those values to resume through a newly
constructed StoreSet. Native receipts—not matching schema or a clean external
suffix—are the sole progress authority. An ambiguous commit returns
`identity.UnknownCommitError` with that original command ID. An exact retry
reconciles authoritative native evidence under ownership before continuing;
an unavailable authority cannot prove success or rollback. Do not generate a
replacement command, infer completion from schema, advance the plan base or
delete unresolved command records. Records have no automatic expiration and
must be retained throughout the reconciliation window. Changing operator scope,
key or policy cannot rebind an old command. Retain the original policy during
recovery. Caller retry keys are never stored in plaintext.

Close cancels and drains active migration operations with finite independent
cleanup, without closing the borrowed PostgreSQL pool. Startup/readiness and
the complete ReferenceService/server facade remain unimplemented. These
operations alone do not make the reference profile deployable.

Once selected schemas exist, `features.Initialize(ctx)` registers native
metadata without warming risk or sending messages. Obtain the public Send
interface with `features.OTP()`. Calls before initialization, before valid risk
activation, for unselected tenants or after closure deny. Exact committed
receipts can replay through a reconstructed initialized graph without a fresh
counter debit; fresh requests still require activation. `workers.ProcessDeliveryOne`
performs one explicit bounded native step; callers supply scheduling, not a
replacement delivery workflow. Queue acceptance does not prove provider delivery.

Audit delivery fails closed. A lost decision gets one idempotent retry of its
original immutable event; durable audit-outage handoff remains unimplemented.
Authenticated-session parity, joint unknown-outcome recovery, complete operator
APIs and full reference acceptance remain outstanding.

## API reference

- `StoreConfiguration`: one immutable selected configuration input; copied at
  composition and never retained as caller-owned TLS/secret slices.
- `VelocityStoreConfiguration`: explicit transport, custody, scopes and
  traversal bounds. Zero does not select defaults.
- `ReferenceDependencies`: borrowed PostgreSQL and selected envelope/sender resources.
- `OTPSendConfiguration`, `DeliveryConfiguration`: explicit native workflow profiles.
- `ComposeStores`: the sole store construction entry point; validates without IO.
- `StoreSet`: sealed shared-lifetime result, not caller-constructible.
- `StoreSet.MigrationSource`: pure upstream-owned migration contributions.
- `StoreSet.ReferenceMigrationCheck`: authoritative read-only selected-owner
  compatibility, bounded by the store lifetime; no partial statuses on failure.
- `StoreSet.ReferenceMigrationPlan`: deterministic read-only plan with complete
  participating source/history binding; no usable plan on failure.
- `MigrationApplyPolicy`: explicit copied operator scope, keyed retry binding
  and finite ownership/cleanup policy. Nil disables Apply.
- `StoreSet.ReferenceMigrationApply`: exact original plan execution and native
  same-command reconciliation/resume, with immutable bounded receipts.
- `StoreSet.RecoverVelocity`: one bounded, fail-closed recovery/activation.
- `StoreSet.Close`: permanent cancellation and bounded joining; repeated calls
  are safe, and a deadline does not reopen ownership.
- `ComposeProviders`, `ComposeWorkers`, `ComposeFeatures`: one sealed selected graph.
- `FeatureSet.Initialize`, `FeatureSet.OTP`: explicit startup and public Send access.
- `WorkerSet.ProcessDeliveryOne`: one explicit native delivery step, without polling.

Formatting is redacted and JSON/text serialization is denied for composition
inputs and handles. See Go documentation for exact errors and lifetime semantics.

## Security and adoption tradeoffs

PostgreSQL is authoritative; Valkey is an ephemeral projection. Recovery never
debits a counter or creates mutation intents. It restores original values,
observations and absolute expiry, not refreshed windows. Live primary ownership,
unknown history, corruption, missing native custody, lost acknowledgements,
incomplete coverage or exhausted bounds grant no store. Later counter calls
recheck the exact original primary/native chain without resetting its expiry.
No SQL transaction spans native IO.

Tenant scopes are selected at deployment, not accepted dynamically from requests.
Only one in-flight recovery per selected tenant is permitted; different selected
tenants can proceed concurrently. The primary owns cross-process exclusion.
Local configuration and copied handles do not grant takeover authority.

This slice deliberately does not renew healthy leases or reconcile a foreign
owner's opaque live marker. Existing handles become unavailable at their
original activation expiry. Cross-process recovery, continuous workers and
additional deployment topologies remain release work. Do not treat this module
as a production-ready login service.

## FAQ

**Why doesn't an empty deployment immediately accept traffic?** It cannot prove
the previous maximum window contained no unresolved work. The authoritative
journal lifetime starts at real insertion time, never one hour in the past.

**Can I inject a journal, health checker or effect callback?** No. The concrete
owned adapters are constructed once with paired opaque authorities. Dependencies
contain deployment resources, not a consumer-written identity workflow.

**Does the historical-origin integration fixture prove fresh bootstrap?** No.
It tests joint mechanics conditioned on established coverage. Only the separate
actual one-hour lane can prove genuine fresh warmup.

## Verification and release notes

Integration tests require isolated loopback PostgreSQL and explicit native TLS
configuration. Apply/Plan/Check do not connect to Valkey; risk/OTP runtime tests
additionally require authenticated TLS Valkey. Missing fixture inputs fail.
The actual warmup test requires
`IDENTITY_REFERENCE_REAL_WARMUP=1` and a timeout exceeding one hour. No tests
contact existing application services. Exact coverage, mutation, interoperability,
clean-consumer and complete reference acceptance gates remain release requirements.
See [CHANGELOG.md](CHANGELOG.md).
