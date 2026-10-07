# Session

## Canonical pre-auth continuation

`PreAuthTransaction` freezes the original ID, tenant, action, exact origin,
callback/no-redirect choice, server nonce, selected policy, resolved remember
policy and original issued/exclusive-expiry times. General configured TTL is
1..10 minutes; reference initiation uses exactly five minutes. `Token.PreAuthDigest`
uses a dedicated named key and a separate complete-binding HMAC domain, never a
session-cookie lookup digest. Retain the original key while the flow is live;
copies and retries must not regenerate the binding, nonce, expiry or choice.

These are private structural values, not authentication or primary active-state
proof. `Check` requires authoritative time after locks and never consumes the
flow. Owned `PreAuthIssuer` freezes configured origin/redirect policy and the
`__Host-identity_flow` transport policy. Durable primary reservation/finalization
are available in PostgreSQL; complete OTP continuation registration with final
session issuance/linking remains under development. No caller-written store or
continuation-ID-only authority can substitute for that composition.

`PreAuthIssueCommand` and `PreAuthIssueExecutor` are storage-neutral native
initiation/recovery contracts. The server retains the same original private
record and command ID across retries; execution and restart recovery return
only historical command metadata, never a cookie or renewed authentication.
The PostgreSQL adapter owns atomic execution; core `PreAuthIssuer` owns original
server entropy and commit-gated reveal-once delivery metadata.

`PreAuthIssuanceExecutor` adds `PreAuthIssueExecution` for future commit-gated
delivery without changing the receipt-only interface. A committed receipt is
not sufficient: the issuer must also require `Replayed == false`, exact original
scope, no error/cancellation and an unexpired original flow. Only acquisition
of the sole execution reservation clears `Replayed`; restart recovery and
terminal observations never permit credential delivery. Formatting and implicit
JSON/text export of execution metadata redact or deny original custody.

### Owned original flow issuance

Compose `NewPreAuthIssuer(ownedExecutor, PreAuthIssuerConfig{...})` with the
owned PostgreSQL `NewPreAuthIssueExecutor`. Both configurations must select the
same exact trusted service actor, action, origin, callback (or empty for no
redirect), policy ID and version. Use a retained dedicated pre-auth digest key,
trusted clock, 1ms..30s execution budget, 32..64-byte token and validated
`__Host-identity_flow` Lax/Strict cookie policy. General flow TTL is 1..10 minutes;
the reference choice is five minutes. No callback allowlist, actor or policy may
be selected directly from client input. Core does not own a store or journal.

`Prepare(PreAuthPrepareInput{CommandID, TenantID, CorrelationID, Remember})`
accepts the already-resolved session choice and validates before generating the
canonical random flow ID, 32-byte nonce and cookie commitment. It performs no
durable work or authentication. Retain the returned preparation unchanged;
copies share a single local attempt. `Command()` exposes safe original custody
for recovery, never the bearer. Calling Prepare again is not a retry.

`Issue(ctx, prepared)` preserves earlier deadlines, executes the exact original
command, validates its complete receipt and returns a reveal-once `Token` plus
credential-free cookie attributes only on new commitment. Cookie expiry uses
whole remaining seconds rounded down within the original flow deadline for
**both** remember choices; a persistent final session never extends the
unauthenticated flow. HTTP explicitly reveals the token and sets Cookie.Value
only at delivery, without logging. HTTP still owns origin/CSRF checks, mixed or
duplicate cookie rejection, no-store response policy and opt-in routes.

Replay/recovery, errors, cancellation, malformed receipt, panic, expired flow
and subsecond remaining lifetime deliver no credential. Known commitment is
preserved when delivery fails. Unknown requires `Recover(ctx, originalCommand)`
under current service policy; it never reexecutes, returns flow payload, renews
time or delivers a credential, even after original expiry. A reconstructed
caller projection is not proof of the historical persisted payload.
This composition does not authenticate a user or complete a browser login.

Experimental Go 1.27 session policy module. This first batch implements shared
remember-policy resolution, lifetime evaluation, secure host-cookie attributes
and opaque token/key custody with tenant-bound lookups. Authenticated cookie
issuance orchestration is available through `SessionIssuer`; owned durable
executor composition is available in the PostgreSQL adapter. Stateful opaque
`SessionService.Get` validation is available against its trusted owned-reader
contract, with an owned primary reader and revocation executor in the PostgreSQL
adapter. Public self-signout is available through `SignOutService` and the
owned PostgreSQL factory. Authenticated `ListService` and its owned PostgreSQL
page-reader composition are available. Core fresh bulk-revocation orchestration
is available; native set mutation remains pending. **Rotation, complete revocation
services and transfers remain unfinished; this is not a usable login service.** Complete authority-vector
construction and exact comparison are available, but do not read primary
authority or prove activity/freshness.

Immutable complete session records and exact-bound native issue commands are
also available for trusted storage/adapters. They are **not** session issuance:
caller-created `authentication.Proof` metadata and `AuthenticationVerified`
cannot establish authentication authority. No command by itself executes
or opens a transaction, reserves a proof, writes a record or reveals a token.

## Quick start and API

### Encrypted companion-cookie caching

Compose `NewCookieCache(encryptedCodec, CookieCacheConfig{Credential:
originalCookiePolicy, Cache: companionCookiePolicy, MaximumCookieBytes: 3800})`.
Both policies must be validated `__Host-` host-only root-path policies with the
same explicit Lax/Strict choice and distinct names. Enable this composition
explicitly; absence disables it. The codec maximum age must be 1 second through
5 minutes. The entire emitted header, not just plaintext or binary ciphertext,
is bounded at 512..3800 bytes, including fixed `Priority=High`. Over-limit output
fails without truncation, chunking or weakening attributes.

`cache.Put(ctx, authenticGetResult)` accepts only original same-service cookie
admission, returning a redacted `CacheCookie`. Explicitly export its bounded
`HeaderValue()` for the owned HTTP transport. Browser-session remember choices
omit persistence; persistent cache cookies cannot exceed the original session
expiry or five minutes. Encryption latency never extends the cookie deadline.
This is a **companion** cookie, not the original credential: ciphertext alone
cannot authenticate and never upgrades a bearer result into cookie transport.

HTTP supplies `cache.Get(ctx, originalGetRequest, selectedCompanionValues)` with
zero or one exact configured cookie values. Duplicate companion values deny
before IO. Missing, corrupt, oversized or noncanonical values require primary
validation; the original credential must still match tenant, digest and cookie
transport. Positive authority retains its original exclusive deadline, including
when `Put` is called again on a warm result. A failed refresh after expiry never
uses stale authorization. No cache write is hidden inside Get.

`cache.Deletion()` emits the exact companion scope with negative Max-Age and a
past expiry; it neither deletes the original credential nor revokes authority.
Cookies/header values contain correlated ciphertext and must never be logged.
Formatting and implicit JSON/text export redact or deny. HTTP still owns origin,
CSRF, mixed original-credential rejection, no-store headers and opt-in routes.
Standard-library cookie/parser/jar behavior is tested; full browser-family,
reference-server and release acceptance remain pending. This composition does
not implement Valkey or the fully stateless profile. `NewSessionService` keeps
its existing stateful primary profile; opt in through this explicit composition.

### Bounded positive admission reuse

`primarySessions.CacheAdmission(authenticatedGetResult, maximumAge)` returns an
opaque `CachedAdmission` only for an unchanged live result minted by that exact
service. Age is 1ms..5m but positive reuse is clipped to the original Get
deadline (at most 20 seconds from its earliest authority read, conservatively
reduced for clock uncertainty and session expiry). The configured trusted clock
owns the cache observation. Copies and repeated promotion cannot renew either
the original deadline or a previously shortened age.

`primarySessions.GetCached(ctx, originalRequest, cachedAdmission)` accepts a
warm entry only for the exact service, tenant, bearer digest and transport. It
retains the complete original session/authority and authenticated-result
custody; cookie admission cannot be reused as bearer admission. A zero, stale,
foreign or substituted entry uses bounded primary Get. Failed refresh returns
no authentication, never stale fallback. Dropped invalidation events therefore
cannot extend the original positive-evidence window. Backward clocks and
caller cancellation deny; explicit invalidation may discard a handle earlier.

The handle owns no raw bearer, cache store, goroutine or invalidation journal.
It is process-local and cannot be JSON/text serialized. It is **not** a signed
or encrypted cookie, durable Valkey projection, stateless codec or new storage
profile; those implementations remain unfinished. Consumers must not turn
structural Session data or a public Authenticated flag into cache authority.
Authorization is still a separate current-policy decision on every action.

### Non-authoritative display enrichment

`NewEnrichmentService(callback, EnrichmentConfig{Schema: EnrichmentSchema{
Version: 1, FieldNames: []string{"label"}, MaxBytes: 1024},
MaximumDuration: time.Second, FailurePolicy: EnrichmentFail})` freezes a bounded
schema. The callback implements `SessionEnricher.Enrich(ctx, source, schema)` and
returns one UTF-8 string per declared field, in schema order. The complete
immutable session is the declared source; the callback must honor cancellation
and be safe for concurrent calls. Earlier caller deadlines win.

Call the service after independently authenticating and authorizing the source.
A structurally valid `Session` is not proof of current activity. Enrichment is
display-only: it never changes the principal, authority, authentication time or
session lifetime. Output is untrusted text; transport must escape it and select
exported fields explicitly. Implicit JSON and diagnostic export are denied.

Every invocation re-evaluates the complete source without caches, store locks,
transactions or background goroutines. Source changes cannot reuse a retained
projection. Do not cache output independently of its complete source and any
external inputs the callback reads. Cache-profile composition remains separate
unfinished work. Callbacks that ignore context cannot be forcibly interrupted;
the service does not leak detached goroutines to hide that contract violation.

`EnrichmentFail` returns a redacted error on callback failure.
`EnrichmentOmit` returns nil display values on callback error or panic only.
Cancellation/deadline and malformed successful output always return errors,
without partial display values. An empty individual field is valid; omission
is not a schema-shaped success. Returned slices and callback schema copies are
independently owned. Existing authentication and persistence APIs are unchanged.

### Commit-gated session rotation

`NewSessionRotator(primarySessions, ownedExecutor, RotationConfig{...})` borrows
the exact configured reader and durable rotation executor. The configured
lookup key must be retained by that reader with identical version and material.
`Prepare(originalGetResult, commandID, correlationID)` requires opaque original
caller admission and an eligible refresh time; premature refresh returns
`ErrRotationDeferred` without execution. Ordinary refresh requires no fresh
login. Preparation freezes the exact source and successor without durable IO.

`Rotate(ctx, preparation)` makes one bounded attempt. It changes only the
lookup digest, accepted activity and session/authority version. Original absolute
issuance, authentication time, family, remember policy, scope and unrelated
authority remain unchanged: rotation cannot turn an old login into fresh
authentication. Copies share one attempt, and only a new successful committed
result within original admission/context limits returns a reveal-once token.
Cookie attributes have an empty value; original bearer transport returns no
cookie. HTTP owns extraction, CSRF/origin policy and explicit credential delivery.

Retain `preparation.Request()` before execution. Replay, error, ambiguity,
cancellation and `Recover(ctx, originalRequest)` never return a credential.
Known commitment remains observable even when ancillary metadata is unavailable;
recovery observes the historical command under the adapter's current exact
result-access policy rather than executing again or renewing caller authority.
The storage-neutral core is available; native PostgreSQL atomic digest retirement,
reuse-family revocation and durable rotation recovery remain pending. Do not
replace those missing effects with an application-written store or journal.

### Authenticated session listing

`NewListService(primarySessions, ownedPages, ListConfig{Authorization: policy,
PolicyRevision: revision, MaximumDuration: budget})` composes the existing
authentication and authorization owners. Each `List` request selects trusted
tenant, credential, safe correlation, explicit `Limit` (1..100) and optional
cursor/`IncludeInactive`; no current-session or user ID can replace a credential.
Ordinary self-listing requires current policy, not fresh login. The reader seam
is for the owned primary adapter, not an application-written domain store. Its
native PostgreSQL implementation is available through its owned factory.

Results contain only device display metadata, exact recorded expiry and current/
inactive flags. Labels are bounded untrusted text, not MFA trusted devices.
Inactive records are filtered by default. Work is bounded to the requested
number of **raw** rows, so a filtered page can be empty with a continuation.
Continue with its cursor; do not restart at the first page to fill the result.
The cursor binds tenant/user/audience/inactive selection but is unsigned and
non-authoritative: arbitrary markers may alter traversal, never access policy.
Every call authenticates and authorizes anew. Keyset traversal uses exclusive
bytewise session-ID order; concurrent inserts before the marker are not revisited.
Cancellation, outage, corrupt pages or expired original caller admission return
no partial metadata. HTTP owns explicit authorized DTO serialization.

### Fresh self-service bulk revocation

`NewSetRevocationService(primarySessions, ownedExecutor, SetRevocationConfig{...})`
borrows the exact configured primary reader and an owned durable executor.
Select explicit policy ID/version, a whole-set bound of 1..100000 active rows
and a 1ms..30s whole-call budget. This is storage-neutral orchestration; the
native PostgreSQL set executor and atomic recovery are not yet implemented.
Consumers must not substitute application-written stores or transactions.

`RevokeOther` accepts tenant, actual cookie/bearer credential and host-generated
command/correlation IDs, never caller-selected user/session IDs. It preserves
the authenticating session. `RevokeAll` additionally requires an explicit
`IncludeCurrent` decision and the positive exact `ExpectedSubjectVersion` from
the authenticated user authority. Targets span that owner's sessions in the
same tenant across audiences; another tenant or user is never selected.
Bulk actions require fresh authentication, unlike ordinary signout/listing.

Private `PrepareRevokeSet` custody is bound to the original `Get` provenance,
entire source record and the earlier original authority/freshness deadline.
Copies, activity or repeated preparation cannot renew either deadline.
The durable owner must serialize against issuance and recheck current source,
owner and policy before applying the complete bounded set in one transaction.
Exceeding the bound must deny without partial revocation, not truncate or page.

Receipt and recovery `RecordID` bind the source session whose version advances.
`SubjectVersion` is the unchanged user-authority CAS; `SessionVersion` is the
source successor. A survivor must retain its original bearer, lifetime and
authentication timestamps with its matching session-version binding. Unknown
or in-progress outcomes retain exact scoped recovery; do not mint a replacement
command. Cancellation or expiry after a known commit preserves its outcome but
withholds counts/disposition. A failed retained-metadata read likewise preserves
the exact known commit with a redacted error and zero success metadata; use
scoped recovery rather than issuing another mutation. HTTP clears only the selected transport after
successful `CurrentSessionRevoked`; this core service emits no cookie itself.

### Idempotent self-signout

`NewSignOutService(reader, executor, SignOutConfig{...})` borrows the exact
configured primary `SessionService` and owned `RevokeOneExecutor`. Use the
PostgreSQL executor configured with that same reader, explicit policy ID/version,
1ms..30s whole-operation duration and the same host-cookie policy as issuance.
Construction performs no IO and accepts no application domain store or callback.

`SignOut(ctx, SignOutRequest{TenantID: tenant, CommandID: commandID,
CorrelationID: correlationID, Transport: CredentialCookie, Credential: credential})`
authenticates through `Get`, freezes the original caller as the exact target and
executes revocation through the existing durable owner. The configured native
adapter authorizes current policy and rechecks current owners under the sole
transaction. No fresh login is required. Supply a canonical host-generated
command ID even for an absent credential; this is not permission or authentication.
HTTP must reject mixed sources and enforce origin/CSRF before invoking cookie
signout. HTTP transport and automatic cookie writing are not provided here.

Missing or primary-denied credentials return idempotent `SignedOut` without a
second transition. Cookie transport returns `ClearCookie` and secure, empty-valued
deletion attributes; bearer transport returns `ClearBearer` without touching a
cookie. Other sessions and families are not selected. Outages, denial, malformed
receipts, cancellation and unknown outcomes do not become successful logout.
An exact receipt's `CommitOutcome` remains visible even alongside a later error;
no outcome observation is `CommitOutcomeInvalid`, not inferred rollback.
On ambiguity retain `CommandID` and `Recovery`, then use the owned native
executor's scoped historical query under current result-access policy. Do not
mint a replacement command or treat the recovery scope as authentication.

`NewRevokeOneCommand(binding, record)` prepares a single-session transition
with the complete original target and a representable version successor.
Its tenant, user and session ID must exactly match the command binding.
`RevokeOne()` exposes a copy; formatting and serialization remain redacted.
This command does not revoke a family, authenticate a caller or execute logout.
The PostgreSQL contributor executes this variant atomically with audit and
lifecycle effects. `SignOutService` targets the authenticating session;
arbitrary target management and absent/expired target semantics remain pending.

`service.PrepareRevokeOne(getResult, command)` retains opaque caller admission
from that exact configured `SessionService`, the original exclusive deadline,
and the independent complete target command. A public reconstructed result,
another configured reader, wrong owner/tenant/audience or a substituted same-ID
record is rejected. Ordinary logout needs no fresh login. The owned executor
must validate the request against its trusted service/time before reservation
and final commit, recheck source and target active owners and current policy,
and handle absent/revoked targets idempotently. `Caller()` and `Command()` are
structural projections only; neither can replace original opaque custody.
Preparation performs no transaction, mutation, validity refresh or logout.

```go
policy, err := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{
    Default: session.PersistentSession,
    AbsoluteTTL: 7 * 24 * time.Hour,
    IdleTTL: 24 * time.Hour,
    RefreshAfter: 12 * time.Hour,
    FreshFor: 24 * time.Hour,
})
```

Check `err`, resolve once before issuing an authentication continuation, and
carry the returned immutable policy unchanged through every factor. The
executable example demonstrates lifetime/cookie composition without inventing
authentication or persistence. Reference defaults belong to deployment.

### Stateful opaque validation

`NewSessionService(reader, ServiceConfig{...})` requires an owned `SessionReader`,
explicit `StorageStatefulOpaque`, configured audience, trusted clock, 1ms..5s
maximum duration, 1ms..5s clock uncertainty and 1..4 retained independent digest
keys with distinct versions. Selection is copied; key retirement removes only
that version's lookup support. Other storage profiles currently fail construction
rather than silently emulate their revocation guarantees. Use the PostgreSQL
adapter's owned primary reader; structural repository `Get`/`Lookup` must not
be passed off as an authoritative reader or replaced by consumer-written glue.

`NewCredential(CredentialCookie, parsedToken)` or `CredentialBearer` selects
exactly one transport. HTTP owns extraction, ambiguity rejection and browser
origin/CSRF policy. Both paths authenticate the same opaque session, not an OAuth
access token. `Get(ctx, GetRequest{TenantID: tenant, Credential: credential})`
sends bounded tenant/key-bound digests, never plaintext, to the reader. It checks
the returned tenant, audience, digest, verified-authentication discriminator,
complete unchanged authority vector and original absolute/idle lifetime. The
reader must independently establish every applicable authority's active state,
exact owner-derived scope, authenticating credential ID/version and native
session/family status; a structurally reconstructed record does not establish
any of those facts. No activity update, refresh, token issue or policy Allow runs.

Positive validity is bounded by the earliest source read plus at most 20 seconds,
the original source deadline, the start of this operation and session expiry,
with clock uncertainty deducted. Copies, cache promotion and delayed reads
cannot restart freshness. `GetResult.ValidUntil()` returns that original exclusive
deadline. Call `ValidateAt(trustedCurrentTime)` before reuse; the public
`Authenticated` flag and historical `Session` alone cannot authorize. Public
result reconstruction or field substitution cannot produce private admission
custody. Refresh eligibility is advisory and does not renew activity or authority.

Inactive, stale, absent and mismatched credentials return an empty result with
no error. Invalid input is `ErrInvalidInput`; incomplete authority, clock or
dependency failures are redacted `ErrUnavailable`. Cancellation/deadline retain
typed identity classifications. There is no stale fallback or automatic cache.
Anonymous state is not elevated to authenticated identity. All protected actions
still require the existing authorization service. Tests of the core reader seam
do not prove real primary, cache or provider interoperability; those adapter and
release checks remain pending.

- `LifetimeConfig` requires explicit durations and an explicit default.
- `RememberPolicy.Bindings` exports the explicit choice and all four resolved
  durations for trusted persistence. `NewRememberPolicy` reconstructs exactly:
  unresolved, out-of-bounds or clamp-requiring values fail. Store the complete
  projection, not just absolute expiry; never resolve a deployment default
  again when loading a session or continuing authentication. Neither API
  proves current authority or changes original authentication timestamps.
- `RememberPolicy.Evaluate` takes authoritative original issuance, accepted-use
  and completed authentication timestamps. It returns earliest idle/absolute
  expiry, ordinary freshness and advisory refresh eligibility without a store.
- `NewCookiePolicy` selects an immutable `__Host-` Lax/Strict profile.
- `CookiePolicy.Attributes` creates an empty standard-library cookie. Persistent
  Max-Age uses whole remaining absolute-lifetime seconds capped at seven days;
  pass `Lifetime.AbsoluteExpiresAt`, not the idle deadline. Server validation
  independently enforces `Lifetime.ExpiresAt`. Browser sessions
  omit Max-Age and Expires. Only the transport populates the credential.
- `DeletionAttributes` matches issuance scope but does not revoke authority.
- `NewToken` generates 32..64 random bytes; `ParseToken` checks bounded,
  canonical unpadded base64url credentials. Neither operation issues a session.
- `Token.Reveal` permits one explicit delivery across all value copies,
  including concurrent copies. A recipient already holding wire bytes can
  parse again: this is custody protection, not replay prevention. Never reveal
  uncommitted/unknown issuance, or mint replacements to recover an outcome.
- `NewDigestKey` defensively copies 32..64 independently generated key bytes
  and a positive version. `Token.Digest` derives a tenant/version/domain-bound
  HMAC-SHA-256 lookup without exposing or storing raw credentials.
- `NewAuthoritySnapshot` freezes all eight required authority bindings and
  explicit organization/factor/passkey applicability. Use `Bindings` only for
  trusted persistence/composition. `CompareCurrent` denies any scope, version,
  selection or presence change, including version increases and regressions.
- `NewSession` reconstructs a complete bounded `SessionSpec`: exact IDs and
  record/family versions, original issuance/activity/authentication times,
  resolved remember policy, one full authority vector and versioned token
  lookup digest. `Bindings` returns an owned projection; `Lifetime` calculates
  recorded expiry/freshness only. Neither method verifies current activity.
- `AuthenticationMetadata` explicitly separates completed-authentication
  metadata from anonymous state. Verified metadata retains the proof ID/version,
  exact authenticating credential ID/version and original proof projection.
  Anonymous state cannot assert credential proof, factor or passkey authority.
  The snapshot's aggregate credential dimension remains separate from the
  exact credential's version. The future issuer must validate live proof,
  credential, factor/passkey applicability and exact derived scope keys.
- `NewIssueCommand` freezes exact root `CommandBinding` plus one new version1
  session, preserving family version. `IssueOperation` declares its v1 mapping.
  `Issue` exposes the native projection; `ValidateIssueAt` rechecks temporal
  preparation only. Authenticated issue requires `session-issue` proof purpose,
  exact tenant/subject/audience, unexpired proof and original freshness.
  The actual issuer must still verify expected private proof authority and
  current operation policy/vector before reserve/apply through the sole
  `identity/postgres` coordinator. This command cannot activate that adapter.

## Adoption, security and tradeoffs

### Commit-gated authenticated cookie issuance

`NewSessionIssuer` freezes the configured proof authority, trusted clock,
bounded execution duration, independent lookup key, token size and host-cookie
policy. `IssueExecutor` is a storage-neutral boundary for the platform's owned
durable execution service, not an invitation to supply an application domain
store or another journal. The native PostgreSQL repository now implements
session effects; the public owned execution-service composition is the next
adapter batch. This core contract alone is not a usable login service.

`Prepare` accepts the original command binding, complete session projection,
resolved `RememberPolicy` and final opaque authenticated proof. The projection's
lookup must be zero. Preparation validates before generating one random token,
then binds that exact token's tenant/key-version digest into the native command.
`PreparedIssuance` exposes only its safe `Request`; it never exposes token bytes.
Retain that original preparation rather than preparing again on a retry.

`Issue` makes one bounded attempt across all copies of a preparation. It accepts
only an exact valid creation receipt and native record: original digest, family,
authority vector, authentication, remember policy and times cannot be replaced.
Only fresh non-replayed committed execution without dependency error or
cancellation returns a `Token` and credential-free cookie attributes. The cookie
uses the original absolute deadline, not a renewed TTL. Explicitly reveal once
at the authorized response boundary; automatic serialization is forbidden.

Malformed output or a panic during durable execution is `Unknown`, not assumed
rollback. A valid exact receipt preserves its known outcome even if subsequent
delivery fails. `Recover` queries the original command through the primary
executor and returns safe historical metadata only, never a replacement bearer
or new session. Proof expiry does not erase historical outcome recovery; the
adapter still enforces current result-access policy. Process-restart recovery
requires retaining the original safe command/proof bindings through owned
durable composition; this in-memory preparation is not a persistence system.

The original opaque proof is available through `IssueRequest.AuthenticatedProof`
for the owned adapter's protected coordinator admission. It cannot be fabricated
from public metadata and must still be checked against the configured private
authority and current lifecycle under the sole transaction owner. Anonymous,
bearer-continuation, session-container limits and rotations remain separate
unfinished contracts; this cookie issuer does not approximate those profiles.

`NewAuthenticatedIssueRequest` binds a closed `SessionCommand` to the upstream
opaque `authentication.AuthenticatedProof`, including its original proof and
credential versions. Its `Validate` requires the expected configured
`AuthorityAuthenticator` and trusted time; a request-selected or foreign
authority cannot substitute provenance. Structural metadata is not a proof,
and anonymous sessions require their separate unprivileged path. The immutable
`Command` projection intentionally loses proof admission.

Validation admits final authentication only: it does not read current lifecycle
authority, reserve or finalize proof use, issue a token, persist a session or
commit required audit/outbox effects. The authoritative adapter must retain the
original request and perform those checks and effects atomically under the sole
coordinator. A positive result alone must not authenticate a stored session.

Zero policies are invalid; use the constructors. Redacted sentinel errors work
with `errors.Is`. Values are immutable and concurrency-safe, and returned
cookies are caller-owned copies. Policy methods perform no IO. Token generation
uses standard-library secure OS entropy. No callback, goroutine or hidden clock
exists. Root identity APIs remain unchanged.

Token/key formatting redacts; automatic JSON/text serialization fails closed.
Explicitly revealed strings are secrets, no longer protected by wrappers.
Custody neither erases memory nor prevents recipient retention. Keys must be
CSPRNG-derived and independent of other cryptographic purposes. Never reuse
versions for different key material. Retain old lookup keys until all required
session/tombstone paths are retired. Key provisioning, encrypted durable
recovery custody and rotation readiness remain unfinished composition
requirements. Raw tokens must never become database lookup keys or cache
projections; stable digests should not be logged because they correlate usage.

Authority keys are canonical dimension-qualified keys supplied by each durable
lifecycle owner, not normalized user inputs. Their exact tenant and aggregate
IDs must be derived from the session/proof; construction does not check a
database, active status, membership, proof applicability or freshness. Never
accept a credential solely because two caller-created snapshots match.
Primary-authority adapters must compare the complete vector, check active state
and expiry, and retain the original bounded read evidence. JSON encoding of the
opaque wrapper fails rather than silently persisting an empty object. Extract
the complete scalar projection for trusted storage; do not log its scope data.

Browser sessions cap server lifetime at 24 hours. Browser restoration may retain
nonpersistent cookies; expiry and revocation remain necessary. Activity never
renews authentication freshness or absolute lifetime. Expiry equality denies;
invalid/future timelines fail closed without silent skew. Sensitive operations
need a separate stricter freshness gate. Calculations are **not** authoritative
shared-issuer validity evidence.

Completed authentication may precede session issuance. Preserve its original
timestamp: replacing it with issuance would renew sensitive-operation freshness.
Activity must still be at/after issuance, and future authentication denies.
Proof expiry is historical record metadata, not the session's lifetime deadline;
new issue preparation separately checks exclusive proof expiry. Stored proof
projections are not authority, and arbitrary matching authority keys are not
primary evidence. No default, normalization, callback or implicit upgrade is
introduced by record reconstruction. These APIs preserve existing root contracts
and consume pinned, unreleased identity/authentication revisions; published
clean-consumer, typed catalog and complete release checks remain pending.

Cookie attributes fix Secure, HttpOnly, path `/`, no Domain and no partitioning.
The reference profile's High priority attribute awaits HTTP serialization;
standard-library `http.Cookie` does not represent it. This is not yet the
complete reference transport profile.
None/cross-site cookies belong to a separate flow-correlation owner. CSRF,
origin checks, duplicate-cookie rejection and no-store headers remain HTTP
requirements. A populated `http.Cookie` contains a secret: never log it.

## FAQ and operations

### Self-session device-label preparation

`NewUpdateCommand(binding, caller.Session, label)` freezes only a label and
checked session-version successor. Use `UpdateOperation()` for the binding;
the source record's version is the expected CAS. Empty clears the label;
UTF-8 text is bounded to128 bytes and excludes control runes. Treat it as
untrusted display text and escape it when rendered, never as device trust.

`service.PrepareUpdate(caller, command)` requires an unchanged authentic
`GetResult` from that exact service and the exact authenticating session, not
another same-user device. The opaque `UpdateCommandRequest` retains original
transport and exclusive admission deadline. Copying or retrying does not renew
authority. Label updates do not require fresh login, rotate credentials or
extend activity, lifetime, remember choice or authentication freshness.

`NewSessionUpdater(service, ownedExecutor, UpdateConfig)` freezes the selected
policy and whole-call budget. `Prepare(caller, UpdatePreparation)` checks the
exact authenticating session ID and positive expected version before creating
original-custody intent. Then `Update(ctx, request)` delegates current policy,
primary owners and atomic label/CAS/audit/lifecycle effects to the owned executor.
Successful results expose safe historical session/device metadata, never a
credential or a renewed Get admission. Empty labels clear display metadata.

Retain the request and scoped result after ambiguity; `Recover(ctx, request)`
authorizes current exact result access through the owner and observes the same
command without executing or requiring expired source custody to become valid.
Recovery returns outcome only, no session/device or apparent active-state claim.
Known commitment survives cancellation, expiry and ancillary read failure;
these errors withhold metadata rather than pretending rollback. Malformed
receipts and post-entry panic are unknown; do not substitute a new command.
Errors before owner entry return an invalid/unobserved outcome, not evidence
that the original command is absent or rolled back. Retain its recovery scope.

Preparation is not authorization or a durable update. Core creates no store,
journal or transaction; PostgreSQL writer/list integration, HTTP composition
and release gates remain pending. Consumers must not implement a private store
or assume a structural successor or recovered receipt authenticates a session.

### Encrypted admission cache

`NewEncryptedCacheCodec(service, envelopeService, config)` adds explicit
encrypted persistence to stateful opaque credential validation. Obtain an
authentic `GetResult` through `SessionService.Get`, then `Seal(ctx, result)`.
Persist only the returned caller-owned ciphertext. On reuse call
`codec.Get(ctx, originalRequest, ciphertext)`; the original opaque credential
is still required. Never log ciphertext, key references or decoded projections.

Use `github.com/faustbrian/go-secret-envelope` with a concurrent-safe bounded
key provider. The codec does not invent encryption or accept client-selected
keys. Configure issuer, environment and a positive deployment epoch explicitly;
changing these invalidates all prior cached custody. Rotate the active key
reference while retaining previous read keys for their bounded lifetime.
Removing a read key requires primary validation rather than accepting that cache.

Every payload contains the complete original immutable session, remember policy,
authority vector, transport and admission timestamps. Five-minute maximum age
is a payload ceiling, **not** five minutes of positive authority. The original
exclusive source deadline (at most 20 seconds, less read/clock/lifetime budget)
wins, including after process restart or resealing. After expiry, an unavailable
primary denies. Corrupt/foreign entries and unavailable key services use bounded
primary validation; never stale fallback. Unknown or noncanonical projections
never establish positive state.
Callbacks must honor the session service's bounded context; no detached work is
started to hide a provider that violates cancellation.

The binary envelope limit is explicit and checked before parsing or crypto.
HTTP must additionally enforce the maximum encoded cookie size and Secure,
HttpOnly, SameSite, CSRF/origin and no-store rules. This codec is not yet cookie
transport, a Valkey adapter or a fully stateless deployment. Existing stateful
constructor behavior is unchanged; the other storage-profile flags still deny
until their real composition is implemented.

**Does refresh reset expiry?** No: preserve original issuance. RefreshDue is
advisory and authorizes neither a refresh nor a new token.

**Can fractional expiry create a persistent cookie with Max-Age zero?** No:
less than one second denies. The 15-minute configuration minimum applies to
issuance, not a lower bound that could extend remaining lifetime.

**Why no defaults?** All sign-in methods must share one selected policy instead
of silently choosing different lifetimes. Resolve before MFA, not after it.

**Is logout implemented?** Only deletion attributes and the closed native
`NewRevokeFamilyCommand(binding, expectedVersion)` preparation contract.
`RevokeFamilyOperation` targets one family, not user-wide logout; exact scope
and a representable version successor are required. An opaque command is not
authorization, a durable receipt or an HTTP endpoint. Durable logout workflows,
unknown-commit recovery and lifecycle integration are pending. This batch has
no core migrations or runtime services. Mutation, public API/release gates and full
session-unit acceptance remain pending. See [CHANGELOG.md](CHANGELOG.md).
