# Session

Experimental Go 1.27 session policy module. This first batch implements shared
remember-policy resolution, lifetime evaluation, secure host-cookie attributes
and opaque token/key custody with tenant-bound lookups. Authenticated cookie
issuance orchestration is available through `SessionIssuer`; owned durable
executor composition is available in the PostgreSQL adapter. Stateful opaque
`SessionService.Get` validation is available against its trusted owned-reader
contract. **The primary authentication reader, rotation, complete revocation
services and transfers remain unfinished; this is not a usable login service.** Complete authority-vector
construction and exact comparison are available, but do not read primary
authority or prove activity/freshness.

Immutable complete session records and exact-bound native issue commands are
also available for trusted storage/adapters. They are **not** session issuance:
caller-created `authentication.Proof` metadata and `AuthenticationVerified`
cannot establish authentication authority. No command by itself executes
or opens a transaction, reserves a proof, writes a record or reveals a token.

## Quick start and API

`NewRevokeOneCommand(binding, record)` prepares a single-session transition
with the complete original target and a representable version successor.
Its tenant, user and session ID must exactly match the command binding.
`RevokeOne()` exposes a copy; formatting and serialization remain redacted.
This command does not revoke a family, authenticate a caller or execute logout.
The PostgreSQL contributor executes this variant atomically with audit and
lifecycle effects; the public owned revocation service remains required.

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
rather than silently emulate their revocation guarantees. The primary reader
implementation is still required; structural repository `Get`/`Lookup` must not
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
