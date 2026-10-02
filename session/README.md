# Session

Experimental Go 1.27 session policy module. This first batch implements shared
remember-policy resolution, lifetime evaluation, secure host-cookie attributes
and opaque token/key custody with tenant-bound lookups. **Session issuance,
authentication, persistence, rotation,
revocation and transfers are not yet implemented.** Complete authority-vector
construction and exact comparison are available, but do not read primary
authority or prove activity/freshness.

Immutable complete session records and exact-bound native issue commands are
also available for trusted storage/adapters. They are **not** session issuance:
caller-created `authentication.Proof` metadata and `AuthenticationVerified`
cannot establish authentication authority. No command in this module executes
or opens a transaction, reserves a proof, writes a record or reveals a token.

## Quick start and API

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

**Is logout implemented?** Only deletion attributes. Durable revocation,
unknown-commit recovery and lifecycle integration are pending. This batch has
no migrations or runtime services. Mutation, public API/release gates and full
session-unit acceptance remain pending. See [CHANGELOG.md](CHANGELOG.md).
