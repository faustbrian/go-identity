# Session

Experimental Go 1.27 session policy module. This first batch implements shared
remember-policy resolution, lifetime evaluation and secure host-cookie
attributes. **Session issuance, authentication, persistence, rotation,
revocation, transfers and authority snapshots are not yet implemented.**

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

## Adoption, security and tradeoffs

Zero policies are invalid; use the constructors. Redacted sentinel errors work
with `errors.Is`. Values are immutable and concurrency-safe, and returned
cookies are caller-owned copies. No IO, callback, goroutine or hidden clock
exists. Root identity APIs remain unchanged.

Browser sessions cap server lifetime at 24 hours. Browser restoration may retain
nonpersistent cookies; expiry and revocation remain necessary. Activity never
renews authentication freshness or absolute lifetime. Expiry equality denies;
invalid/future timelines fail closed without silent skew. Sensitive operations
need a separate stricter freshness gate. Calculations are **not** authoritative
shared-issuer validity evidence.

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
