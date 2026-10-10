# Identity password workflows

**Development checkpoint:** input policy, bounded credential work, canonical
account comparison and portable keyed change contracts are implemented. The
native PostgreSQL adapter has single-factor reauthentication and authenticated
change composition; this core does not yet connect its portable change port.
Complete signup/signin, upgrades, set/reset, administrative workflows and HTTP
remain required. These helpers do not authorize persistence or session issuance.

`NewPasswordVerifier` freezes a real primitive service, exact current-policy
dummy hash, explicit byte/time bounds, trusted clock and platform-owned
`CredentialVerificationRepository`. `VerifyPassword` accepts a canonical kernel
`UserID` and trusted `TenantID`, not an email/phone identifier or an OTP. Unknown
and missing accounts execute real dummy work; even a matching dummy cannot
authenticate. Blocked, expired, mismatched and stale-version results are neutral.
A real match requires a second primary snapshot preserving the original hash,
reference version and user-wide credential epoch. Ordinary user aggregate
version changes do not invalidate an otherwise eligible credential.

The repository must join kernel authority and owned hash material consistently;
the native password PostgreSQL adapter provides that reader and single-factor
reauthentication composition. Do not wire
independent kernel/hash reads or a cached positive fallback into this port.
The comparison result is not a lease, proof or session: the owning signin
workflow still must apply risk, verification, MFA, remember policy and atomic
upgrade/session effects, identically for email, username and phone callers.
The verifier never trims bytes, upgrades a hash or consumes caller secret custody.
The caller destroys its Secret after the call. Request/snapshot diagnostics are
redacted and implicit JSON/text serialization is denied; explicit hash access
and private-field diagnostic reflection remain sensitive.

The private execution path now performs bounded primitive work: new hashes
require successful owned screening first, unknown identities use a current-policy
dummy hash and never return a match, and late cancellation or secret destruction
discards output. Existing short passwords are not rejected by the signup minimum.
This is not a wall-clock constant-time claim across legacy hash algorithms or
storage, and the HIBP provider and durable workflows are not yet connected here.

The shared screening path now delegates complete decisions to `risk.Policy`,
requiring explicitly selected HIBP for each creating action. It freezes bounded
provider facts and reassesses their original age after hashing, without another
provider call, cache promotion or freshness reset. Missing/unavailable signals,
breaches, foreign bindings, step-up and throttle cannot yield a usable hash.
Concrete HIBP provider collection, atomic risk consumption and password workflow
composition still need to be connected; structural facts are not source proof.

`NewHashPreparer(HashPreparationConfig)` makes that existing screened path
available to native workflow composition without importing a persistence or
provider adapter. Construction requires the real primitive, exact policy dummy
hash, explicit inclusive byte bounds, a timeout up to ten seconds, trusted clock,
HIBP-enabled risk policy and bounded owned signal collector. It performs no IO.
`Prepare(ctx, candidate, binding)` returns the primitive's opaque encoded hash
and an internal assessment only after complete Allow screening and unchanged
original-fact rechecks. Unselected creating actions cannot reach the provider.
The assessment is not authorization or transactional risk evidence. Complete
reference composition must wire real provider provenance; this public helper
does not establish provenance from caller-built structural facts.

Run preparation before opening the protected transaction. Never log or return
`EncodedHash.String()`; borrow it only for owned command/persistence work and
discard copies afterward. The caller destroys the password after the call and
retains provider/primitive shutdown ownership. No retry, store or goroutine is
introduced. Earlier deadlines win; cancellation survives and errors/panics redact.

## Quick start

```go
policy := password.RegistrationPolicy{
    Enabled: true, MinimumBytes: 12, MaximumBytes: 128,
    RequireVerifiedEmail: true,
}
if err := policy.Validate(); err != nil { return err }
secret, err := primitive.NewSecret(input)
if err != nil { return err }
defer secret.Destroy()
if err := policy.CheckPassword(secret); err != nil { return err }
```

Here `password` is `github.com/faustbrian/go-identity/password`; `primitive` is
`github.com/faustbrian/go-password`. Production workflows must still enforce
configured HIBP/risk, account status, verification and transactional authority
before hashing or committing. This checkpoint cannot replace those workflows.

## API and ownership

`CookieChangeRequest` wraps the unchanged `ChangeRequest` and the session owner's
opaque `CSRFToken`. Its nested request carries the sole retry key. Its distinct
`CookieChangeService` port lets optional browser HTTP composition select the
native cookie profile without importing PostgreSQL or silently falling back to
bearer change. Trusted transport must first enforce permitted origin and reject
mixed cookie/bearer channels. Structural `Validate` delegates intrinsic bounds
only: even a zero CSRF token can pass it, but must be denied by the native service.
The native owner checks exact synchronizer state under its primary session fence,
including named-key eligibility before returning a historical retry outcome.
Neither validation nor formatting consumes token delivery or password custody.
Cookie native port binding and HTTP endpoint composition remain pending.

`ChangeRequest` is the adapter-neutral authenticated change input. Direct
callers set its sole required `identity.IdempotencyKey`; HTTP must acquire that
key only from exactly one `Idempotency-Key` header. The request carries the
original upstream `authentication.ReauthenticationProof` and bearer, a borrowed
primitive password secret, and trusted tenant/caller/network provenance. It
exposes no request-selectable clock, assurance or revocation policy.

`Validate` checks only intrinsic bounds, key presence, live secret length and
caller/tenant consistency. It neither authenticates a proof nor establishes
freshness, risk eligibility or permission to mutate. A structurally valid
request with a zero, expired or foreign proof must still be denied by the native
signed-proof owner. Deployment byte limits are separate. Values must not be
mutated during a call; destroy the secret only after work returns. Formatting
and slog redact, JSON/text serialization deny, and explicit field access remains
sensitive. Do not put raw input into private diagnostic wrappers.

`ChangeService` defines the native `Change` and code-free
`Recover` workflow boundary without importing persistence or
providers. Select the real platform adapter, not application-written stores or
workflow callbacks. `ChangeResult` conserves original command/outcome and exposes
no credential material. Zero outcome is absence of authoritative observation,
not rollback; busy/unknown does not permit a new key or automatic retry. Only
error-free known commitment can expose the credential successor and predecessor
invalidation. Native binding and opt-in HTTP composition are subsequent work;
these port declarations alone are not a working endpoint or lifecycle claim.

`RegistrationPolicy.Validate` requires explicit inclusive raw byte bounds in
1..1,048,576, with maximum at least minimum. The reference deployment separately
owns stricter policy ranges/defaults; the core never supplies silent defaults.
`CheckPassword` rejects disabled registration and zero/destroyed/out-of-bounds
secrets. It does not trim, normalize, copy, borrow, hash or destroy them.
Caller-owned secrets require explicit destruction. Successful length admission
does not pin secret lifetime; later work must still use the primitive's bounded
exclusive borrow contract and handle concurrent destruction or use.

`SignupAddressInput.Validate` admits 1..4096 UTF-8 bytes without interpreting an
address kind. Pass the original input to the identity registration owner for
canonicalization, uniqueness and verification. Email parsing does not belong
here; no `identity/email` dependency is required. Generic input admission proves
neither address ownership nor deliverability.

Errors are stable `errors.Is` classifications and contain no password/address
material. Direct address formatting and structured logging redact; implicit
JSON/text serialization is rejected. Explicit string conversion reveals input.
Never retain raw address scalars inside diagnostic objects: private fields can
bypass formatting methods. This checkpoint owns no IO, goroutines or resources;
policy values are safe for concurrent reads, not concurrent mutation.

## Adoption, tradeoffs and FAQ

- **Can these helpers register or authenticate a user?** No. Their sole purpose
  is input admission; the required owning transactional workflows are pending.
- **Why raw byte limits?** Password normalization changes the secret. Bounds
  apply to the exact primitive-owned bytes, not characters or trimmed text.
- **Why allow a non-email signup address?** The registration owner selects the
  address kind; this package must not duplicate that interpretation.
- **Can I persist or log a Secret?** No. Use its explicit synchronous borrow
  only for bounded verification/hashing and destroy caller custody afterwards.

See [CHANGELOG.md](CHANGELOG.md) for checkpoint release notes. Exact package
coverage/mutation, complete workflow/infrastructure/provider evidence,
clean-consumer and release qualification remain pending.
