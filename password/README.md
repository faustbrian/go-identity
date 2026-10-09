# Identity password workflows

**Development checkpoint:** input policy, bounded credential work and canonical
account comparison are implemented. Transactional signup/signin, hash upgrades, change/set/reset,
reauthentication and administrative workflows remain required and unimplemented.
These helpers do not authorize persistence or session issuance.

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
the concrete password PostgreSQL implementation is still pending. Do not wire
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
