# MFA (in development)

This Go 1.27 module owns second-factor authority, separate from primary
authentication. The initial API distinguishes explicitly known empty state from
unknown state. It now defines immutable browser partial-authentication continuation
bindings and shared attempt budgets. Durable continuation issuance/completion,
enrollment, factor verification, recovery codes and trusted devices remain
unfinished; it is not a complete MFA service.

Trusted adapters construct `FactorAuthority` from current owner storage.
`RequireEmailRecovery` denies unknown, cross-subject, or enrolled state. Successful
admission still requires verified email, current account and risk checks, and a
purpose-bound capability. Never accept authority records from a client or cache
them as authorization. PostgreSQL admission holds the generation lock through
the protected transaction. Primary passkey credentials are not MFA enrollments.

Public API semantics are documented on `AuthorityRecord`, `FactorAuthority`,
`NewFactorAuthority`, `Version`, and `RequireEmailRecovery`.

## Partial authentication

Construct `PartialAuthContinuation` from trusted `ContinuationSpec` storage,
not client fields. Retain the original primary-proof identity/digest, browser
flow/origin, independent factor and policy generations, allowed methods, resolved
remember policy and absolute lifetime (at most five minutes and never beyond
the original primary proof expiry). `Bindings` returns
an owned projection. The projection is not authenticated or committed authority.

`CapabilityPayload` maps the immutable scope to the existing capability format,
with one use and no raw primary credential. The actual capability issuer owns
signing and replay storage. `Authorize` compares an already verified grant
read-only; repeat validation consumes nothing and cannot refresh expiry.
`ScopeDigest` supplies that same immutable binding to durable adapters without
signing, consuming or granting authentication. Mutable attempts and terminal
states cannot renew or change it.

`RecordAttempt` projects one shared-budget transition for an allowed factor
method. The durable MFA owner must CAS the exact stored version and persist the
transition atomically with the factor outcome. Switching methods cannot restore
attempts. Exhaustion is `Revoked`; absolute expiry and terminal states deny.
These pure methods do not authenticate factors, create durable continuations,
consume capabilities or issue sessions. Required MFA must never fall back to a
single-factor session while its continuation service is unavailable.

## TOTP computation and custody

`TotpVerifyRequest` binds the original child challenge, selected enrolled factor,
opaque code and original browser cookie to a trusted transport caller. `Validate`
checks structure only, including fragment-free HTTPS origin/callback URLs; it
does not authenticate the caller, consume a proof or check a factor. Current
policy must explicitly handle `TrustDevice`; unsupported policy denies it.
`TOTPCompletionService` describes the login-completion boundary, but a concrete
public service and reference/HTTP composition are still being implemented.
Recovery cannot disclose another credential or repeat primary authentication.

`TOTPProfile` explicitly selects SHA1/SHA256/SHA512, 6..10 digits, a whole-second
15..120-second period, 0..2 skew steps and an exact provisioning issuer. Zero
skew is supported. Validation never repairs a stored enrollment profile.

`NewTOTPVerifier` retains an independent, trusted comparison key behind opaque
custody. `Verify` borrows an owned `password.Secret`, accepts only an opaque
`authentication.OneTimeCode`, and compares through authentication's existing
keyed-digest contract. The native caller supplies authoritative time and an
injective tenant/subject/factor/challenge scope including the retained comparison
key version. The caller destroys the secret after use; verification retains no
factor bytes. Submitted codes have no plaintext accessor.

The returned counter is metadata, not a proof or consumed factor. Read and fence
`TOTPReplayState` under native durable authority and advance it atomically with
the shared attempt budget, continuation completion and original-primary session
effects. Verification alone must never issue a session. Those durable completion
operations and enrollment remain unfinished.
