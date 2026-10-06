# otp

Purpose-bound OTP policy and code generation for Go 1.27. The durable challenge,
attempt, delivery, reservation and owning-workflow services are **unfinished**.
Do not use generation as login, verification, issuance or replay protection.

## Quick start

```go
profile, err := otp.NewCodeProfile(otp.CodeProfileSpec{
    Purpose: otp.PurposeSignin, Alphabet: "0123456789", Length: 6,
    TTL: 5*time.Minute, ResendInterval: time.Minute,
    MaximumSends: 5, Attempts: 5, Replacement: otp.ReplacePrevious,
})
```

Check `err` before retaining policy. `profile.Bindings()` returns its complete
non-secret immutable policy projection. Use `profile.Generate(ctx, use)` only
inside trusted issuance composition: the synchronous callback borrows the code
until return; the slice is then cleared, including on error or panic. The
executable example demonstrates this lifecycle without displaying a code.

## API and security

- `NewCodeProfile` validates all explicit fields; zero policy is invalid. The
  alphabet is unique visible ASCII, length is 4..128 and code space is at least
  one million. Six decimal digits match the reference profile. Other policy
  bounds are documented on `CodeProfileSpec`; no defaults are silently supplied.
- `Generate` uses OS cryptographic randomness with rejection sampling. It never
  uses biased modulo reduction or weak fallback; hostile/failing sampling is
  bounded. Its callback receives a context capped at five seconds and must
  honor cancellation. OS random reads cannot be forcibly interrupted.
- No callback, code, key or mutable state is retained. Profiles are safe for
  concurrent use. No background goroutines or shutdown owner are introduced.
- `ErrInvalidProfile`, `ErrInvalidGeneration`, `ErrGenerationUnavailable` and
  `ErrCodeUse` contain no caller data. Callback errors are not retained because
  they may contain codes. Context cancellation/deadline errors take precedence.
  Callback panics propagate after buffer cleanup; callers must not put codes
  in panic values or recover them into telemetry.

## Adoption and tradeoffs

### Keyed digest storage

`NewDestinationInput` copies bounded raw channel input without normalizing it.
The owning email/phone workflow must canonicalize and enforce uniqueness before
using it in `NewDigestScope`. `DestinationInput.Value` is an explicit trusted
delivery/workflow accessor, never a logging or wire representation.

`NewDigestScope` binds exact tenant, closed purpose, subject (empty only before
account creation), channel, canonical destination, challenge, workflow target,
policy/generation and a nonzero authorization binding. The trusted workflow
must derive that binding from the complete closed authenticated-session or
pre-auth transaction context, including session remember policy; request data
cannot stand in for verified authorization. The constructor validates bounds,
not ownership, account existence, current permission or challenge validity.

`NewVerifier(current, retainedKeys)` copies an explicit ring of 1..8 nonzero
32-byte keys with positive versions. `Digest(scope, authentication.OneTimeCode)`
uses the current key; `CodeDigest.Storage()` is an explicit digest-only durable
projection. `Compare(scope, stored, code)` selects exactly the recorded retained
key and compares in constant time. Rotation preserves old verification while
the original key is retained. Removing a key returns `ErrDigestUnavailable`;
there is no fallback, automatic migration or renewed expiry. Neither raw codes
nor raw digest keys have accessors. Automatic formatting is redacted and
serialization denied, including the adapter projection. Go cannot promise
complete secret erasure; release all retained keys/codes when no longer needed.

**Compare is not a login/check endpoint.** It grants no proof or reservation.
It belongs inside the durable counted attempt transaction after locked scope,
expiry, generation, current authorization and rate-limit checks. Wrong-code
attempts must persist their decrement/denial exactly once; ambiguous outcomes
must recover without a second comparison. Those workflow/store operations remain
unfinished. Never expose an unmetered digest oracle or store unkeyed codes.

The consumed authentication contract is pinned to local reviewed commit
`303520b8d5af937e4e38ec8cb3ee8ff6f9813230`. Development verification uses an
explicit disposable workspace composition, not a permanent module replacement.
Publication and clean remote-consumer qualification remain release work.

Borrowed callbacks make accidental secret retention less likely, not impossible:
the callback is trusted and can copy bytes. It must not log, format or retain
the raw code; production composition must compute a versioned scope-bound keyed
digest and seal the delivery payload through `secret-envelope`. Raw and unkeyed
code storage is forbidden. Those workflow operations are not available yet.
The library does not forcibly terminate a non-cooperative callback.

The profile's purpose, TTL, replacement, send and attempt values are declarations,
not store enforcement. PostgreSQL must own database time, keyed digest custody,
attempt idempotency, one-winner reservation, same-transaction finalization and
unknown-outcome recovery. A generated code has no validity or authority before
that durable issue transaction. Never send before issuance commitment.

## FAQ

**Can I use this for TOTP?** No. TOTP is an MFA protocol, not a randomly issued
one-time challenge.

**Does generation revoke an older code?** No. Replacement is an atomic durable
issuance transition, not generation or delivery-provider success.

**Is OTP ready for registration/login?** No. This is a development checkpoint;
store, attempts, delivery, session/remember policy and public workflow contracts
remain in progress. Coverage/mutation/release and composed acceptance are pending.

See [CHANGELOG.md](CHANGELOG.md) for release notes.
