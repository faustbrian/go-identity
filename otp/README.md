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
