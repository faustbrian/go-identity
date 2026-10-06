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

### Continuations and logical attempts

`NewFlowAuthorization` freezes a closed explicit discriminant and exactly one
session or pre-auth transaction ID. Both members, no member, unknown kinds and
malformed IDs fail. It never infers authentication from subject or remember
policy and does not verify the selected session/transaction against a database.
Session IDs use the existing session record's bounded visible ASCII contract;
pre-auth IDs use identity's canonical nonzero random128 encoding.

`NewContinuation(scope, authorization, remember)` derives its authorization
binding instead of accepting one from a request: the input scope binding must
be zero. Signin uses pre-auth context only, with an already-resolved session
remember policy. Pre-auth MFA carries that same policy. Other purposes require
zero remember policy; they cannot acquire persistence by fallback. All exact
remember limits, including nanosecond precision, are bound unchanged. The owning
workflow must check that they match the original primary pre-auth/session state;
structural construction alone cannot certify provenance or renew validity.

`NewAttemptIssuer(version, fingerprintKey)` receives an independent nonzero
32-byte key, separate from challenge digest and signing keys. `Prepare` accepts
no caller-selected attempt ID or fingerprint. It draws a canonical random128 ID
and keys a complete scope/authorization/code/mode/expected-version fingerprint.
Check and Consume are explicit disjoint modes; neither preparation mode grants
authentication or creates a reservation. OS random reads cannot be forcibly
interrupted; preparation has a five-second context cap with checks around work.

`PrepareForCommand` additionally freezes the root-validated consuming command
binding and trusted operation descriptor. Tenant, user namespace and required
record target must match the continuation. Anonymous-flow schemas explicitly
require an empty pre-account subject. The independent actor remains distinct
from that subject. Its domain-separated keyed fingerprint includes all command
metadata, and code-free recovery retains the original command ID as well as
the attempt ID. `CommandBinding()` rejects zero and legacy unbound preparations;
returned projections cannot mutate the original submission. Legacy `Prepare`
keeps its existing exact fingerprint profile.

This structural binding is not the coordinator's command fingerprint, operation
registration, primary authorization or a dispatch capability. The owning native
adapter must enforce operation-purpose semantics and original pre-auth/session
provenance; generic feature execution must not bypass the pending typed OTP
transaction phases. No durable command dispatch is implemented by preparation.

Use the same `AttemptCommand` across dispatch retries. The code remains opaque
through `Code()` for the authoritative bounded comparison, and `Bindings()` is
code-free. Never persist the whole command. Release all command/code copies on
a terminal result; retain only `Recovery()` metadata when the outcome is unknown.
It must query the original ID/fingerprint/version without re-comparison or a
second denial decrement. Key rotation changes new attempts, not an old recovery
identity. A new Prepare call represents a new submission, **not** a recovery.

These values own no transactions, current authorization, challenge expiry,
attempt accounting or protected mutations. The pending PostgreSQL adapter must
lock primary challenge/authorization state, decrement and record a wrong-code
denial once, or atomically create the sole generation-fenced reservation on a
correct consuming attempt. Successful Check must return no proof/reservation.
Persisted absence does not prove not-committed while the original transaction
is live. The workflow must reconcile ambiguity before selecting another action.
Automatic formatting is redacted and JSON/text serialization denied throughout.

Root ID parsing and remember policy are consumed from the reviewed identity
and session modules at `aa3c66f5c5aa41d7a2fab11b301974db72aed52a`; no new session
policy engine or identifier parser is introduced.

### Locked challenge policy

`NewAttemptPolicy(profile, checks)` derives the shared total-attempt bound from
the frozen code profile; there is no independent override. Checks are explicitly
enabled with a separate 1..10 total cap, or disabled with a zero cap. Every
admitted precheck uses that separate budget; all admitted comparisons, including
correct checks and consuming success, use the profile's total budget. Lockout is
a positive microsecond-exact duration at most
24 hours; the durable owner must enforce it across replacement challenges.

`NewChallenge` validates a digest-only primary snapshot with immutable complete
continuation, original policy, positive version, counters and closed state.
Issue/expiry times are exact PostgreSQL UTC instants; expiry cannot exceed the
profile's original TTL. Earlier-expiring challenges are supported, never renewed.

`Verifier.EvaluateAttempt` is a **trusted transaction policy seam**, not a
verification endpoint or a store. Check the original attempt replay record and
current primary authorization first, then invoke it once under the primary row
lock with database time. It proposes exact counters, state and next version:
every admitted comparison decrements the shared allowance once; checks never reserve; only
correct Consume proposes Reserved. Terminal or already-reserved state cannot
be revived, expired or released by evaluation. At exact expiry only Issued may
become Expired. Foreign scope never charges another row; stale/maximum versions
deny. Retired keys fail without a charge or fallback.
Correct Check on the final allowance returns Checked but leaves the challenge
Exhausted with no wrong-code lockout. Correct Consume on the final allowance can
still propose Reserved. Separate UsedAttempts/FailedAttempts counters preserve
that distinction; successful checks cannot create extra future verification.

The proposal creates no proof, handle, SQL, durable attempt result or current
authority. The forthcoming adapter must commit it atomically with its command
record and required effects, serialize concurrent attempts, and reconcile
ambiguity without re-comparison. Never expose private outcomes/counters to a
client. The service must normalize them to enumeration-safe responses. These
remaining durable requirements are not implemented by these pure policy APIs.

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
