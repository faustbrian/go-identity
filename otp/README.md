# otp

## Original-session synchronizer binding

`NewBoundSessionAuthorization` retains both immutable session projections:
the base record and separate digest-only `CSRFState`. `NewContinuation` commits
the latter's presence, named key version and digest under
`identity-otp-authorization-v4` when present. The original tenant/session/version
are already committed in the base frame and must match the CSRF tuple through
the session owner's constructor. No raw CSRF token or key enters OTP custody.

Tokenless complete-session v3, complete-preauth v2 and legacy ID-only v1 frames
remain byte-for-byte unchanged. Changing or stripping CSRF state changes the
code digest, server-attempt fingerprint and sealed-record signature. No
authentication time, remember choice, authority epoch or validity is renewed.

This is cryptographic binding, not primary admission or HTTP CSRF enforcement.
The durable OTP adapter must preserve the full original state during recovery;
that adapter integration and protected token/origin handling remain unfinished.
Upgrade the adapter before enabling CSRF-bearing OTP continuations. An adapter
that drops state fails restored verification; do not replace the frozen original
with a fresh lookup to make a retry pass.

## Native Send preparation

`NewSendPreparer(SendPreparationConfig)` fixes attempt policy, retained digest
keys, an owned `delivery.TemplateRenderer`, template version and copied ordered
locale fallback. Its `Prepare` method generates one code for both digest and
rendered message, lending plaintext only to the synchronous adapter-owned
encryption boundary. A failed or panicking seal returns no challenge and no
secret-bearing diagnostics; cancellation is preserved. Instances retain no
request-specific state and support concurrent use. Template selection and
message/locale schema are checked against the real request before entropy.

This is the storage-neutral native preparation seam, **not `Service.Send`**.
The platform's native adapter must resolve/authorize the destination, perform
current primary/risk admission, and acknowledge the original journal's start
before calling it. On retry, it must select and restore retained encrypted
output instead of invoking generation. Final atomic issuance must recheck
current authority and expiry. Applications must not supply the missing store,
journal or workflow as callbacks. The sealing callback belongs to the native
adapter and must not retain plaintext, ignore cancellation or start background
work. Strings and copies retained by a violating callback cannot be erased by Go.

## Complete original authenticated-session continuation

`NewBoundSessionAuthorization(originalSession)` retains the complete immutable
session-owned `Session` projection. `AuthenticatedSession()` returns it only
for this explicit profile. Anonymous sessions are rejected. The constructor
does not authenticate a caller, verify a token or grant a current validity lease.

`NewContinuation` requires the original tenant and subject, rejects signin and
requires zero continuation remember policy. Its domain-separated v3 commitment
includes the complete session/family IDs and versions, audience, resolved
session remember policy, lookup key version/digest, complete authority vector
including optional presence, authentication metadata and original UTC
nanosecond timestamps. No constructor, reconstruction or retry renews time.
Legacy ID-only v1 and complete pre-auth v2 commitments remain unchanged.

Native admission must independently authenticate submitted credential custody,
check every applicable current authority and compare the exact original session
and family under primary locks. Session lifetime and operation-required
freshness must be rechecked after downstream waits. This core profile does not
activate the still-unfinished authenticated-session PostgreSQL execution path.

## Complete original pre-auth continuation

`NewBoundPreAuthAuthorization(originalSessionFlow)` explicitly retains the
immutable session-owned `PreAuthTransaction`. `PreAuthTransaction()` returns
that private projection only for this profile; legacy ID-only and authenticated
session contexts return zero/false. The existing `FlowAuthorizationSpec` and
its constructor are unchanged, so existing ID-only values do not silently
become complete-flow evidence.

`NewContinuation` requires matching tenant and preserves original remember
policy for signin/pre-auth MFA. Its domain-separated v2 binding includes the
explicit authorization kind/IDs and selected remember policy, then the complete
original ID, tenant, action, origin, callback/no-redirect, policy ID, UTC
RFC3339Nano issued/expiry, nonce, policy version, original remember policy,
cookie key version/digest and record version. Strings are uint16-length-prefixed;
versions/durations use big-endian integers, with uint32 cookie key version and
uint64 policy/record versions and durations. The original remember choice is
uint8. The binding is SHA-256 under `identity-otp-authorization-v2` plus NUL,
then incorporated into the existing keyed exact-submission fingerprint/MAC.
Legacy context retains its exact v1 bytes and domain.

Bound anonymous commands must select the same original pre-auth ID; command
preparation rejects namespace substitution. No constructor authenticates a
user, proves cookie possession, reads primary state or reserves a flow. Native
consuming owners must require the complete profile, independently derive the
submitted cookie digest under retained keys, and recheck full original intent,
current primary state, expiry and exact reservation in the sole transaction.
ID-only compatibility never substitutes for that admission. Native phase
activation and a usable OTP login remain unfinished.

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

### Restoring native command attempts

`AttemptIssuer.SealForCommand` produces a code-free `CommandAttemptRecord` from
one immutable `PrepareForCommand` submission. Its domain-separated MAC binds
the server's random attempt ID, complete continuation, operation/command scope,
mode, expected version and original submitted-code fingerprint. Keep the
original issuer key/version through dependent history retention. Native adapters
own bounded private encoding; automatic JSON/text export is rejected because
the projection includes PII. Never send it to clients or accept request-selected
attempt IDs, keys or projections.

`Verifier.ScopeDigest` provides a code-free keyed private lookup binding over
the same complete scope under an explicitly selected retained code-digest key
version. Native storage can match scope without plaintext destinations or an
unkeyed address dictionary. Rotation preserves original bytes; retired versions
deny rather than silently switching to the current key. It grants no proof,
challenge comparison, attempt allowance or primary freshness.

`VerifyCommandRecord` authenticates that historical declaration without code
access or comparison. `RestoreForCommand` additionally authenticates the same
opaque original submission, preserving its exact recovery identity without
entropy, new IDs, policy changes or renewed expiry. Neither checks a stored
challenge, current authority or durable replay. The owning PostgreSQL adapter
must still check primary replay/authority and compare inside its counted denial
or reservation transaction, with effects and terminal state committed together.
Restoration is not a public unmetered code-check or signin endpoint. Existing
legacy unbound `Prepare` attempts cannot be sealed for command dispatch.

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
# Public Send contract

`Service.Send` owns a complete Send workflow; `otp/postgres.NewSendService`
provides its native implementation. Direct callers supply trusted caller
context, a canonical destination, bounded trusted network/device dimensions,
one explicit `NewPreAuthSendFlow` or `NewSessionSendFlow`, the selected purpose,
workflow target and an exact `identity.IdempotencyKey`. They do not supply a
command ID, risk decision/digest, prepared command or domain store.

`SendResult` exposes only the original server-owned command ID, outcome and
in-progress retry delay. Committed means accepted, not delivered or authenticated.
Suppressed and issued requests have the same public result shape. Replay retains
the original selected flow, recipient/suppression, policy and expiry; changed
intent conflicts. Send does not consume pre-auth or issue/rotate a session.

Possession constructors perform no authentication or IO; IDs alone grant nothing.
Never serialize or log their private bearer bindings. HTTP proxy/origin/CSRF
admission remains the transport owner's responsibility, not this direct API.
Complete public check/consume/login orchestration, real risk-store composition
and package release gates remain in development.
