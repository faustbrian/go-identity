# OTP PostgreSQL

Go 1.27 native storage for purpose-bound OTPs, sharing the identity coordinator's
PostgreSQL transaction domain. Experimental and incomplete: this initial batch
implements challenge storage/migrations, **not** a usable issuance or verification
service, plus encrypted original-attempt command custody. Installing it never
proves a code, grants a reservation or authorizes a
workflow. Do not implement a consumer-written store to fill the remaining gaps.

## Quick start and API

```go
source := otppostgres.MigrationSource{Schema: "otp_store", Version: 100}
history, err := source.Load(ctx)
```

Import `github.com/faustbrian/go-identity/otp/postgres`. Compose the source with
the owned `go-migrations/v3` runner and its PostgreSQL backend, after the identity
kernel migrations. Allocate `Version` permanently in the single composition
history. The example is compiled in tests. `Load` is pure, cancellation-aware,
concurrent-safe and returns independently owned history. It accepts a dedicated
lowercase SQL namespace of at most 63 bytes; reserved schemas and zero versions
are invalid. The migration is atomic and forward-only; occupied namespaces fail
instead of being silently adopted. Reuse installed history via the migration
runner, never by executing installation SQL again.

## Storage and security

Native private primary reads now lock the exact keyed scope from committed
issuance and reconstruct the original core profile, counters and full-width
version. Denial/check/expiry writes use optimistic CAS plus a final database-time
expiry fence. Correct consumption is rejected by that separate counter writer.
These helpers are not exposed as a raw store or online verification API. Current
flow/lockout authority, command replay/result/audit and consuming participant
composition remain mandatory before a public attempt workflow is enabled.

`NewAttemptCodec` copies trusted local wrapping, attempt-issuer and code-digest
keyrings. `Map(ctx, attempt, retainedDigestVersion, featureSpec)` returns the
owning feature command and exact coordinator OTP plan. It requires the original
core `AttemptIssuer.PrepareForCommand` submission and matching structural scope.
The `otp.*` field namespace is reserved. Mapping performs no SQL or challenge
comparison; native restoration is private, not an online verification oracle.

Map once and keep the returned command/plan for retries. Encryption is randomized;
remapping changes command intent and cannot replace an ambiguous original attempt.
Retain original wrapping, issuer and digest-key versions while dependent command
history remains. Changing bytes under an existing version is not key rotation.
All keys are copied and concurrent codec use is safe. Configuration formatting
is redacted and serialization is denied. No provider callback is injectable.

Private destination and explicit flow/remember policy are encrypted and bound to
the exact command structure and selected digest version. The raw submitted code
remains only in opaque command custody, never in the encrypted record. Decrypted
byte buffers are cleared; Go cannot guarantee erasure of immutable reconstructed
strings. Cancellation/deadlines are checked before and after local cryptography;
OS entropy and crypto calls cannot be interrupted mid-call. No late success is
returned. Mapping is not proof of current session, challenge or account authority.

- Only versioned keyed code/scope digests are stored, never codes, destinations,
  key bytes or flow/session bearers. Key metadata has no secret material.
- Scoped identity, original expiry, issued policy and issuance linkage cannot
  be reset. Counters and row versions are monotone. Full `uint64` generations
  and versions are preserved without fractional rounding.
- Pre-account challenges preserve an explicitly empty, non-null subject; no
  invented account identifier substitutes for the original continuation.
- Stored states are issued, reserved, finalized, released, expired, revoked and
  exhausted. Successful checks share the total counter, but cannot reserve.
  Reservation custody is complete or absent, never partially nullable.
  Terminal release stores unchanged rollback ownership or the exact recovery
  successor, with no code comparison or interim reservation needed.
- Primary journal FKs preserve issuance and consumer lineage. Unresolved
  reservations cannot expire into clean release. Terminal rows cannot resurrect.
  No deletion path exists yet; retention/key retirement cleanup is pending.
- Database constraints reject impossible storage transitions; they **do not**
  establish cryptographic verification, current authority, counted replay,
  correct reservation generation, or a proof of non-commit. Those belong to the
  forthcoming native participant APIs in the sole coordinator transaction.
- All original policy fields are frozen. Full alphabet/entropy validation still
  belongs to `otp.NewCodeProfile`; SQL bounds are storage defenses, not another
  policy engine. Only trusted native adapter projections will write this store.

## Adoption, tradeoffs and FAQ

`LockoutMigrationSource` installs a separately versioned forward-only extension
after challenge custody. Private shared lockout identities use a dedicated HMAC
key over tenant/subject and tenant/channel/canonical destination, never plaintext
PII. Purpose, challenge, flow and rotating code-key versions cannot reset them.
Pre-account flows retain destination exclusion without inventing a subject.
The dedicated lockout key is pinned by an immutable digest binding; absent or
changed key configuration fails closed. Its future explicit migration must
preserve live lockouts, not initialize another empty namespace.

Future issuance must precreate these unique scope rows before exposing a
challenge. Native verification locks destination then subject before challenge
comparison, samples primary time after lock waits and denies active lockouts.
Only newly counted wrong exhaustion may extend them in the same coordinator
denial transaction as counters, audit and stable result; correct checks cannot.
The private SQL primitives do not yet activate these public workflows or replace
current session/pre-auth authority. No caller-owned lockout store is supported.

Private consuming persistence now projects one provisional correct comparison
into the coordinator-owned transaction, preserving exact original command,
attempt and generation custody. Exact successor takeover does not compare again,
renew times or charge another attempt. Finalization can commit atomically with a
protected domain effect; rollback removes both. Finalization and takeover enforce
exclusive primary database expiry even if the sampled decision time was earlier.
Reservation/takeover preserve a row-version increment for eventual terminalization.

Release persistence accepts unchanged rollback ownership or one exact recovery
successor, including after original expiry, without decrypting submitted codes.
These private helpers are not admission or noncommit proof: public sealed native
participant callbacks, current flow/lockout checks, command replay/audit and the
coordinator's authoritative recovery composition remain pending. No public raw
transaction or binding-to-release shortcut is exposed.

**Can I use this for login?** Not yet. Native issuance/send windows, original
atomic counted denial/check/reservation, live authority,
finalization/release/recovery and bounded cleanup remain in development. There
is intentionally no public raw SQL/pool/store workaround.

**Can I rotate a digest in place?** No. Existing rows keep their original retained
key version and digest. Future issuance selects the modern active profile;
retirement must preserve referenced replay tombstones.

**Does expiry release a reserved OTP?** No. Only the coordinator's authoritative
non-commit protocol can do that. A terminal release requires a newly issued OTP.

**Which checks exist?** Real isolated PostgreSQL tests exercise installed storage,
counter CAS races, expiry, immutable terminal states, full-width custody and
transaction rollback. These are not end-to-end code verification, delivery,
recovery, complete adapter coverage/mutation or release evidence.

## Release notes

See [CHANGELOG.md](CHANGELOG.md). No stable release or production-readiness claim
is made for this development checkpoint.
