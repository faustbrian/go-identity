# OTP PostgreSQL

Go 1.27 native storage for purpose-bound OTPs, sharing the identity coordinator's
PostgreSQL transaction domain. Experimental and incomplete: this initial batch
implements challenge storage/migrations, **not** a usable issuance or verification
service. Installing it never proves a code, grants a reservation or authorizes a
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

**Can I use this for login?** Not yet. Native issuance/send windows, original
attempt restoration, atomic counted denial/check/reservation, live authority,
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
