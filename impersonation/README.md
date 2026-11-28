# Impersonation request binding

This independently versioned module supplies the storage-neutral part of the
selected M24 direct-Go pending request and one-distinct-admin approval profile.
It is not the complete impersonation feature. A successful pure transition
does not authenticate an administrator, authorize an operation or grant access.

`NewActor` and `NewTarget` use the pinned identity module's identifier syntax,
preserving exact case and spelling. The target also binds its current account
version. `NewScope` owns a sorted copy of 1–64 distinct printable non-space ASCII
permissions, each at most 128 bytes; duplicates are invalid. `NewReason` preserves
1–1024 UTF-8 bytes, rejects whitespace-only text, redacts implicit formatting and
has a SHA-256 digest. `StorageText` is explicit protected-storage access, never
safe logging or target-facing presentation. Unkeyed digests are not anonymous.

`NewPolicy` binds an exact policy ID and nonzero version. This profile fixes
one distinct approver, also distinct from the target, and a fifteen-minute
request-to-decision deadline. `NewRequest` binds tenant, original actor,
target/account version, canonical scope, reason digest, requested duration and
policy ID/version. Duration must be at least one second and at most fifteen minutes.
Zero typed values, unknown statuses, mismatched tenants and self-targets fail
closed. No constructor normalizes identifier text or discovers eligibility.

`NewPendingGrant` produces version 1 in `StatusPendingApproval`, with deadline
exactly fifteen minutes after supplied trusted creation time. `Approve` requires
the exact grant ID and pending version, identical complete intent, same-tenant
distinct approver, nonzero reason and a trusted decision time not before creation
and strictly before expiry. It returns version 2 `StatusApproved` and a separate
immutable approval; neither input is mutated. Expiry is not renewed. Errors are
stable redacted `Error` classifications (`ErrInvalidInput`, `ErrConflict`,
`ErrExpired`). Times are stored as UTC without monotonic data. There is no
clock, random source, I/O, goroutine or mutable store in this module.

## Durable consumer responsibilities

Before either transition the adapter must authenticate a non-impersonated
administrator using their own current password-plus-TOTP session, fresh within
fifteen minutes, and original CSRF. It must enforce the actual current target
eligibility, account state/version, actor authority and scope-specific policy,
including protected service/super-administrator and organization restrictions.
Approval revalidates both original requester and approver; the target's factor
or effective permissions must never satisfy the administrator's requirements.

Persist one versioned grant and distinct immutable approval rows. In the same
transaction atomically compare the actual stored version and binding, record
the keyed original result and audit/risk/outbox effects. Two concurrent pure
calls can both produce snapshots: only the durable compare-and-swap chooses a
winner. Repeated pure approval conflicts; keyed durable retries must recover
their original result, including unknown-commit recovery. Cancellation,
not-committed/committed/unknown outcomes and resource ownership belong there.

Rehydrate protected original fields with their validating constructors, call
`NewRequest`, and verify `Request.Digest()` equals the stored digest before any
decision. The canonical binding uses SHA-256 over the domain string
`identity.impersonation.request.binding.v1`, each string prefixed by its unsigned
64-bit big-endian byte count, and unsigned 64-bit big-endian numeric values:
tenant, actor user, target user, target version, scope count, sorted permissions,
the raw 32-byte reason digest, duration in nanoseconds, policy ID, policy version.
The domain string is also length-prefixed. Actor and target tenants have already
been validated equal to the encoded tenant. Binding is separate from a native
keyed command fingerprint. Reconstruct pending snapshots using original ID and
creation time; reconstruct approved snapshots by applying the persisted original
approval against that pending snapshot at the original decision time. This is
structural validation, not renewed authorization or permission to replay effects.

All full lifecycle names are recognized by `Status.Valid`, but this profile
exposes only pending creation and pending-to-approved. Denial, revoke, activation,
session issuance/restoration, lineage/presentation, quorum reads, HTTP transport,
expiry persistence and authoritative online session checks are unsupported.
There is no bearer token, `SessionIssuer` stub, mutable aggregate approval list or
private authorization engine. Completing this module alone does not deliver M24.

See the executable external-package `ExampleApprove` for the public call shape.
