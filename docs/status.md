# Suspend, ban and restore

## API and adoption

`NewUserStatusService` composes `UserStatusRepository`, the existing `UnitOfWork`,
the exact upstream `authorization.Service`, redaction and `UserStatusConfig`.
It freezes transition/reason configuration without I/O. Dependencies and policy
callbacks must be bounded and concurrency-safe. No goroutines or stores are
owned by the service.

The four literal operations are `UserSuspend`, `UserRestore`, `AdminUserBan`
and `AdminUserUnban`. Trusted composition supplies `ActorScope`; never decode it
from client input. Role labels or IDs are not authority. Both admission and the
post-primary-read decision must allow the exact current policy revision.

`UserStatusRequest` contains the stable random command ID, exact tenant/user,
expected aggregate and user-authority versions, registered reason, optional
absolute expiry, trusted actor context and safe correlation. Creation of a
`UserStatusCommand` is only structural validation, not authorization. The
compiled `ExampleNewUserStatusCommand` demonstrates adapter-facing access.

## Versions, replay and expiry

`User.Version` is an aggregate version; profile updates may advance it without
changing user authority. `UserStatusRecord.AuthorityVersion` is the separate
monotonic security dimension. Every authority change also advances the aggregate.
New commands fence both counters under the durable owner's lock. Overflow must
fail closed. A future expected version is rejected before execution; an older
version may enter the owner for same-command replay before locked CAS. Changed
input conflicts and cannot create another effect.

Suspend/ban require a configured reason code (not free-form text), bounded to
512 UTF-8 bytes. Zero expiry means indefinite. A nonzero expiry must be strictly
future and no later than the configured maximum at new-command admission,
microsecond-exact and representable in PostgreSQL years 1..9999. It is normalized
to UTC without altering its instant. Retain it unchanged across retries; a
historical replay remains valid after that expiry.

Expiry does not itself make the user active or resurrect credentials. The
required expiry executor must submit an audited, fresh version-fenced restore or
unban command. Manual restore is only from suspended; unban is only from banned.
Their new user-authority version prevents old sessions, grants and keys from
becoming valid again. Terminal anonymized/deleted identities cannot be restored.

## Admission versus cleanup

The one UnitOfWork owner must atomically persist status/expiry, both next
versions, the audit, lifecycle event/outbox, immutable required-consumer snapshot
(IDs and public-contract fingerprints), random cascade ID at generation 1 and
original result. `RequiredConsumers` returns the exact ordered
`identity-lifecycle-consumers-v1` set, including unavailable consumers.

Suspend/ban emit `identity.suspended.v1` and `identity.user.suspend` audit;
restore/unban emit `identity.restored.v1` and `identity.user.restore` audit.
Admission receipts contain every required consumer as `RevocationPending`.
The service rejects fabricated completed receipts or missing consumer entries.
Commitment proves only owner admission. No asynchronous mutation, consumer
acknowledgement or aggregate closure is inferred. Denial is effective at commit;
cleanup failures must leave pending cleanup rather than roll authority back.

## Outcomes, recovery and security

The existing closed `CommitOutcome` remains authoritative. Lost replies or
malformed receipts yield Unknown, not rollback. `RecoverUserStatus` is an exact
tenant/user/actor/operation primary lookup with current authorization, never a
second Execute. It returns historical state, not current login authority.
The receipt keeps its original policy identity/version even after policy changes;
current policy and redaction govern whether it can be disclosed now.
Cancellation, redaction failure, callback panic or a dependency error after a
valid receipt withhold output without erasing known commitment. User and cascade
projection are disclosed together only after successful complete redaction.
Commands are immutable copies, redact all formatting and reject JSON persistence.

## Tradeoffs and pending integration

Explicit dual expected versions make retries stable and avoid conflating profile
updates with revocation. They are core adapter inputs; HTTP session freshness,
CSRF and keyed idempotency admission remain transport responsibilities.

The storage-neutral service and its atomic-seam tests do not prove SQL durability,
crash recovery, consumer acknowledgement, event serialization, cache denial
deadlines or external revocation. PostgreSQL integration, the immutable
fingerprint snapshot, audited expiry executor, cascade query/closure APIs and
full Service/catalog composition remain required implementation. No complete
identity platform or release claim follows this slice.
