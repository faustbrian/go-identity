# PostgreSQL impersonation requests and approvals

This optional adapter persists one pending impersonation request and one
approval by a different administrator. A separate opt-in activates that
exact approved grant and validates a distinct derived credential online.
Separate selections add administrator revocation and impersonated self-stop.
The adapter does not expose HTTP routes or ordinary session issuance.

## Compose

Install `MigrationSource{}` through the application's migration runner
before enabling the feature. It creates a separate, empty
`identity_impersonation` schema. It does not rewrite existing identity
tables or run automatically. The normal primary identity, password session,
TOTP, authorization epoch, risk, audit and lifecycle stores must already be
installed. The application owns the borrowed pool and other dependencies.

Pass `NewService` the same primary and the native MFA/password session
configuration, session CSRF key, privileged risk counter repository, protected
audit, lifecycle outbox and secret-envelope service. Select a policy that
explicitly authorizes the exact tenant, administrator, target and
`impersonation.scope` string set for each request or approval. Treat changes
to administrator permissions or target eligibility as authority changes:
advance the appropriate durable epochs or account version together with
the change. The configured policy revision must match the authorization
decision. Recovery is a separate policy decision on the original action
and target, distinguished by the `identity.command.recovery` resource attribute.

## Direct-Go use

1. The requesting administrator supplies their ordinary password-plus-TOTP
   session, its original CSRF token, a stable command ID, and the intended
   target, scope, reason and duration to `PrepareRequest`. Call `Execute`
   with that prepared command. A committed receipt records version 1 and its
   `Binding.RecordID` is the grant ID.
2. A different administrator supplies their own password-plus-TOTP session
   and CSRF token, a different command ID, the grant ID, expected version 1
   and a reason to `PrepareApproval`. A committed `Execute` receipt records
   version 2. Both administrators must be distinct from the target. The
   service rechecks the original requester's account and authorization before
   approval. A pending grant expires fifteen minutes after creation.
3. Retain `PreparedCommand.Binding()` as non-bearer correlation. Replaying
   the same prepared command requires current authentication and policy.
   If the caller loses the prepared value or the result is uncertain, call
   `Recover` with the original binding and the same administrator's current
   authentication, not a new command ID. Recovery does not repeat mutation.
   It authorizes at the current revision even after an approved policy change;
   the original binding and historical policy revision must remain unchanged.
   Check the receipt's `Outcome` even if `Execute` returns no error: a replay
   can return a retained `NotCommitted` receipt without a fresh error.

A receipt is historical metadata, not access authority. The retained
request and approval reasons are encrypted and are not projected into the
receipt, audit or lifecycle event. Authorization is not delegated to the
approver's target session or to a caller-selected identity. This profile
does not treat a committed counter charge or denial audit as grant approval.

## Opt in to activation and online use

Apply version 2 from `ActivationMigrationSource{}` before selecting activation.
The activation history retains version 1 byte-for-byte. Version 2 creates an
empty table, its indexes and a lineage guard; it does not rewrite, backfill or lock the
existing grant/approval tables. An older binary can keep serving the
unchanged request/approval flow. Revert the application without removing
the new table or its retained evidence.

Use `NewServiceWithActivation` with an independently generated lookup key.
Rotation to a different key denies old derived credentials; their lifetime is
at most fifteen minutes. Only approved requests with retained approval
authority versions can start. Historic approval envelopes remain valid as
historical approval receipts, but cannot start a session with authority
versions they did not record.

The original administrator calls `PrepareStart` with the exact approved
version, their current ordinary TOTP session and the original CSRF proof,
then calls `ExecuteStart`. A committed receipt may transfer one derived
credential to the caller; invoke its `Reveal` only for the authorized
response. Exact retries and recovery return the original receipt without
minting a second credential. No raw bearer, parent credential, approval
reason or synchronizer is stored in the active grant.

Call `ValidateUse` for **each** requested application permission. The service
checks the exact live grant, approved scope, current actor and target
permissions, original parent, and approver versions. It rereads the grant
after policy callbacks; a revoked or expired grant cannot be served from
a cache. The result is marked with separate actor, target and grant IDs.
It authorizes only that use, not future requests or an ordinary session.
Reserved identity and organization administration actions are excluded.

## Opt in to administrator revocation

Apply all five versions from `RevocationMigrationSource{}` before calling
`NewServiceWithRevocation` with the existing activation configuration. It
preserves both installed migrations. Version 3 adds empty terminal storage;
versions 4 and 5 each add one metadata-only guard with a five-second local lock
timeout, without rewriting or scanning existing rows. If either guard cannot
be installed, keep revocation disabled. An older request/approval/activation
binary can keep handling other grants. If migrations and application use
different database roles, permit the legacy writer roles to read the terminal
table's tenant and grant key columns for the guards. Code rollback retains the
storage and both guards; never remove them to re-enable a revoked grant.

A fresh ordinary administrator distinct from the target supplies their
password-plus-TOTP session, original CSRF proof, a new command ID, grant ID,
expected version (1 pending, 2 approved, 3 active), and private reason to
`PrepareRevoke`. The policy must allow `identity.impersonation.revoke` on the
original target with the `impersonation.grant-id` attribute. Execution checks
the administrator again and takes the exact grant lock. A committed receipt
means that the terminal version, protected audit, lifecycle event, and command
journal committed together. It does not require the target or original grant
requester to remain active.

Use the same prepared command for an exact retry or recover its original
binding after restart. Neither returns a credential or the private reason.
After commit, an existing derived bearer fails its next authoritative check.
The old request and approval are historical records, not authority; the
database guards prevent older binaries from approving or activating that
grant again.

## Opt in to impersonated self-stop

Install `SelfStopMigrationSource{}` before selecting `NewServiceWithSelfStop`.
Its version 6 adds two empty immutable tables (child synchronizer digests and
stop receipts), without modifying or locking earlier application tables.
Existing deployments can keep using the prior constructors and starts.
Code rollback retains the tables and the already terminal grant versions.

Use the same `PrepareStart` but call `ExecuteStoppableStart` to receive the
one-time derived credential and its separately revealed `StopCSRF` proof.
This profile rejects `ExecuteStart` because it cannot deliver that proof.
Reveal each only for the authorized response, and present them together to
`PrepareStop`. This path cannot retrofit a proof for an earlier activation.
Ordinary session CSRF and synchronizers from other grants are not accepted.
The action policy must allow `identity.impersonation.stop` for the original
actor on the target with the exact `impersonation.grant-id` attribute.

`ExecuteStop` makes one irreversible terminal update. It can also validate
the existing original actor session if the caller presents that original
ordinary bearer separately. A zero `Parent` means it could not be resumed,
without undoing a committed stop. Use the original credential you already
hold; the result never issues, rotates or discloses a bearer. An independently
revoked or expired grant cannot be stopped by a new command. Retain the
original binding and derived proof for `RecoverStop`, which runs current
recovery policy and returns only the command receipt.

## Opt in to keyed Start

Install the existing kernel request-key and request-key preparation
migrations alongside the selected self-stop migration. Wrap the configured
self-stop service with `NewKeyedStartService`, a stable request-key namespace
and lookup configuration, and `KeyedStartCustody` with an independent local
encryption keyring. Keep the configuration ID stable for the same deployment
and execution profile. Retain old ciphertext keys for retained requests.

Call `Start` with the same actor, approved grant/version and
`identity.IdempotencyKey` for a retry. The kernel scopes admission to the
current original actor and tenant, the canonical Start operation and POST.
The native Start and recovery policies are also required. Only the original
acknowledged mapping winner can execute and receive the original bearer and
stop synchronizer. A replay may return the original receipt but cannot
recover a bearer or synchronizer. Reusing a key for a different grant
conflicts; a retained mapping without an execution claim returns Unknown
with the original command ID and never starts the grant again.
