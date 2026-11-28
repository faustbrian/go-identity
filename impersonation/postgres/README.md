# PostgreSQL impersonation requests and approvals

This optional adapter persists one pending impersonation request and one
approval by a different administrator. It does not activate an impersonation,
issue or revoke a session, grant target access, or expose an HTTP handler.

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
