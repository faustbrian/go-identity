# Changelog

## Unreleased

- Add an exact approved-to-active decision with fixed scope and immutable
  actor, target and parent-session lineage. Active expiry cannot outlive
  the original authorized duration or parent session.

- Add immutable bounded impersonation request binding and versioned pending
  grants for the selected M24 direct-Go consumer profile.
- Add exact-intent distinct non-target approval with fixed fifteen-minute expiry,
  redacted reasons, deterministic persistence reconstruction and stable errors.
- Session issuance, authentication, authorization and durable execution remain
  outside this storage-neutral module; full impersonation is not delivered.
