# Changelog

## Unreleased

- Add explicitly selected cookie-only passkey self-deletion with exact signed
  delete-proof/session custody, stored CSRF and header-only original retry key.
  Native owns current recovery and atomic removal/session effects. Fresh and
  historical responses contain durability metadata only; the password session
  is neither cleared nor renewed. Disabled selection exposes no route or wire.

- Add independently selected cookie-only credential-label updates with original
  signed update proofs, session-bound CSRF and header-only idempotency. Native
  mutation and shared secret-risk owners remain authoritative; historical
  retries return original command metadata without another credential projection.

- Add opt-in existing-account cookie-only passkey registration, identified and
  explicitly discoverable signin, and safe self-user inventory HTTP operations.
  Enrollment requires distinct genuine action proofs and original session CSRF;
  signin retains original flow/device/mode/remember custody. Keyed options retries
  return original metadata without another challenge, and consuming completion
  never redelivers credentials. Base HTTP routes and dependencies stay unchanged.
- Retain validated native durability metadata when final delivery expires or is
  canceled, without implying rollback or reporting authentication success. Keep
  owned response payloads out of middleware writers until final validation.
