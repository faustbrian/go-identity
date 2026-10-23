# Changelog

## Unreleased

- Add opt-in existing-account cookie-only passkey registration, identified and
  explicitly discoverable signin, and safe self-user inventory HTTP operations.
  Enrollment requires distinct genuine action proofs and original session CSRF;
  signin retains original flow/device/mode/remember custody. Keyed options retries
  return original metadata without another challenge, and consuming completion
  never redelivers credentials. Base HTTP routes and dependencies stay unchanged.
- Retain validated native durability metadata when final delivery expires or is
  canceled, without implying rollback or reporting authentication success. Keep
  owned response payloads out of middleware writers until final validation.
