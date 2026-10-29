# Changelog

## Unreleased

- Add independently selected strict-bearer metadata Get/List with exact self or
  optional organization ownership, bounded live-view pagination and safe stored
  modern/legacy/terminal record projections. Reads require current native
  authority and shared safe-rate admission, not mutation ports or fresh action
  proofs. Bodies and idempotency keys are forbidden; no key secret, digest,
  principal, verification/debit or partial failed page is exposed.

- Add an explicitly selected organization-owned create profile and typed native
  port, retaining the human manager as actor. Rotation/revocation can project
  selected native organization outcomes without fabricating user ownership.
  Owner input and schema stay absent by default; original keyed rate admission,
  reveal-once response custody and unknown recovery remain unchanged. Supply
  profile-scoped native mutation ports so user-only HTTP cannot act on org keys.

- Add explicitly selected strict-bearer modern API-key creation, rotation and
  revocation routes using original-key native workflows, shared secret-rate
  admission, closed bounded JSON and reveal-once committed response custody.
  Disabled features expose no route or OpenAPI operation. Native organization,
  legacy, quota, cache and API-key-session profiles are not selected.
