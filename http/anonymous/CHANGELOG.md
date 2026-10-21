# Changelog

## Unreleased

- Preserve native upgrade's exact original delivery deadline through final
  response commitment. All optional, implicit and informational writer paths
  retain the same owned-cookie, synchronizer and cache policy.

- Add explicitly selected cookie-only anonymous signin, self-deletion and
  existing-password upgrade handlers with closed JSON/OpenAPI, shared native
  admission, required Idempotency-Key and original signed browser custody.
  Both guest and permanent synchronizers are required for upgrade. Native
  owners retain all proof, transaction, replay and lifecycle authority. Only
  fresh acknowledged commits deliver credentials; historical replies contain
  metadata only. Resource transfer and other upgrade factors are unsupported.
