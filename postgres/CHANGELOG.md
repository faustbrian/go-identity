# Changelog

## Unreleased

- Supply immutable forward-only user schema migrations through `go-migrations`,
  enforcing tenant/user uniqueness, bounded case-sensitive IDs, registered
  lifecycle states and full-width positive integer versions without rounding.

- Add bounded primary tenant/user reads with lossless uint64 version decoding,
  strict projection validation and redacted failure classifications. This
  initial development adapter does not yet include its durable mutation
  coordinator and is not ready for adoption.
