# Changelog

## Unreleased

- Add explicit registration enablement and inclusive raw password-byte limits
  over primitive-owned ephemeral secrets, without normalizing or consuming
  them. Generic signup-address validation preserves owner interpretation and
  denies implicit serialization. Complete identity password workflows remain
  in development; these checks do not authorize a credential mutation.
