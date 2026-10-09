# Changelog

## Unreleased

- Add the private shared credential execution path for upcoming workflows:
  require completed screening before hashing, perform real dummy verification
  for unknown accounts, and discard output on cancellation or custody loss.
  Durable registration/signin and provider composition remain unimplemented.

- Add explicit registration enablement and inclusive raw password-byte limits
  over primitive-owned ephemeral secrets, without normalizing or consuming
  them. Generic signup-address validation preserves owner interpretation and
  denies implicit serialization. Complete identity password workflows remain
  in development; these checks do not authorize a credential mutation.
