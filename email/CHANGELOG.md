# Changelog

## Unreleased

- Add typed `VerificationConfirmRequest` with bounded non-consuming proof,
  exact HTTPS callback structure and trusted caller/network admission. This
  does not authenticate the proof, authorize a mutation or create a session;
  native confirmation/result and transport composition remain required.

- Reject malformed ports and bracketed hosts in constructed verification URLs
  as well as parsed configuration, without normalizing callback identity.

- Add email-owned signup verification grant policy that preserves anonymous
  origin and prospective-user separation, binds exact mailbox/version/callback
  intent with retained keyed commitments, and denies scope or expiry changes.
  Signing, scanner-safe confirmation and atomic consumption remain separate
  obligations; authenticated identifier-management proofs are unchanged.

- Prevent parsed-address disclosure through private consumer diagnostic fields
  while preserving canonical/display projections and raw-input compatibility.

- Add email-owned immutable address policy, exact mailbox admission, stable
  versioned canonical comparison, fixed IDN domain processing and explicit
  display retention. This does not establish ownership or deliverability.
