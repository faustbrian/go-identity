# Changelog

## Unreleased

- Add native existing-password material replacement through the original
  coordinator transaction. Require exact current issuance parameters, lock and
  CAS the owned predecessor, and retain hash-free original-command evidence.
  Legacy material remains readable and may be replaced without changing its
  encoding first. Install additive password migration 2 and kernel replacement
  history. Reauthentication/HIBP/session and complete lifecycle workflows remain
  under development; no independent setter or authenticated endpoint is added.

- Add forward-only password material storage and bounded canonical-account
  primary reads that preserve exact hash encoding and full credential versions.
  Consistent kernel eligibility and material/version checks prevent partial
  positive results; the public core can compare real stored credentials.
  Coordinated mutations, complete lifecycle and release qualification remain
  in development. No independent setter or consumer workflow is provided.
