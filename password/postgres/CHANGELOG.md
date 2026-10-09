# Changelog

## Unreleased

- Add native single-factor password reauthentication using the original bearer,
  counted/audited abuse admission and current locked primary owners. Commit the
  original signed proof, required audit and lifecycle event together without
  creating or extending sessions. Exact configured targets and capped original
  lifetime deny scope expansion. Code-free outcome recovery never redelivers a
  proof; unknown outcomes must not be automatically retried. Install password
  migration 3 and the selected kernel/session/authorization/audit/outbox histories.
  Protected atomic consumption, other factor profiles and complete password
  lifecycle/release qualification remain in development.

- Add bounded primary retrieval of original signed password reauthentication
  records through authentication's public source contract. Pending, aborted,
  absent, foreign and malformed records expose no partial proof or renewed
  freshness. Install additive password migration 3; native issuance, current
  authority checks, atomic consumption and retention remain in development.

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
