# Risk PostgreSQL adapter

Experimental, Go 1.27. This module is being built as the durable owner of risk
evidence and decisions. It is **not yet an executable durable risk service**.

## Implemented boundary

- `MapIssue` accepts only an opaque successful core evaluation and matching
  trusted identity binding. `IssueOperation` fixes its closed native schema.
- The native decoder verifies every signed field and current configured policy.
  Its record target is the canonical opaque command ID; the private retained
  intent digest never becomes audit/lifecycle aggregate metadata. A committed
  response resolver must compare that digest separately after authorization.
- The internal response codec uses the existing secret-envelope AES-256-GCM
  implementation and a concrete copied local keyring. Original times and exact
  scope are authenticated; rotation preserves retained responses without
  renewing freshness. It cannot invoke network key providers inside Work.
- `MigrationSource{Schema: "identity_risk", Version: allocation}` provides a
  dedicated, forward-only issued-evidence schema. Allocate its version in the
  composition's single history after the identity kernel. Never renumber an
  applied version or adopt unmanaged objects.
- `IssuanceIDMigrationSource{Base: originalSource, Version: laterAllocation}`
  appends the opaque command-ID profile without changing the original history
  or retained legacy ciphertext/AAD. Install this complete history for new native
  issuance. Legacy digest-target rows remain retained, not silently rewritten.
- `NewRepository(Config{...})` supplies the native issuance contributor. Enlist
  that exact instance with the identity repository, audit and lifecycle adapters
  in one coordinator registry. It inserts through the coordinator's active Work,
  materializes at database time and returns only a provisional structural receipt.
  The coordinator commits evidence, protected `identity.risk.decide` audit,
  `risk.evidence_issued.v1` lifecycle and command result together.
- Recovery examines native linkage only during the locked coordinator invocation.
  Positive or inconsistent evidence keeps the command unresolved; native absence
  can contribute to unanimous negative evidence because this initial journal
  never prunes rows. Neither expiry nor a private pool lookup permits release.

## Adoption and security

The official executor will own plan construction, authorized primary resolution
and exact original-response replay. Application
code must not supply a private transaction, journal or workflow substitute.
Mapping and encrypted bytes establish neither durability nor protected recovery
authority. No bearer may be exposed until the sole coordinator proves commit.
Expiry, missing metadata or a failed read never establish rollback.

Trust actor kind, policy and correlation from server composition, not transport
input. Record IDs, digests, native commands and encrypted response material are
internal custody data, never operation results or log fields. Retain wrapping
keys for every retained encrypted result. Go cannot guarantee memory erasure.

## Remaining work

Official executor and authorized primary response resolution/replay;
reservation/finalization/release; durable lockouts/counters; CAPTCHA participants;
investigation, retention and anonymization; complete
public examples/API baseline and package/release verification remain pending.
There is no supported login or phone recovery workflow from this module yet.
