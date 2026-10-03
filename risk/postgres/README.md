# Risk PostgreSQL adapter

Experimental, Go 1.27. This module is being built as the durable owner of risk
evidence and decisions. It is **not yet an executable durable risk service**.

## Implemented boundary

- `MapIssue` accepts only an opaque successful core evaluation and matching
  trusted identity binding. `IssueOperation` fixes its closed native schema.
- The native decoder verifies every signed field and current configured policy.
  Its required record target derives from the versioned keyed pre-provider
  intent, so exact primary admission does not need raw request facts.
- The internal response codec uses the existing secret-envelope AES-256-GCM
  implementation and a concrete copied local keyring. Original times and exact
  scope are authenticated; rotation preserves retained responses without
  renewing freshness. It cannot invoke network key providers inside Work.
- `MigrationSource{Schema: "identity_risk", Version: allocation}` provides a
  dedicated, forward-only issued-evidence schema. Allocate its version in the
  composition's single history after the identity kernel. Never renumber an
  applied version or adopt unmanaged objects.

## Adoption and security

The official executor will own plan construction, shared-Work journal writes,
authorized primary resolution and exact original-response replay. Application
code must not supply a private transaction, journal or workflow substitute.
Mapping and encrypted bytes establish neither durability nor protected recovery
authority. No bearer may be exposed until the sole coordinator proves commit.
Expiry, missing metadata or a failed read never establish rollback.

Trust actor kind, policy and correlation from server composition, not transport
input. Record IDs, digests, native commands and encrypted response material are
internal custody data, never operation results or log fields. Retain wrapping
keys for every retained encrypted result. Go cannot guarantee memory erasure.

## Remaining work

Same-Work issuance and audit/lifecycle/receipt atomicity; primary resolve/recovery;
reservation/finalization/release; durable lockouts/counters; CAPTCHA participants;
investigation, retention and anonymization; real PostgreSQL integration, complete
public examples/API baseline and package/release verification remain pending.
There is no supported login or phone recovery workflow from this module yet.
