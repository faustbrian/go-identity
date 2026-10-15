# Changelog

## Unreleased

- Compose supported envelope v2 custody and matching public native participants.
  Callers supplying envelope/keyring services must use `/v2` types; stored
  ciphertext, original authority lifetimes and transaction ownership stay intact.

- Use current public workflow, HTTP and native participants with matching
  primitive-major values; retain original issuance, proof and journal custody.

- Adopt identifier v2 input and normalization types through public source
  dependencies. Callers sharing these typed values must use `go-identifier/v2`;
  stored profile/version bindings and selected workflow behavior are unchanged.

- Adopt capability v2 public proof/grant types and explicit trusted issuer
  policy. Update capability imports and issuer-owned keys/configuration; token
  framing and native transaction/recovery ownership remain unchanged.

- Enable explicitly configured public signup-by-link through original browser
  request, encrypted delivery and atomic account/session creation. Existing
  verified accounts sign in without duplicate creation. Authenticate prospective
  original custody for HTTP quota admission without fabricating current users;
  use the corrected mailbox/browser supersession family for resends.

- Retain existing-recipient original login custody even when requested through
  the signup-enabled profile. Preserve submitted input identity while selecting
  storage format from actual creation; required MFA completion and exact request
  retries no longer misinterpret existing accounts as prospective creation.

- Commit explicitly selected enrolled-TOTP primary login as an atomic signed
  MFA continuation, consuming the original link without creating a session.
  Preserve original browser, primary expiry, remember policy and factor epoch
  in encrypted preparation; audit failure rolls back all challenge effects.
  Retry and proof-free recovery retain outcome without credential redelivery.
  Complete public TOTP session completion remains in development.

- Opt into primary-link requests for known MFA-enrolled accounts while retaining
  original factor generation in signed issuance. The default still suppresses
  enrolled accounts; challenge consumption and public MFA login remain unfinished.

- Reconstruct original magic-link primary metadata from authenticated consumed
  parent custody and committed encrypted request history for MFA completion.
  Match the whole original payload, recipient, browser scope and signed lifetime;
  never request the primary bearer again or renew historical risk permission.
  Public MFA completion and challenge branching remain unfinished.

- Retain complete signin request commands in a versioned encrypted origin
  profile inside the existing preparation journal. Preserve legacy retry
  decoding without relabeling old ciphertext. Origin-only reads fail closed for
  legacy records whose original command fields cannot be recovered; upgrade all
  request writers before enabling the forthcoming MFA challenge workflow.

- Consume original prospective links through protected account creation, real
  empty-factor and authorization initialization, one-use finalization and
  session issuance. Creation and session lifecycle effects share the same
  transaction; collisions and storage failures roll back. Replay and recovery
  never recreate bearer custody. Public signup remains disabled while required
  MFA continuation and complete transport composition are unfinished.

- Generate prospective identity only after original journal admission, retain
  it in encrypted request output and fence availability again before staging.
  Occupied mailboxes receive neutral acknowledgements without delivery or
  account creation. Consuming composition can authenticate the exact committed
  original creation intent without renewing request risk or regenerating IDs;
  public signup remains disabled until creation and session wiring is complete.

- Bind prospective signup payloads to frozen creation IDs, attributes and
  mailbox policy without manufacturing existing user or factor authority.
  Delivery verification retains the explicitly selected issuer limits;
  public signup request/consume composition remains in development.

- Bind resends to the exact original recipient/browser scope and atomically
  supersede earlier unused links. Validate original browser authority before
  returning the typed superseded result; competing consumption retains the
  shared native transaction fence and original recovery provenance.

- Add native original-browser magic-link request, encrypted delivery, scanner
  inspection and explicit atomic capability/session consumption using existing
  owner journals and current recipient/factor/risk authority.
- Add frozen address normalization for shared HTTP destination admission without
  account lookup or recipient disclosure.
- Add purpose-bound consumption rate-source lookup with original browser/grant
  custody, current recipient and exact query-policy revision. It discloses only
  sensitive rate metadata, performs no use reservation, and never renews expiry.
- Preserve authenticated committed request receipts when an accompanying error
  or cancellation prevents successful disclosure; errors do not imply rollback.
- Exercise selected HTTP request/delivery/consumption against native PostgreSQL
  rate, capability and session owners, including foreign-browser denial and replay.
- Complete resend, MFA/signup and reference composition remain in development.
