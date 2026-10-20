# Changelog

## Unreleased

- Add opaque, separately selected sessionless password-reset request/completion
  contracts. Retain the original risk issuance command independently from its
  consumer; completion retains the canonical capability, SMS, independent TOTP
  and borrowed replacement password together. These ports enable no native
  workflow or route and offer no weaker factor or email fallback.

- Derive a distinct canonical-target commitment for sessionless phone-password
  recovery. It cannot substitute for password or OTP signin intent; the native
  workflow still owns pre-auth authentication, risk and all recovery proofs.

- Describe the direct original phone-update recovery contract for independently
  selected HTTP composition. Metadata alone enables no route or workflow.

- Require a retry key for replacement completion so the native owner can
  preserve one server-owned attempt across lost responses and wrong-code
  denials. Changed bound input under that key conflicts.

- Add separately selected `ChangeService`, correlated `UpdateResult` and opaque
  code-free `UpdateRecoveryRequest` contracts. Committed replacement requires
  its real pending identifier-change cascade; history is not a new session.

- Bind replacement completion to the original SMS command/session and a
  distinct password proof for `identity.phone.update`. Keep code and caller
  custody opaque; the native workflow still owns actual proof/OTP admission.

- Add opaque authenticated phone-change initiation input binding both canonical
  numbers and exact verified-identifier predecessors. Sending must preserve the
  old number until purpose-bound confirmation; this input alone enables no
  workflow, OTP issuance or public route.

- Add separately selected, opaque self-removal request and original-outcome
  recovery contracts. Removal requires action-bound recent authentication and
  an independent usable recovery method; it does not consume an OTP or issue
  a replacement session.

- Describe the native phone signin Send and historical-recovery contracts for
  independently selected HTTP composition, without enabling routes by metadata.

- Add an opaque existing-account SMS-code signin request and workflow contract.
  Preserve canonical number and original pre-auth custody; no request field can
  select user identity, challenge, code, session or remember policy.

- Derive a separate canonical-target commitment for phone OTP signin, retaining
  the exact tenant and stored-number profile without reusing password intent.
  Native OTP admission and session composition remain separately required.

- Derive a canonical-number, comparison-profile, tenant and purpose-bound
  password-preauth identifier commitment. This does not accept an OTP, verify
  a password or enable login; the native workflow must compare original intent.

- Carry explicit current CSRF synchronizers on verification and recovery
  requests so native cookie admission can validate the caller's request.
  Bearer requests retain the structurally valid zero-token representation.

- Make existing-account verification requests and results opaque immutable
  custody, preventing nested diagnostics from traversing original proof, flow
  bearer or result correlation. Explicit Spec constructors/projections retain
  scope and durability checks, clone caller collections and bound all caller
  payloads before copying; raw projections remain sensitive and are not safe
  logging handles.

- Define neutral existing-account phone enrollment, consuming verification and
  code-free recovery contracts with bounded self/action validation, original OTP
  attempt correlation, durability/replay metadata and redacted diagnostics. Native
  execution remains separately selected and unimplemented by this core module;
  structural input validity is not authentication, ownership or session authority.

- Add explicit bounded ASCII-v1 phone number policy using pinned phonenumbers
  v2.0.14 and upstream v9.0.40 metadata, with canonical E.164 comparison,
  opt-in region-bound national input and display retention, opaque redacted
  values and exact-profile sensitive persistence/restoration. Metadata changes
  require explicit migration and ownership reverification policy; structural
  number validity is not verification, deliverability or recovery authority.
