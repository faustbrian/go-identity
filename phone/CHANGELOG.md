# Changelog

## Unreleased

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
