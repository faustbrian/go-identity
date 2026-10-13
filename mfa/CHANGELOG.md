# Changelog

## Unreleased

- Connect the bounded factor-management contract to native TOTP rename and
  independently selected HTTP/reference composition. Fresh signed TOTP proof,
  actual source session and recent primary authentication are required. Rename
  atomically consumes proof, advances factor authority and revokes subject
  sessions; replay/recovery return only original outcome metadata. This
  supersedes the native/HTTP caveat below, not the unfinished remove/replace
  and other factor-management requirements.

- Define bounded optimistic factor-management requests with exact rename,
  remove and replace selection, session custody, keyed input and fresh
  action-bound factor proof. Extend authenticated TOTP structural admission
  to factor-update and disable without accepting unrelated protected actions.
  These contracts do not yet deliver native management mutations or HTTP routes.

- Add authenticated self-listing contracts with bounded safe factor/device
  projections and remaining recovery-code counts. Empty inventory and exhausted
  codes are valid; missing authority, foreign/corrupt records and unauthenticated
  callers deny without partial metadata. Listing retains original session
  validity and rechecks current authority. Native adapter and HTTP/reference
  composition remain in development.

- Add a disjoint authenticated TOTP step-up request and immutable original
  session/action proof projection for recovery regeneration. Login and pending
  enrollment cannot supply this profile. Proof construction grants no issuance
  provenance or consumption authority; native step-up remains in development.

- Define recovery-code regeneration requests with a separate action-bound
  eligible factor proof, original session custody and exact caller scope.
  Replacement results keep reveal-once codes out of implicit diagnostics and
  serialization. Structural validation grants no proof-use authority; native
  step-up issuance and atomic replacement composition remain in development.

- Define recovery-code completion with distinct opaque code, original child and
  browser custody, stable continuation/command identities and redacted results.
  Recovery never redelivers credentials or repeats uncertain authentication;
  shared structural checks do not grant factor or session authority.

- Add explicit synchronizer custody to cookie MFA enable requests. Zero keeps
  the existing bearer profile; cookie transports must supply the original token
  and exact HTTPS-origin policy, with native CSRF fencing during enrollment.

- Add an explicit authenticated enrollment-confirmation variant of TOTP
  verification, disjoint from the existing login-child fields. Preserve legacy
  login validation and borrowed CSRF custody; activation metadata does not grant
  a session or renew pending expiry. Native activation remains unfinished.

- Preserve borrowed synchronizer custody across repeated URI-request validation;
  validation rejects zero tokens without consuming transport reveal permission.

- Define a separate TOTP URI reveal request bound to enrollment, stable command,
  original session, CSRF synchronizer and trusted origin/caller scope. Reveal
  results forbid implicit export and require no-store/no-cache transport. Native
  marker consumption and transport remain unfinished; validation grants no
  disclosure authority.

- Define keyed, subject-bound MFA enrollment input with separate original
  primary and action-specific reauthentication proofs, explicit positive
  recovery-code policy and redacted pending/recovery result contracts. Execution
  commands remain server-owned and are returned for recovery. Reveal-once code
  output uses destroyable secret owners for explicit delivery, not the opaque
  verification-input type. These contracts do not yet provide an enrollment
  service.

- Add bounded TOTP provisioning URI construction from the exact stored profile
  and borrowed secret, with escaped issuer/account labels and redacted delivery
  material. Construction grants no reveal authority; native enrollment must
  still consume its reveal marker atomically and disclose only on first commit.

- Define bounded browser TOTP-completion input and reveal-once result contracts.
  Bind the child challenge, enrolled factor, original browser cookie and trusted
  caller scope without accepting account, expiry or remember-policy overrides.
  Reject URL fragments, including empty fragments. These contracts do not yet
  provide a concrete public completion service.

- Add explicit TOTP profiles and a verifier that borrows password.Secret and
  compares opaque authentication.OneTimeCode values. Matching returns only a
  moving-factor counter; durable attempts, replay consumption and session
  permission remain owned by the protected MFA workflow.

- Add bounded TOTP skew/replay checks and comparison of opaque submitted codes
  through authentication's existing keyed-digest contract. A matching counter
  is not an authentication proof; durable replay advancement and protected
  continuation-to-session completion remain unfinished.

- Add bounded RFC 6238 computation for native TOTP verification using standard
  library HMAC-SHA1/SHA256/SHA512. Enrollment, skew policy, atomic replay
  protection and session completion remain unfinished; computation alone
  grants no authentication authority.

- Expose the immutable continuation scope digest for durable adapter binding;
  preserve the existing signed scope bytes across mutable attempt transitions.

- Add immutable browser partial-authentication continuations with exact original
  primary-proof, tenant, subject, origin, factor/policy and remember-policy
  bindings to the existing one-use capability format. Factor methods share one
  bounded attempt budget; expiry, exhaustion and version conflicts are explicit.
  These contracts do not yet provide durable issuance, factor verification or
  completed MFA session orchestration.

- Distinguish known-empty second-factor authority from unknown or enrolled state
  when admitting email-only password recovery. Full MFA workflows remain pending.
