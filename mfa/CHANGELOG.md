# Changelog

## Unreleased

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
