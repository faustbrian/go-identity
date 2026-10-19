# Changelog

## Unreleased

- Explicitly select verified-phone/password signin with closed `phoneNumber`
  input and its original target-bound browser flow. Reuse native verification,
  rate, session and recovery owners; no enrollment, OTP or MFA fallback route is
  enabled. Email and username transport contracts remain unchanged.

- Explicitly select native username/password MFA challenges with
  `SigninConfig.MFAContinuation`. Fresh committed challenges disclose only the
  original proof header and metadata, never session or CSRF credentials; the
  unselected known-empty-factor profile remains unchanged.

- Add explicitly selected username signup, signin, advisory availability and
  protected cookie rename transport through the existing native owners.
  Username routes have distinct actions and wire schemas; email routes remain
  unchanged. Preserve original retry/proof/CSRF custody and disclose no fresh
  credentials on errors, ambiguity or historical replay. Enrolled-MFA username
  signin remains unselected rather than silently downgraded.

- Compose current session custody backed by supported envelope v2. Existing
  workflow/HTTP contracts and original credential lifetimes are unchanged.

- Bind password transport to current public owners and primitive major versions;
  callers must pass matching authentication, proof and password values.

- Adopt identifier v2 input and normalization types through public source
  dependencies. Callers sharing these typed values must use `go-identifier/v2`;
  stored profile/version bindings and selected workflow behavior are unchanged.

- Adopt capability v2 public proof/grant types and explicit trusted issuer
  policy. Update capability imports and issuer-owned keys/configuration; token
  framing and native transaction/recovery ownership remain unchanged.

- Add opt-in POST /v1/password/reset/inspect with bounded body-only proof input,
  exact Origin, no-store advisory state and shared secret quotas on every read.
  No subject, redirect, session, reservation or completion is returned.
  Preserve native reset-completion denials before a receipt exists without
  inventing rollback or erasing original recovery ambiguity.

- Add opt-in password-first MFA challenge responses. Deliver the native proof
  once through `X-MFA-Token`, never JSON or a session cookie; error, ambiguity,
  replay, expiry and failed final response commitment withhold credentials.

- Add separately selected reset-completion transport with original issued-proof
  and shared challenge admission. Preserve password/proof-free recovery metadata
  on ambiguity, destroy local credential custody on every exit, and return
  replacement/session effects only after known error-free commitment.

- Add opt-in enumeration-safe password-reset request transport with exact
  callback/origin policy, signed browser-device correlation and shared delivery
  budgets. Preserve original attempt metadata for native recovery; return no
  address, reset token or session. Completion remains separately selected work.

- Preserve `rate_limiter_unavailable` on shared signin/signup admission outages
  and advertise that stable classification in both selected wire contracts.

- Add opt-in keyed browser signup for the required-email-verification profile.
  Preserve original flow/device, byte-exact header key, schema-owned fields and
  remember choice, split shared IP/identifier admission, neutral acknowledgement
  and original recovery metadata. Never issue a session or disclose account
  identity; ambiguity and replay do not retry passwords or renew custody.
  Select `FeatureConfig.Signup` alongside existing password operations.

- Add opt-in original-flow browser password signin through the native workflow
  and normalization owner. Preserve split IP/identifier rate admission, original
  remember/callback/device custody, non-keyed attempts and safe recovery metadata.
  Deliver the original secure session cookie and synchronizer only on fresh
  error-free commitment; errors, ambiguity and replay never deliver credentials.
  Select `FeatureConfig.Signin` alongside existing password operations.

- Add explicit protected cookie password-verification handlers and opt-in
  features through the distinct native cookie service. Require the original
  secure session cookie, exact trusted Origin, sole synchronizer header and
  original signed browser correlation; no bearer fallback, issuance or renewal.
  Preserve non-keyed atomic admission and original proof/error observations.
  Selected OpenAPI requires all three custody inputs together. Existing bearer
  and change-only APIs remain unchanged.

- Add explicit device-bound bearer verification composition using the existing
  signed browser correlation cookie, scoped to its original tenant/origin and
  expiry. Authorization remains the sole session credential; verification never
  issues or renews device custody. Generic bearer APIs still ignore cookies.
  Selected wire requires both inputs without advertising an authentication
  fallback. The native Authentication risk profile requires this provenance.

- Add opt-in bearer-verification features with actual closed OpenAPI 3.1.1
  requests and success/error projections. Combined password feature selection
  supports verification alongside bearer or cookie change without owner-ID
  collisions or consumer glue. Existing change-only APIs remain change-only;
  invalid selected owners return no partial feature. Cookie verification and
  native verification SQL-over-router qualification remain in development.

- Add strict bearer password-verification handlers with closed non-keyed JSON,
  atomic IP/subject rate admission and one native verification invocation.
  Deliver only the original proof locator and target/timing metadata after
  fresh known commit; retain command observations without proof on failures.
  Ambient cookies cannot substitute for bearer custody. Cookie verification,
  selected verification routing/OpenAPI and native SQL composition remain
  in development. Password-change response protections remain shared.

- Add opt-in password-change Feature contributions and explicit OpenAPI 3.1.1
  request/response contracts for the selected cookie or bearer profile. Omitted
  features expose no route or metadata; missing dependencies fail construction.
  Project recovery metadata with lower-camel-case JSON names without changing
  its Go lookup type or advertising anonymous/account-link fields.

- Add opt-in cookie/bearer keyed password-change HTTP handlers using the
  existing native workflow ports, exact original retry-key bytes and original
  completed proof lookup. Session owner discovery supplies the rate subject;
  atomic shared rate admission and original validity precede mutation. Cookie
  requests retain exact origin and primary transaction-bound CSRF custody.
  Errors retain command observations without credential delivery or retries.
  Complete password feature, OpenAPI, native SQL-over-HTTP and browser/release
  qualification remain in development.
