# Changelog

## Unreleased

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
