# Changelog

## Unreleased

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
