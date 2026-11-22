# Changelog

## Unreleased

- Add opt-in linked-member OAuth2 browser sign-in. Share the keyed start
  route with a configured OIDC provider when both are selected, and use a
  separate OAuth2 callback with original transaction quotas, native issuer
  settlement and fresh-commit session and CSRF cookie delivery.

- Add opt-in explicit enterprise member linking on the existing keyed start
  and shared OIDC callback. Require original cookie and same-origin CSRF;
  authenticate native callback mode without fallback and deliver no cookies
  on link completion. Unselected and ordinary sign-in are unchanged.

- Support case-sensitive enterprise provider IDs in callback wiring without
  substituting them for the OAuth parser's logical ID.

- Add explicit static enterprise OIDC start and query callback contributions.
  Use native original browser attribution and provider rate admission; deliver
  separate session and CSRF cookies only on a fresh acknowledged commit.
  Discovery can be selected independently or alongside start.

- Add opt-in HTTP and OpenAPI for anonymous static-OIDC provider discovery.
  Bind trusted tenant and browser facts to native admission, share the auth
  IP limit, and export only the advertised provider choice.
