# Changelog

## Unreleased

- Support case-sensitive enterprise provider IDs in callback wiring without
  substituting them for the OAuth parser's logical ID.

- Add explicit static enterprise OIDC start and query callback contributions.
  Use native original browser attribution and provider rate admission; deliver
  separate session and CSRF cookies only on a fresh acknowledged commit.
  Discovery can be selected independently or alongside start.

- Add opt-in HTTP and OpenAPI for anonymous static-OIDC provider discovery.
  Bind trusted tenant and browser facts to native admission, share the auth
  IP limit, and export only the advertised provider choice.
