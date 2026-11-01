# Changelog

## Unreleased

- Add a bounded generic HTTPS OIDC authorization-code/query/S256 protocol client
  with exact configuration, strict existing ID-token validation, explicit
  refusal/invalid-proof/unknown outcomes and opaque token/verifier custody.
  Native state reservation, provider linking, persistence and sessions remain
  required separate composition; this does not deliver a complete signin flow.
