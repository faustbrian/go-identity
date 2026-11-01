# Changelog

## Unreleased

- Add bounded query callback parsing with required exact RFC 9207 issuer binding,
  duplicate/conflicting response rejection, original code/state custody and a
  separate provider-denial state lookup. Parsing does not authenticate state,
  reserve a transaction or authorize exchange; native lifetime and one-use
  checks remain required. Provider error text is deliberately not exposed.

- Add a bounded generic HTTPS OIDC authorization-code/query/S256 protocol client
  with exact configuration, strict existing ID-token validation, explicit
  refusal/invalid-proof/unknown outcomes and opaque token/verifier custody.
  Native state reservation, provider linking, persistence and sessions remain
  required separate composition; this does not deliver a complete signin flow.
