# Changelog

## Unreleased

- Add explicit signin-only feature selection, real router middleware binding
  and concrete OpenAPI 3.1.1 request/result schemas. Disabled selection exposes
  no signin route or metadata; unknown outcomes remain credential-free.
- Add typed signin middleware and router rebinding with opaque request-local
  state, detached outcome observation, and retained session/CSRF response custody.
  Short circuits, cancellation and repeated continuation cannot bypass native
  admission or forge credentials.
- Reject middleware response trailers, including credential fields injected
  during unwind; fresh credentials remain confined to owned response headers.
- Add opt-in original-flow OTP signin HTTP handling with exact-origin/cookie
  possession, closed request grammar, source-bound shared rate admission, and
  reveal-once secure session/CSRF delivery only on fresh native commitment.
- Preserve code-free correlation and original commit outcomes on ambiguous
  results without retrying the consuming workflow. Complete feature/server
  composition and release qualification remain in development.
- Retain prepared recovery before issuance and meter trusted IP before native
  source lookup, then debit only the retained canonical identifier dimension.
