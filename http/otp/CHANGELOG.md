# Changelog

## Unreleased

- Document first-primary OTP establishment through an explicitly selected native
  profile and original sole-verified change policy. HTTP selection alone still
  grants no such authority and existing routes/responses remain unchanged.

- Add opt-in genuine-primary email-change OTP request, consuming confirmation
  and code-free recovery features/handlers. Require original committed change
  provenance, current cookie/CSRF/rate authority and independent code delivery;
  success returns `changed`, not authentication credentials or renewed authority.

- Add explicit cookie/Origin/synchronizer-protected pending-email OTP Send,
  completion and code-free recovery handlers with concrete OpenAPI schemas and
  original-source rate admission. This verification-only profile returns no
  credentials or replacement session and rejects alternate identity/custody.

- Compose current session custody backed by supported envelope v2. Existing
  workflow/HTTP contracts and original credential lifetimes are unchanged.

- Bind OTP transport to the public OTP/HTTP/session owners and current primitive
  majors; preserve selected admission, attempt and cookie policies.

- Adopt identifier v2 input and normalization types through public source
  dependencies. Callers sharing these typed values must use `go-identifier/v2`;
  stored profile/version bindings and selected workflow behavior are unchanged.

- Add explicitly selected email-signin Send transport and optional combined
  Send/signin/recovery feature. Original flow/device custody and header-only
  idempotency remain mandatory; safe acceptance never reveals recipient or
  delivery state. Other purpose/channel/MFA profiles remain in development.

- Add explicit recovery-only and combined signin/recovery feature selection
  with concrete original-correlation OpenAPI schemas and one shared flow scheme.
  Disabled recovery contributes no route or metadata; historical results never
  advertise live authentication or credential delivery.
- Add explicit original-flow signin recovery HTTP handling and typed middleware.
  Recovery is code-free historical observation, shares strict IP admission, and
  never repeats consumption or delivers session/CSRF credentials.
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
