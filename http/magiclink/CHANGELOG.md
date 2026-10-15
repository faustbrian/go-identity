# Changelog

## Unreleased

- Bind magic-link transport to public workflow/HTTP/session owners and current
  primitive majors without changing original-link custody or admission.

- Adopt capability v2 public proof/grant types and explicit trusted issuer
  policy. Update capability imports and issuer-owned keys/configuration; token
  framing and native transaction/recovery ownership remain unchanged.

- Preserve explicitly selected native proof-parsing limits for signup links;
  default and narrower profiles still reject oversized caveat sets before
  original-source lookup. Native signature/scope checks remain authoritative.

- Opt into native MFA continuation delivery in `X-MFA-Token` with challenge-only
  metadata. Never accompany it with session cookies or CSRF custody; withhold
  expired, replayed, ambiguous, failed and mixed-session results. Protect the
  original credential header at response commitment and middleware unwind.

- Return HTTP 409 with `superseded` for authenticated obsolete links without
  issuing cookies or synchronizer credentials; document the closed wire result.

- Add opt-in enumeration-safe magic-link request transport with original browser
  custody, exact tenant/origin/callback binding, shared IP/destination admission,
  secret-safe acknowledgements and preserved unknown/committed outcomes.
- Add explicit opt-in consuming transport with original-source challenge admission
  and fresh-commit-only secure cookie/synchronizer delivery. Replay, ambiguity,
  errors and cancellation retain outcome without delivering credentials.
  Recheck original expiry at response commitment and withhold credentials from
  informational responses, including when middleware delays final delivery.
- Require the existing session-owned signed browser-device cookie and preserve
  its authenticated correlation in native request/consuming risk admission.
  Missing, duplicated, malformed, expired or foreign-scope cookies deny; no
  client-claimed device identifier or manufactured fallback is accepted.
- Document exactly the selected request/consume routes through OpenAPI; complete
  native/reference workflow qualification remains in development.
