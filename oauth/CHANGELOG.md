# Changelog

## Unreleased

- Add distinct existing-account callback input with original preauth-cookie
  custody and trusted browser attribution. Callback shape does not select a
  local user, infer Remember policy, or grant exchange/session authority.

- Add distinct existing-account signin initiation input and result contracts.
  Bind original preauth browser custody, resolved Remember policy and configured
  service/flow scope without treating them as authentication. Native initiation,
  callback/session composition and full social-login acceptance remain required;
  explicit-self linking and its callback input are unchanged.

- Add a typed terminal provider-error redirect outcome with no identity or
  session projection. Only the exact committed state-consumption receipt and
  original validated application error callback can produce it.

- Expose pure query-callback profile validation so transport construction can
  reject unsupported configuration without parsing synthetic provider input.

- Add typed committed linked-account/allowlisted-redirect outcomes and redacted
  original callback-rate attribution. Callback actors are resolved natively from
  state and original browser custody, not selected by transport or a new session
  lookup. Linking preserves remember policy and does not issue a session.

- Add typed explicit-self link initiation and parsed callback requests with
  exact allowlisted callbacks, explicit scope selection, canonical original
  browser/caller checks and refused diagnostic serialization. These structural
  requests are not session, state-consumption or account-link authority.

- Preserve defensive parse-time provider/configuration provenance on successful
  and denied query callbacks through `Profile()`, and expose the selected
  query-only `Callback` alias. Native flow/configuration matching and state
  admission remain independent requirements; provenance is not authentication.

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
