# Changelog

## Unreleased

- Accept exact case-sensitive native tenant identifiers in sealed OIDC proxy
  evidence, preserving the original tenant bytes in authenticated bindings.

- Add an opt-in identity-only OIDC proxy exchange boundary. Dispose parsed
  refresh tokens through one configured same-origin RFC7009 request before
  accepting verified identity, including cleanup on proof rejection. Preserve
  unknown disposal for reconciliation without exposing or persisting tokens;
  ordinary OIDC exchange and OAuth2 revocation remain unchanged.

- Add authenticated handoff of minimal OIDC code-exchange evidence to an exact
  preview recipient. Bind the original exchange client, transaction, signed
  times, Remember policy and rotating keys without forwarding tokens or claims.

- Add an opt-in exact canonical Google hosted-domain constraint for direct
  credentials. Require the signed `hd` string after existing strict Google
  validation, reuse bounded selected-claim projection and reject missing,
  malformed or mismatching claims without inferring authority from email.
  Default direct verification, code flow and identity shape stay unchanged.

- Add direct bounded Google ID-token credential verification on explicitly
  selected Google providers, reusing strict signature/issuer/client/nonce/time
  validation and opaque identity evidence without token exchange or custody.
  Reject companion hashes when their original token/code is unavailable;
  preserve authentication-time presence and signed evidence lifetime. Browser
  CSRF/origin, one-use initiation and local account/session authority remain
  separate; this does not complete One Tap.

- Allow callers to request the exact scopes bound to a stored OAuth2 refresh
  token explicitly. Existing refresh calls still omit scope on the wire.

- Add an explicitly selected shared-issuer OAuth2 refresh adapter, including
  string-subject profiles, using the existing scoped refresh engine and exact
  original profile/token custody. Preserve original grant scopes and explicit
  rotation evidence without UserInfo, identity, storage or retry authority;
  ordinary refresh selection and provider policies remain unchanged.

- Add explicitly configured RFC7009 refresh-token revocation for ordinary and
  shared-issuer OAuth2 profiles. Borrow existing original-token custody and
  provider credentials for one bounded same-origin HTTPS POST; distinguish
  HTTP200 acknowledgement from coherent refusal and unknown outcomes without
  retrying, following redirects or inferring related-token/session effects.
  Native admission, storage and recovery remain separate.

- Add pure static OIDC authorization rendering from normalized secret-free
  profile facts and original state, nonce and S256 challenge, without opening
  credentials, consulting keys or starting a provider. Existing provider and
  Google instance validation, lifecycle and authorization URLs remain unchanged.

- Add pure shared-redirect OAuth2 authorization rendering from validated
  secret-free profile facts and original state/S256 challenge, without opening
  credentials or starting a provider. Existing instance lifecycle checks and
  distinct-route social behavior remain unchanged.

- Add a separate shared-redirect OAuth2 token and HTTPS identity-resource
  client. It checks issuer-parsed custody, exact profile, original state and
  S256 challenge before exchange; retains bounded string or integer subject
  evidence and optional scalar observations without inventing an ID token.
  Distinct-route social providers and native reservation ownership are unchanged.

- Add separately selected shared-redirect OAuth2 code/query/S256 callback
  parsing with exact trusted-route and decoded RFC 9207 issuer binding on
  success and denial. Reuse bounded code/state custody and destruction without
  inventing OIDC proof, distinct-route UserInfo facts or exchange authority;
  existing OIDC and social OAuth2 callback selections remain unchanged.

- Add opt-in bounded projection of selected verified OIDC ID-token claims.
  Preserve absent, null, string and boolean values after full token validation;
  default providers and refusal/unknown handling are unchanged. The result
  grants no identity mapping or authorization policy.

- Add a separately selected ordinary OAuth2 HTTPS token-endpoint refresh adapter
  with original persisted-profile and actual-grant scope binding, redacted token
  custody, explicit rotation or retain-original outcomes, and definitive grant
  rejection versus refusal/unknown classification. Existing provider defaults and
  public shapes are unchanged; no UserInfo, retry, storage, identity or session
  authority is added.

- Add explicit closed GitHub OAuth-app token/resource policy without changing
  existing public config/profile shapes or strict zero defaults. Bind fixed
  cross-origin UserInfo, comma reported scopes and honestly absent token expiry;
  original identity evidence remains bounded independently of token lifetime.
  Add a policy-bound distinct-route callback parser; no refresh flow is added.

- Add an explicit OAuth2 code/query/S256 and bearer-UserInfo variant with
  separate immutable protocol facts and distinct registered redirect-URI mix-up
  defense. Preserve strict OIDC callbacks and public ProviderProfile shape;
  OAuth2 observations do not invent ID-token or provider authentication claims.

- Accept Google's two documented identity-scope URI spellings only under
  explicit Google Accounts selection and only for equivalent requested scopes.
  Collapse equivalent spellings without expanding grants; preserve generic
  strictness, exact request configuration and original token bytes.

- Add explicit `NewGoogleAccountsProvider` selection for Google's canonical and
  documented legacy signed ID-token issuers, projecting one canonical account
  issuer and unchanged subject after full validation. Bind the selection in an
  omitted-false provider profile; generic constructors, strict callback query
  issuers and existing profile bytes remain unchanged. No implicit signup,
  catalog, One Tap or live-provider interoperability is added.

- Support explicitly configured `client_secret_post` for HTTPS OIDC code
  exchange. Keep credentials in the token form only, bind the chosen method
  into callback configuration and preserve existing public/Basic behavior.
  There is no automatic credential-channel fallback.

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
