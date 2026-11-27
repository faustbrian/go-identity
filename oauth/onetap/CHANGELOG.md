# Changelog

## Unreleased

- Add a distinct immutable, redacted `BrowserRedirectStartRequest` with the
  existing bounded transport input shape and exact original bindings. Accept
  only selected redirect-button options, preserve retry and resolved Remember
  policy, and deny cross-mode conversion, zero/wire construction and JSON/text
  export. The existing callback request still rejects redirect options; neither
  request selects a provider, client, login URI or native flow authority.
- Add explicitly selected redirect-button options and a typed launch projection
  from the separately configured Google redirect validator and original
  provider-bound transaction. Derive the registered login URI, client, base64url
  nonce, canonical flow-ID button state, exact parent origin and original
  lifetime without accepting replacement launch values. Existing prompt/popup
  constructors and JSON remain unchanged. This non-authoritative projection
  issues/consumes no state and requires native fresh-commit admission before
  release; it supplies no renderer, HTTP decoder or browser qualification.
- Add explicitly configured read-only provider-bound Google button redirect
  validation with an exact same-origin HTTPS endpoint. Preserve original mode,
  nonce, provider/client, policy, cookie, cutoff and RememberPolicy; require the
  separate Google double-submit CSRF proof before JWT verification and recheck
  original expiry afterwards. Existing callback constructors remain unchanged;
  durable redirect initiation, HTTP delivery and live browser
  interoperability are not supplied.
- Add an immutable, redacted browser-start request that retains the exact
  bounded transport context, retry key, prompt/button and resolved Remember
  policy for native execution without selecting provider or flow authority.
- Add immutable constructor-validated prompt or popup-button options with an
  explicit exclusive start choice and detached typed non-secret projection.
  Preserve closed GIS values, explicit cancellation and bounded optional width.
  This option slice is not a keyed native intent, durable initiation or browser
  interoperability proof; popup selection remains separate from redirect validation.
- Add provider-bound callback verification using the persisted original Google
  provider/version/client/callback mode and independently derived flow-cookie
  digest. Preserve the complete provider-bound original projection and recheck
  its expiry after verification without consuming state.
- Add an optional trusted startup hosted-domain restriction enforced only by
  Google's signed exact `hd` claim, never an email suffix or browser hint.
- Add callback-mode-only read-only Google One Tap CSRF/origin/original pre-auth
  validation before the published pinned Google credential validator. Preserve
  original nonce, cookie, record version and RememberPolicy in a redacted typed
  result without creating local authentication or durable completion authority.
- Redirect initiation/HTTP delivery, durable browser credential release, email/linking policy,
  active-state reservation/replay prevention, session/link completion and live
  Google browser interoperability remain unsupported.
