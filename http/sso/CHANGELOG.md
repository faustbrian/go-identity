# Changelog

## Unreleased

- Opt into SP-generated SAML logout RelayState at the start and return
  operations. Preserve the reserved signed Redirect and route a canonical
  return handle to the native one-use settlement owner. Existing no-state
  and independently selected IdP request profiles are unchanged.

- Opt into an exact opaque RelayState echo for IdP-initiated SAML logout.
  Only fresh signed replies contain it, and it never selects a destination
  or authorizes session or response-settlement behavior.

- Add cookie- and synchronizer-bound SP SAML logout start with one original
  retry key. Separate local revocation from remote delivery and expose the
  selected local outcome even when the provider continuation is unavailable.

- Let applications select IdP-initiated SAML logout without mounting inbound
  response settlement or advertising it in OpenAPI.

- Add an opt-in SAML Single Logout POST for an installed provider. The native
  owner handles signed requests and responses on separate paths through the
  handler. Cookie-free navigation can deliver a signed POST form only to the
  pinned IdP endpoint or redirect to an exact approved SP continuation.

- Add an opt-in same-browser confirmation endpoint for unsolicited SAML.
  The initial IdP POST returns a private confirmation form and scoped
  browser cookie, never a session. The confirmed native result controls
  standard credential delivery and clears the pending cookie.

- Add a separately selected, anonymous SAML SP metadata GET for the installed
  sign-in pair. Use the shared safe-read quota and publish only fresh public XML.

- Add opt-in SAML login and signed POST assertion consumer transport for an
  installed SP-initiated linked-member profile. The exact path-scoped
  correlation cookie, provider quotas and native commitment gate delivery.

- Expose explicitly selected enterprise OIDC provider logout routes. Start
  requires the original cookie, synchronizer and retry key. The one-use
  return is cookie-free and cannot disclose a redirect on refusal, timeout
  or unresolved acknowledgement.

- Add optional parsed OIDC sign-in and member-link callback owners. Pass the
  existing bounded callback custody without reparsing, retain legacy owners
  when the extension is absent, and never retry legacy completion on a typed
  owner's error.

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
