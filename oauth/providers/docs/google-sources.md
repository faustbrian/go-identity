# Google source pins

Reviewed 2026-11-13 without credentials or authenticated Google flow access.
These are exact response-byte pins for the finite built-in browser profile,
not a claim of live Google interoperability or full catalog conformance.

| Official source | Revision / retrieved SHA-256 |
| --- | --- |
| [OpenID configuration](https://accounts.google.com/.well-known/openid-configuration) | Retrieved 2026-11-13; `f86b185fd428f81d7efaa83ec256693b3abedb57ddfcc6a826f5f396b4827f02` |
| [OpenID Connect documentation](https://developers.google.com/identity/openid-connect/openid-connect) | Page updated 2026-10-29; raw HTML `0f59f947396987ecd73df03d5d424b145cb26e48ba53c4a7b9e5c85cde9febe0` |
| [Web-server OAuth flow](https://developers.google.com/identity/protocols/oauth2/web-server) | Retrieved 2026-11-13; raw HTML `88ecdfdaf3dd6b89204accbb736ced6efb33635afc74fd0db992afc9cdd9d3a6` |

The metadata independently supplies the exact canonical issuer and authorization,
token, UserInfo, revocation and JWKS endpoints. Its selected relevant members
are `id_token_signing_alg_values_supported=[RS256]`, the three identity scopes,
query/S256 and POST support, and
`authorization_response_iss_parameter_supported=true`. Therefore this profile
keeps the existing mandatory exact raw callback issuer policy; documented
signed-token issuer compatibility cannot widen that boundary.

The OpenID Connect article's token validation sections require original signed
proof verification and describe the canonical and legacy Google token issuer
forms and stable `sub`. Its subject guidance, not mutable email/display data,
owns the account namespace. The web-server token exchange uses the exact
registered redirect and configured client credentials. The local catalog selects
POST despite metadata also allowing Basic, and closes requested scopes despite
Google supporting additional API permissions in other profiles.

Google developer documentation is published under its page-declared Creative
Commons Attribution 4.0 terms, with code samples under Apache 2.0. This module
does not vendor the HTML or samples; raw retrieved responses are retained in
the private implementation evidence. Endpoint facts are fixed at construction;
runtime metadata fetch or silent pin update is not enabled.

To update, fetch the same official HTTPS resources, retain raw bytes/date/hash,
compare the selected fields and issuer/subject/credential clauses, and review
catalog differences before changing code. Run affected fact, actual RSA/TLS and
native consumer tests. Changing facts for active flows requires deliberately
new trusted configuration identity, not mutation of retained state. Preserve
earlier results and blocked interoperability cells; never infer a capability
from an added metadata member.
