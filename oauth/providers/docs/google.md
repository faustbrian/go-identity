# Google built-in browser profile

This finite profile constructs the existing `oauth.OIDCProvider` through
`oauth.NewGoogleAccountsProvider`. It adds provider facts, not a token verifier,
transaction/state engine, account mapper or session authority. Apple signing
behavior is unchanged. Full catalog coverage remains unfinished.

## Fixed selection

| Fact | Selected value |
| --- | --- |
| Stable provider ID / aliases | `google` / none |
| Issuer | `https://accounts.google.com` |
| Authorization endpoint | `https://accounts.google.com/o/oauth2/v2/auth` |
| Token endpoint | `https://oauth2.googleapis.com/token` |
| Browser response / PKCE | `code`, `query`, `S256` |
| Signature algorithm | `RS256` |
| Token authentication | `client_secret_post` only |
| Default scopes | `openid`, `email`, `profile` |
| Explicit scopes | Unique subset of those three, always including `openid` |
| State / nonce | Existing native state custody and required ID-token nonce |
| Raw callback issuer | Required and exactly canonical |
| Signed issuer forms | Canonical HTTPS and documented `accounts.google.com`, canonicalized only after full validation |

These are the selected catalog decisions, not every feature Google supports.
In particular, metadata also advertises Basic, other response modes and plain
PKCE; this builder does not enable them. It exposes no endpoint, issuer,
algorithm, credential-channel, arbitrary-parameter or alias override.

## Configuration, ownership and failures

Supply a positive trusted configuration `Version`, registered `ClientID`,
`ClientSecret`, exact HTTPS `RedirectURI` and trusted `oauth.SigningKeySet`.
`Clock` and `HTTPClient` retain the generic OAuth owner's semantics; a nil clock
selects system time and a nil client selects its fresh standard transport.
The caller provisions/updates actual Google verification keys and retains
borrowed clock/transport collaborators. Neither constructor fetches discovery
or JWKS or trusts an issuer-selected key URL.

The builder forwards only the existing resource controls: `Timeout`, `ClockSkew`,
`MaxResponseBytes`, `MaxTokenBytes` and `MaxCodeBytes`. Their zero defaults and
bounds are the OAuth owner's: timeout 10s (1..30s), skew 1m (positive..5m),
response 64KiB (1KiB..1MiB), token 16KiB (256B..16KiB), code 4KiB (1B..64KiB).
Earlier caller deadlines win. Nil scopes select defaults; an explicitly empty,
duplicate, openid-free or unlisted set denies rather than silently expanding it.
Configuration/constructor failures return fixed `ErrGoogleConfiguration` with
no source values; formatting and JSON/text serialization cannot expose secrets.

The existing owner copies credentials/scopes and clones the transport; callers
clear their source secret and close the returned provider. It disables redirects,
ambient cookies, connection replay and insecure TLS and starts no background
worker. Each exchange retains original code/PKCE/token bytes and must follow
native state reservation; there is no retry or new authority in the builder.

Supply the constructed provider to the native `oauth/postgres` link/signin
configuration. A successful existing-account flow uses only canonical issuer
and unchanged verified subject, current directory/credential/factor policy and
the original native browser/state/session owners. Email/display claims cannot
select a user or authorize implicit linking. Unsupported selections do not
create capabilities or global registrations.

## Retained scope and evidence boundaries

The complete Google catalog row still requires its declared additional-client,
hosted-domain, parameter, UserInfo/claims mapping, native-token, refresh,
revocation/unlink and logout decisions and interoperability. Those cells are
not implemented or advertised by this constructor. It is not signup, direct
ID/access-token signin, One Tap, proxy or shipped Reference Google support.
The global 43-row matrix retains its blocking states; this page does not replace
its schema or report Google/the unit verified.

Deterministic tests use actual RSA signatures and authenticated test TLS at the
fixed hostnames through a caller-owned loopback transport. Native consumer proof
uses the existing real PostgreSQL/account/session path, not substitute stores.
Such tests establish controlled integration only, not live Google acceptance.
See [source pins and update procedure](google-sources.md).
