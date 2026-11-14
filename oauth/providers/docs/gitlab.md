# GitLab existing-account OAuth2 profile

`NewGitLab` selects the provider catalog's OAuth2 profile, not GitLab OIDC.
The deployment owner supplies registered client credentials and a distinct
HTTPS callback URI. Empty `Issuer` means `https://gitlab.com`; an explicit
self-managed issuer is an exact HTTPS deployment base without trailing slash,
userinfo, query, fragment or ambiguous path. Endpoints are that base plus
`/oauth/authorize`, `/oauth/token` and `/api/v4/user`.

The fixed profile is code/query/S256, `client_secret_post`, exactly `read_user`,
and bearer HTTPS current-user lookup. The sole subject is a positive JSON int64
`id`, projected to canonical decimal. Email, username and display fields are
not linking authority. No ID token, JWKS, discovery or nonce proof is selected.

## Native composition and callback defense

Supply the returned existing `oauth.Provider` to `oauth/postgres.NewLinkService`
and `NewSigninService`; complete signin through `NewSigninCompletionService`.
Consumers provide real migrated native dependencies and trusted configuration,
not account/session stores or permission callbacks. Link explicitly from an
existing authenticated self session before permitting existing-account signin.

Register one exact redirect URI per authorization server. The provider registry
rejects shared callback routes when this variant is selected. At the transport
boundary call `oauth.ParseOAuth2QueryCallback(ctx, rawQuery, receivedRoute,
provider.OAuth2Profile())`, where `receivedRoute` is the trusted actual route
without query, not an inbound Host/issuer/redirect field. Unexpected `iss`
parameters deny; strict existing OIDC parsing still requires exact RFC 9207
`iss` on both success and denial. Native encrypted state binds the full base
profile and additional UserInfo facts before state reservation or PKCE release.
Parsing alone is never state, account or exchange authority.

The provider makes one token POST and one bearer UserInfo GET, with no redirect
or retry. Original UserInfo observation validity is at most twenty seconds,
capped by original access-token expiry, and survives native retention without
renewal. This is local observation evidence, not provider authentication age.
OAuth2 ID-token issued/expiry and authentication-time projections remain absent.
Supplied nonce arguments are rejected, not silently ignored.

## Ownership, limits and errors

Construction performs no network operation. Credentials and scopes are copied;
clear source secrets after construction. The provider clones and owns its
standard transport; supplied clock/transport inputs must be concurrent-safe.
Do not mutate inputs during construction. Close only after admitted calls
finish; closure clears the copied secret and idle connections, with no
goroutine started by the provider. Configuration refuses implicit serialization
and redacts formatting. Errors omit provider bodies, credentials and URLs.

Default total timeout is ten seconds, configurable from one to thirty seconds.
Response default is 64 KiB, configurable from 1 KiB to 1 MiB. Token default/max
is 16 KiB, configurable down to 256 bytes. Code default is 4096 bytes, bounded
from 1 to 65536 bytes. Duplicate JSON fields, noncanonical IDs, conflicting
callbacks and unsupported scope grants deny. Ambiguous post-send failure is
Unknown and native owners do not retry an original consumed code.

## Exclusions and adoption

This finite profile excludes signup, email matching, implicit account linking,
MFA completion, direct native tokens, refresh, revocation, remote logout and
enterprise routing. Local logout uses the existing native session owner.
Current strict OIDC HTTP/Reference adapters do not automatically expose OAuth2;
applications must compose the explicit native variant at their trusted route.
The complete provider catalog and broader OAuth goals remain binding.

Independent OAuth2 oracle checks are not live GitLab interoperability. See the
[source and oracle record](gitlab-sources.md) for that distinction.
