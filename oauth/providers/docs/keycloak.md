# Keycloak existing-account browser profile

`NewKeycloak` returns the existing `*oauth.OIDCProvider` for an explicitly
configured realm. It does not implement enterprise SSO or organization routing.

```go
provider, err := providers.NewKeycloak(providers.KeycloakConfig{
    Version: 1,
    Issuer: configuredRealmIssuer,
    ClientID: registeredClientID,
    ClientSecret: loadedSecret,
    RedirectURI: exactRegisteredCallback,
    Metadata: reviewedDiscoveryBytes,
    MetadataSHA256: configuredDiscoveryPin,
    KeySet: trustedRealmSigningKeys,
    HTTPClient: httpClient,
})
if err != nil {
    return err
}
clear(loadedSecret)
defer provider.Close()
// Supply provider to the existing oauth/postgres linking/signin composition.
```

## Trust and selected behavior

The deployment owner obtains the realm's exact
`{issuer}/.well-known/openid-configuration` over authenticated HTTPS, reviews it,
and configures its SHA-256 pin separately. Hashing arbitrary callback-provided
metadata is not authentication. Metadata and issuer are trusted startup inputs,
never selected from callback parameters. A changed document requires a reviewed
new pin and configuration version; no runtime discovery, silent pin update,
JWKS refresh or background worker is introduced.

Construction bounds metadata to 64 KiB and 128 top-level members, rejects
duplicate decoded names and malformed JSON, and requires exact configured issuer
equality. Authorization, token, UserInfo and JWKS URLs come from that document,
with no endpoint defaults. This finite profile requires canonical HTTPS URLs
under the exact issuer plus `/`, without query, fragment, userinfo, percent
encoding, dot segments or doubled path separators. Cross-origin and cross-realm
endpoint deployments are not selected. The trusted key-set collaborator is
provisioned from the pinned `jwks_uri` and remains caller-owned; a metadata hash
does not establish that the provided keys came from that endpoint.

| Decision | Selected contract |
| --- | --- |
| Stable provider ID | `keycloak`; no aliases or runtime ID guessing |
| Response | `code`, `query`; no hybrid or form POST |
| Client authentication | `client_secret_basic` only |
| Scopes | Nil selects `openid`, `profile`, `email`; explicit unique subset must retain `openid` |
| PKCE and nonce | Advertised S256 required; nonce required and validated |
| ID-token signing | Advertised RS256; existing strict signature/time/issuer/audience/azp validation |
| Callback issuer | Metadata must advertise RFC 9207; exact `iss` required on success and denial |
| Account selection | Explicit authenticated link, then exact pre-existing issuer/subject signin |
| Session | Existing native issuance/read/local logout; no provider session claim |

The selected Keycloak client must keep **Exclude Issuer From Authentication
Response** disabled. Advertising support in discovery does not override a
client-specific compatibility switch: a real response without `iss` still fails
closed before exchange. Register the exact HTTPS callback, enable the standard
authorization-code flow and confidential client authentication, and require S256.
Configure the client's default/optional scopes so returned grants cannot exceed
the selected identity scopes. Unlisted returned scopes are not silently dropped.

The existing OAuth owner copies the client secret and scopes, clones/hardens the
standard HTTP transport, and owns its copied resources until `Close`. Nil clock,
HTTP client and zero limits select that owner's documented defaults. Invalid
configuration returns only `ErrKeycloakConfiguration`; formatting and implicit
JSON/text serialization cannot disclose configuration or credentials.

## Explicit limits

No signup, email-based implicit linking, direct/native-token signin, UserInfo
enrichment, refresh operation, remote logout, revocation or unlink operation is
added by this constructor. Discovery advertisements do not enable these paths.
The generic token custody may contain a provider-returned refresh token, but
this builder exposes no refresh capability. Mutable profile/email fields never
select or merge a local identity. Unimplemented catalog claims remain required
and unverified, not non-applicable or supported by a generic default.

## Verification and updates

[Source pins](keycloak-sources.md) identify the official Keycloak revision and
immutable independent test-provider image. The integration-tagged provider test
requires `KEYCLOAK_TEST_ADDRESS` for the owned loopback TLS port and
`KEYCLOAK_TEST_CA` for its generated certificate. Its test-only realm/client/user
names and credentials are isolated fixture inputs, not live provider access.
It exercises an actual Keycloak login page, code callback, strict exchange and
code-replay rejection. With no fixture selected it skips and is not evidence of
interoperability. Controlled signed-token tests separately exercise issuer,
audience/authorized-party, nonce and signature rejection.

Before updating, retrieve and hash the official sources and deployment-specific
metadata again, compare capability/issuer/client-compatibility decisions, review
keys and realm configuration, and rerun the affected provider/native consumer
tests. One selected realm/profile does not qualify all Keycloak configurations,
the complete provider catalog or the whole identity milestone.
