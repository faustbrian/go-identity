# Keycloak source pins

Reviewed 2026-11-14 for the finite existing-account browser profile. Official
Keycloak tag `26.4.0` resolves to immutable source commit
`4e25e47b3c3619b3a0593448e1dfc0dd786cfbe1`.

| Official source | SHA-256 of retrieved bytes |
| --- | --- |
| [Available OIDC endpoints](https://github.com/keycloak/keycloak/blob/4e25e47b3c3619b3a0593448e1dfc0dd786cfbe1/docs/guides/securing-apps/partials/oidc/available-endpoints.adoc) | `4dedfed5e25ffe59ebb17616aa64ead84684639d2780d683f4453e1063a44dec` |
| [OIDC discovery implementation](https://github.com/keycloak/keycloak/blob/4e25e47b3c3619b3a0593448e1dfc0dd786cfbe1/services/src/main/java/org/keycloak/protocol/oidc/OIDCWellKnownProvider.java) | `2c3f00d204675afe58d1e49c96f4168e817f7e0cb12da82c1e72c58b767687bd` |
| [OIDC login response implementation](https://github.com/keycloak/keycloak/blob/4e25e47b3c3619b3a0593448e1dfc0dd786cfbe1/services/src/main/java/org/keycloak/protocol/oidc/OIDCLoginProtocol.java) | `d8d2e89f216eea547a7f62d912a23528c3eb2a7e45ba6b37fa0856ca525610fb` |

The discovery source supplies advertised query/code, subject types, algorithm
metadata, S256 and RFC 9207 support, and derives endpoints from the realm. The
login-response source adds issuer on success and denial unless the selected
client explicitly excludes it. The local catalog fixes Basic authentication,
the three identity scopes and unsupported native-token modes; broader Keycloak
server capabilities do not widen this finite builder.

The independent test provider is official image
`quay.io/keycloak/keycloak@sha256:5f3fb534cde6bf006d79f5912473e5d2c828c707cdfc52e16972803aca9d43dd`
(Keycloak 26.4.0). The isolated test realm uses an exact HTTPS issuer, generated
verified TLS certificate, a confidential code/S256 client, only profile/email
client scopes, issuer responses enabled, refresh issuance disabled and an
existing test user. No external tenant credentials or live-user data are used.
The actual realm metadata response SHA-256 for this fixture is
`5dd8c81370dd835c4964f6678f1e3f8496772821c79941bcc03946b1f1276d80`.
This value is fixture-specific, not a universal Keycloak realm metadata pin.

Keycloak source is Apache-2.0. The module does not vendor its Java source or
container. Runtime images and keys are test-provider resources, not library
dependencies. To reproduce a deployment's profile, obtain its own authenticated
realm discovery response and review/pin those exact bytes and keys; never
substitute the example realm's digest or invent tenant endpoint defaults.
