# OAuth relying-party protocol

`github.com/faustbrian/go-identity/oauth` implements one explicit HTTPS OIDC
authorization-code client: query response mode, S256 PKCE, a required nonce,
and configured ES256/RS256 signing keys. The explicitly selected Google provider
also verifies a borrowed Google ID-token credential without a code exchange.
Go 1.27.0 or newer is required.

This is a protocol boundary, **not a complete social signin or linking workflow**.
Native authenticated transaction/state reservation, encrypted PKCE persistence,
account policy, token vault, identity mutation, session issuance, HTTP and reference
composition remain separate required owners. Calling this client does not confer
any of those authorities. It does not complete M17, M18 or unit qualification.

`NewOIDCProviderWithClaims` optionally selects exact scalar ID-token claims for
a trusted mapper. `ExchangeResult.VerifiedOIDCClaims` returns the validated
token's selected strings and booleans, preserving absent and null separately.
It returns no raw token or unselected claim map and confers no authorization.
Default providers do not project claims.

## Consumer sequence

1. Configure one `OIDCConfig` with explicit HTTPS authorization/token/issuer and
   exact callback URI, positive trusted configuration version, client ID,
   `PublicClient`, `ClientSecretBasic` or explicitly selected `ClientSecretPost`,
   exact scopes including `openid`,
   signing algorithms and a trusted locally available `SigningKeySet`.
2. `NewOIDCProvider` performs validation only, with no network access. Its
   immutable `Profile` is the secret-free configuration the native transaction
   owner must bind. Keep the provider open for the supported flow lifetime.
3. The native initiation owner generates and durably binds state, nonce and
   PKCE under its authenticated transaction. `Authorization` builds the fixed
   code/query/S256 redirect; only deliberate `AuthorizationRequest.URL()` access
   reveals it to the intended browser. Never log it.
4. Parse `r.URL.RawQuery` with `ParseQueryCallback(ctx, rawQuery, boundProfile)`.
   `boundProfile` is the exact immutable provider profile frozen into the native
   transaction, never a configuration/version/issuer selected by callback data.
   The native owner then validates exact provider/client/issuer/redirect,
   response transport, transaction/tenant/operation/session and other required
   bindings, **reserves one-use state before decrypting PKCE**, and supplies
   the original `identity.OAuthCallbackInput` plus `NewPKCEVerifier` custody.
   Raw inbound state is never proof of admission.
5. Call `Exchange` once using that transaction's expected nonce. A successful
   result contains `ProviderIdentity` admitted by the existing strict
   `authentication/oidc` validator, not an auth-v1 principal or a raw claims map.
   It is not local account, link, reauthentication or session authority.
6. Encrypt tokens at the native vault seam through `TokenSet.Use`. Its typed
   byte projection is borrowed synchronously and cleared on return. Explicitly
   `Destroy` token, verifier and original callback custody after bounded use,
   including later native failure. No durable secret storage is implemented here.

`ClientSecretPost` sends the original client ID and copied secret only as form
members of the HTTPS token request. It never adds Basic authentication or puts
the secret in an authorization URL. Empty, control-containing or oversized
secrets fail construction. Select the method from the immutable provider
profile; there is no automatic fallback between credential channels. Prefer
Basic unless the selected provider profile requires POST authentication, as
described by [RFC 6749 section 2.3.1](https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1).
This generic capability does not itself implement the built-in Google catalog
or claim Google interoperability.

## Explicit Google Accounts selection

For a configured Google Accounts provider, call
`NewGoogleAccountsProvider(config)` instead of `NewOIDCProvider(config)`, with
`config.Issuer` exactly `https://accounts.google.com`. All other configuration,
trusted key, ownership and shutdown requirements are identical. This explicit
selection consumes `authentication/oidc/v2`'s Google-only policy; the generic
constructor continues using its released strict validator.

Only a fully verified original ID token may use either Google's canonical
`https://accounts.google.com` issuer or its documented `accounts.google.com`
form. Both return the canonical issuer and the exact unchanged subject, so the
native account lookup uses one issuer/subject namespace. Signature, audience,
authorized party, nonce, time and present access-token/code hashes remain
mandatory checks. Original signed token bytes are neither rewritten nor used
to choose the configured key source. No discovery occurs in either constructor.

Google may report the identity scopes as
`https://www.googleapis.com/auth/userinfo.email` and
`https://www.googleapis.com/auth/userinfo.profile`. The explicit Google selection
projects these to `email` and `profile` only when that short scope was requested.
Equivalent short/URI spellings collapse to one granted permission. Exact URI
configuration otherwise stays unchanged; unknown or unrequested scopes still
fail. Requested scopes and original access, refresh and signed ID-token bytes
are unchanged. The generic constructor does not apply this policy. See Google's
[response-scope contract](https://developers.google.com/identity/protocols/oauth2)
and [identity scope equivalents](https://support.google.com/cloud/answer/15549945).

`ProviderProfile.GoogleAccounts` binds the selected policy into the existing
native immutable configuration and retained transaction snapshot. Its false
value is omitted from JSON, preserving strict profile bytes. Never change the
selection for an in-flight transaction: policy mismatch must deny rather than
reinterpreting the retained callback. This flag is trusted startup metadata,
not a claim, callback option or authentication proof.

The RFC 9207 raw callback `iss` must still equal the canonical configured issuer;
the signed-token policy does not accept a legacy query issuer or aliases in
discovery metadata. This finite configured-key profile is not a built-in catalog,
Google One Tap, automatic signup/email merge or live Google interoperability
claim. The Google issuer policy is owned by the explicitly selected upstream
validator, not an application-level JWT rewrite.

### Direct Google credential verification

`OIDCProvider.VerifyGoogleCredential` accepts `GoogleCredential{IDToken: bytes}`
and `GoogleCredentialNonce{OriginalNonce: nonce}` only on an explicitly configured
`NewGoogleAccountsProvider`. The credential bytes are borrowed synchronously:
the caller owns and clears them, must not mutate them during the call, and must
not log or persist them. The nonce must be the original canonical 32-byte nonce
from the trusted initiating transaction, never a value taken from the credential
or its callback. Neither typed input grants admission or transaction authority.

The method reuses the pinned strict Google validator and returns only the same
opaque `ProviderIdentity` as code exchange. Issuer forms, signature, audience,
authorized party, subject, time and nonce remain checked. An absent `auth_time`
remains absent, not replaced by `iat`; the original signed `exp` caps evidence.
Any present `at_hash` or `c_hash`, including JSON null, fails because this input
has no original access token or authorization code against which to verify it.
The method never contacts a token endpoint, exchanges or returns access/refresh
tokens, stores credentials, selects keys from callback data, or creates a local
identity, link or session. It uses only the configured caller-owned key set.
The existing Google constructor and its full configured-provider lifecycle remain
required; this method does not add a second provider configuration path.

Nil/zero/non-Google/closed providers, invalid borrowed input and a missing or
noncanonical original nonce return `InvalidInput`. Invalid signed proof returns
`InvalidProof`; cancellation or the bounded provider deadline returns
`Unavailable`, preserving `errors.Is` for the context cause. Errors and input
diagnostics do not disclose the credential or nonce. Verification does not consume
the nonce or prevent a second verification of the same valid credential.

This is not a complete One Tap callback. Its future browser owner must first
validate cookie/body CSRF and authorized-origin bindings; the durable initiation
owner must bind and atomically consume nonce/state, provider/client, tenant and
mode/redirect policy. Generic OAuth owners retain account/link/session authority.
No browser, replay, hosted-domain/email-policy, prompt/button/redirect or live
Google interoperability qualification is claimed here.

```go
result, err := provider.Exchange(ctx, originalCallback, decryptedVerifier, boundNonce)
if err != nil {
    // Classify *oauth.Error. Never automatically re-exchange a code.
    return err
}
defer result.Tokens.Destroy()
return result.Tokens.Use(ctx, func(ctx context.Context, tokens oauth.TokenBytes) error {
    return encryptForNativeVault(ctx, tokens.AccessToken, tokens.RefreshToken, tokens.IDToken)
})
```

The names above represent native-owned inputs and encryption, not missing
pluggable domain stores consumers must invent. The composed native workflow is
not yet provided by this module.

## Explicit OAuth2/UserInfo variant

`NewOAuth2UserInfoProvider` selects code/query/S256, POST client credentials and
bearer HTTPS UserInfo without inventing OIDC claims. Its optional
`OAuth2UserInfoFacts` retains immutable additional facts without changing the
public `ProviderProfile` struct shape. Use a distinct registered redirect URI
per authorization server and `ParseOAuth2QueryCallback` with the trusted actual
received route. A shared callback URI or unexpected `iss` is rejected. Existing
OIDC constructors/parser semantics remain unchanged. `EvidenceExpiresAt` is
original signed OIDC expiry or bounded original OAuth2 observation expiry;
OAuth2 supplies no ID-token/authentication times. Native state and current
authority remain separate mandatory owners. See the GitLab provider profile
for finite existing-account adoption and unsupported operations.

The additive `NewOAuth2UserInfoProviderWithPolicy` selects an explicit closed
`OAuth2TokenPolicy`; zero preserves the original strict contract. The GitHub
OAuth-app policy alone permits its fixed cross-origin UserInfo, comma response
scopes and honestly absent token expiry. Native callers bind the optional policy
alongside full UserInfo facts and use `ParseOAuth2QueryCallbackWithPolicy` at the
trusted distinct route. `TokenSet.ExpiresAt()` is zero only when that selected
provider omits expiry; identity evidence remains bounded to the original read's
twenty seconds. No public config/profile struct shape or existing default changes.

### Shared-redirect OAuth2 identity resource

`NewSharedOAuth2UserInfoProvider(config, claimNames)` selects a separate
nonce-free client for a shared callback. Its static HTTPS endpoints share the
configured issuer origin and use POST client authentication. Select the exact
string subject format or the positive JSON integer format; neither coerces the
other. Explicit scalar claim selection retains absent, null, string, and
boolean without granting policy authority. The legacy social `Provider` does
not accept this profile.

Build the authorization URL from the original native state and S256 challenge.
Parse callbacks with `ParseSharedOAuth2QueryCallback` using the exact original
provider profile and received route. The native owner must authenticate and
reserve the transaction and decrypt its original verifier before calling
`Exchange`. `Exchange` rejects wrong custody, state, or challenge before I/O;
an admitted call performs one token POST and one bearer identity GET without
redirects or retries. The identity is not an OIDC assertion or authentication
timestamp. Its evidence deadline is fixed when the identity read begins and
cannot outlive the bearer token. Preserve denial/unknown outcomes through the
native owner. Move successful `TokenSet` custody directly to that owner's vault
and destroy inputs, tokens, and provider-owned credentials when finished.

## Explicit ordinary OAuth2 refresh

`NewOAuth2RefreshProvider(provider)` separately selects refresh for an existing
ordinary `OAuth2UserInfoProvider` with zero token policy. It does not add refresh
to `Provider`, existing providers, OIDC, or any catalog preset. This selection
uses that provider's exact immutable HTTPS token endpoint, POST client credentials,
bounded owned HTTP/1 transport and lifetime; keep the provider open until admitted
operations finish. Construction performs no I/O. Basic/public client methods and
the GitHub response policy are not selected by this adapter.

Only after the native owner authorizes the owned account, admits its expected
durable token generation and decrypts the stored refresh secret may it construct
`NewRefreshToken(secret, storedProviderProfile, actualStoredGrantScopes)`. Supply
the original persisted profile and actual grant scopes, not current caller input
or broader configured scopes. Construction snapshots them; refresh rejects any
profile mismatch before releasing credentials. Copies share destruction and one
concurrent borrow admission, but this is **not durable single-flight, one-use or
retry authority**. Native generation locking, envelope encryption, finalization,
unlink/version races and unknown-result recovery remain mandatory separate owners.

`Refresh(ctx, custody)` performs at most one bounded POST and never requests
UserInfo, follows a redirect, retries, issues identity evidence, changes an account,
or issues a credential or session. The form omits `scope`: under
[RFC 6749 section 6](https://www.rfc-editor.org/rfc/rfc6749#section-6), its effective
scope is the original stored grant. Missing response `scope` therefore preserves
those scopes, never the broader provider configuration. Explicit response scopes
must be a subset; `Tokens.ScopeReported()` preserves the distinction.
`Tokens.RequestedScopes()` records the effective original refresh-grant scopes,
whereas `Tokens.GrantedScopes()` records the new access-token scopes. A narrower
access-token scope does not redefine the refresh grant's original scope.

Success returns owned redacted `TokenSet` custody and an explicit `Rotation`:
`RotatedRefreshToken` supplies the returned replacement; `RetainOriginalRefreshToken`
supplies **no** refresh bytes and instructs the native owner to preserve the safe
predecessor. A replacement must replace the predecessor according to section 6;
its presence does not prove when the provider invalidated the old token. Encrypt
through `Tokens.Use` and destroy all temporary custody promptly on every path.
Receipt time and required positive bounded expiry describe only provider tokens,
not authentication age, native authorization or session validity.

`RefreshGrantRejected` means a coherent `invalid_grant` response: the provider
definitively rejected the submitted grant, which may be expired, invalid, revoked
or bound to another client. It is not proof of a specific revocation cause.
Other coherent refusals return `Refused` and must not erase the stored grant.
Malformed/oversize responses, transport failures, cancellation after attempt,
redirects and contradictory responses return `Unknown`, since rotation may have
occurred. Local invalid custody/configuration returns `InvalidInput`; pre-attempt
cancellation returns `Unavailable`. No error authorizes automatic retry.

## Query callback boundary

`ParseQueryCallback` accepts only the query authorization-code profile. It
requires exactly one nonempty `code` or `error`, canonical 32-byte state, and
`iss` equal to the exact expected issuer, including on provider denial. It
rejects all decoded duplicate parameter names (including percent-encoded
aliases), conflicting security members, and known token/hybrid/JARM members.
The full RFC 6749 Appendix A.11 code grammar is preserved without trimming or
truncation. Malformed input returns typed `InvalidInput`; local cancellation
returns `Unavailable`. Neither outcome performs provider or database I/O.

Success exposes the existing opaque root `identity.OAuthCallbackInput` through
`Input()`. A coherent provider error instead has `Denied() == true` and no code
custody. `UseDeniedState` synchronously lends a private bounded state copy for
native transaction lookup and auditing. It is **not authentication, admission,
or a state capability**. Provider error codes, descriptions and URIs are checked
for bounded protocol syntax and deliberately discarded, not exposed as
diagnostics or redirects. Unknown valid error codes remain typed denials.

`Callback` is an alias for the selected query-only `QueryCallback`, not another
wrapper or support for hybrid/form-post responses. For success and denial,
`Profile()` returns a defensive secret-free snapshot of the exact validated
parse-time profile, including configuration version, issuer, client, redirect,
scopes, algorithms and limits. Source and returned slice changes cannot alter
it. This metadata remains readable after `Destroy`; a zero/invalid callback
returns the zero profile. The snapshot preserves parsing provenance only. The
native consumer must independently match it against the original flow and
current or retained configuration, authenticate bindings/lifetime and reserve
actual state. The projection adds no authentication, admission or new lifetime.

```go
parsed, err := oauth.ParseQueryCallback(ctx, rawQuery, boundProfile)
if err != nil {
    return err // malformed/cancelled, never exchange
}
defer parsed.Destroy()
if parsed.Denied() {
    return parsed.UseDeniedState(ctx, lookupAndAuditNativeDenial)
}
originalCallback, _ := parsed.Input()
// Authenticate complete native bindings and reserve state before decrypt/exchange.
```

The example names native-owned values and the required native denial handler;
it is not a provided endpoint or completed native workflow. Callers must freeze
the exact trusted profile at initiation and enforce the native transaction's
authenticated expiry and one-use rules. Parsing adds no clock, expiry or new
lifetime, and a parsed result does not make expired/replayed state valid.
Destroy promptly on every exit. Aliases share destruction; an admitted
synchronous borrow may finish on its private copy, which clears on return.
Concurrent/reentrant denial borrows deny; consumers must not retain bytes,
copies or asynchronous access. The raw query belongs to the caller and cannot
be erased by the parser; do not log request URLs or retain callback data.

Before percent decoding, the parser bounds total raw input to
`3*MaxCodeBytes + 16 KiB` and 32 members. Decoded names are at most 64 bytes;
values are bounded to the configured code limit, 43-byte state, 2048-byte
issuer/error URI, 256-byte error, 1024-byte description, or 4096-byte extension.
Encoded values cannot exceed three times their decoded ceiling. Security
members use their RFC ASCII grammar; ignored extension values must be valid
UTF-8. Unknown response extensions are ignored after these checks, as required
by [RFC 6749 section 4.1.2](https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2).
Required exact decoded issuer comparison follows
[RFC 9207 section 2.4](https://www.rfc-editor.org/rfc/rfc9207#section-2.4).
These are rejection limits, never truncation or additional callback authority.

## Outcomes and recovery

| Kind | Meaning |
| --- | --- |
| `InvalidInput` | Construction/custody/preflight denied before send. |
| `Unavailable` | Local cancellation prevented an attempt. |
| `Refused` | Coherent definitive OAuth error from the configured endpoint. |
| `InvalidProof` | Completed exchange failed the configured OIDC identity proof. |
| `Unknown` | Attempted exchange lacks a trustworthy terminal outcome. |

The client performs no retries and follows no redirects. Transport errors after
attempt, cancellation during I/O, malformed/oversize/duplicate responses,
untrusted statuses and incomplete results are conservatively `Unknown`. Native
reconciliation must retain reservation and encrypted PKCE under its existing
authority; constructing another verifier or callback does not authorize retry.

`RequestedScopes`, `GrantedScopes` and `ScopeReported` preserve both configured
and returned scope semantics. When `scope` is absent, RFC 6749 section 5.1 defines
it as identical to the request; the projection explicitly marks that absence.
No reported scope may expand the configured request. `expires_in` is required,
integer, positive and at most one year; there is no invented expiry default.
Provider-token expiry does not establish ID-token, session or reauthentication
freshness. `ProviderIdentity.IDTokenIssuedAt` and `IDTokenExpiresAt` preserve
validated `iat`/`exp`, including the existing validator's exact fractional
NumericDate semantics. Native signed proof must not outlive its source proof,
original flow or local authority. `AuthenticationTime` is explicitly absent
without a validated `auth_time`; token `iat` is not substituted for a real
authentication event.

## Limits and trust

Defaults: 10-second total timeout, 60-second validation skew, 64 KiB response,
16 KiB token and 4 KiB original code. Configured bounds are documented on
`NewOIDCProvider`. JSON is limited to 16 levels, 256 members per object,
1,000 aggregate values and 16 KiB strings, including ignored extension members;
duplicate members, invalid UTF-8 and replacement-character strings are rejected.
The stricter upstream validator additionally bounds ID-token claims.

Configuration and scope/algorithm slices are snapshotted. `Clock` and key-set
collaborators are trusted, caller-owned, synchronous and concurrency-safe.
Constructors never fetch discovery or provider-controlled endpoint metadata.
The transport is an owned clone of a standard `http.Transport`, with verified
TLS 1.2/1.3, fixed HTTP/1 requests, no ambient cookies, replay, redirects or
retries. Custom TLS dialers, insecure verification, unrelated server-name
overrides and obsolete/unknown TLS versions are rejected; inherited HTTP/2
protocol/ALPN selection cannot override the selected one-send profile.
`Close` clears retained credentials; in-flight requests retain their private
bounded copies and are cancelled by their contexts.

Owned byte buffers and borrows are cleared, but Go strings, the HTTP stack,
compiler copies and garbage collection cannot provide runtime-wide secure
erasure. Callers must not retain borrowed slices or copies, use them
asynchronously, or log deliberately revealed token/URL data. Diagnostic
formatting is redacted and serialization of secret-bearing contracts is refused.

## Unsupported in this profile

Provider catalogs, discovery/JWKS retrieval, extra audiences, UserInfo overrides,
native/direct tokens, Apple/form-post/hybrid, signup/link policy, default refresh,
revocation/logout, popup, One Tap and proxy are not exposed. Optional profiles
must be separately implemented and verified; unsupported behavior is not inferred.

## Verification and status

The focused public tests use controlled TLS token endpoints and real signed ID
tokens, authenticated public dependencies and the existing strict validator.
The [constructor example](example_test.go) is executable and makes no requests.
They do not establish real-provider interoperability, complete native journeys,
mutation qualification, release integrity or publication. Run the module's
ordinary tests, vet, targeted race and bounded parser fuzz in a serialized,
task-owned disposable Go-cache session. The parent repository owns module
registration, native composition, independent final review and final acceptance.
