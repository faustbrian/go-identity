# OAuth relying-party protocol

`github.com/faustbrian/go-identity/oauth` implements one explicit HTTPS OIDC
authorization-code client: query response mode, S256 PKCE, a required nonce,
and configured ES256/RS256 signing keys. Go 1.27.0 or newer is required.

This is a protocol boundary, **not a complete social signin or linking workflow**.
Native authenticated transaction/state reservation, encrypted PKCE persistence,
account policy, token vault, identity mutation, session issuance, HTTP and reference
composition remain separate required owners. Calling this client does not confer
any of those authorities. It does not complete M17, M18 or unit qualification.

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
native/direct tokens, Apple/form-post/hybrid, signup/link policy, refresh,
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
