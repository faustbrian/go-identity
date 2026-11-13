# Built-in OAuth profiles and direct operations

This experimental module supplies an explicitly configured Google
code/query/S256 provider through the existing OAuth owner and
`identity.oauth.provider-apple-client-secret-sign`, which signs an Apple
client-secret JWT using an explicitly configured, preprovisioned encrypted
P-256 key. It does **not** implement Apple authentication, hybrid/form-post
callbacks, implicit signup, a complete provider catalog or whole-unit qualification.

## Google existing-account browser flow

```go
provider, err := providers.NewGoogle(providers.GoogleConfig{
    Version: 1,
    ClientID: clientID,
    ClientSecret: loadedSecret,
    RedirectURI: "https://application.example/google/callback",
    KeySet: trustedGoogleKeys,
    Clock: clock,
    HTTPClient: httpClient,
})
if err != nil {
    return err
}
// The caller clears loadedSecret after construction.
defer provider.Close()
// Supply provider to the existing native OAuth link/signin configuration.
```

`NewGoogle` fixes the stable ID, reviewed issuer/endpoints, RS256,
`client_secret_post`, code/query/S256 and required nonce. Nil `Scopes` selects
`openid`, `email`, `profile`; an explicit unique subset must retain `openid`.
Unlisted scopes, aliases and endpoint/algorithm/authentication overrides are
not selected. `Profile()` is the existing defensive, secret-free facts
projection, not a second catalog or proof owner. See [the Google profile and
source pins](docs/google.md) for bounds, supported behavior and remaining scope.

Construction performs no discovery, key fetch, clock read or network exchange.
Trusted keys, clock and standard HTTP transport remain caller-owned. The
returned `*oauth.OIDCProvider` owns its copied secret and cloned transport;
close it when admitted operations finish. Native state admission, exact callback
binding, account selection, current authority and session issuance remain owned
by the existing OAuth/native services. Configuring this builder does not grant
any of those authorities or expose a route by itself.

The two documented signed Google issuer forms project to one canonical
issuer/exact-subject account after full verification. Raw callback `iss` remains
required and exactly canonical, as declared by the pinned Google metadata.
There is no email matching, automatic signup, direct/native-token signin,
UserInfo enrichment, refresh, revocation, unlink, provider logout or One Tap
operation in this finite builder. Controlled TLS/signature/native tests do not
claim live Google interoperability. The full 43-row provider matrix and all
unimplemented Google cells remain binding and unverified.

## Provision and use the Apple signer

The application owns key provisioning, authorizes the operation, and retains
the actual `secret-envelope/v2` service and its concurrent-safe wrapping-key
provider. During provisioning, decode the Apple `.p8` PEM to PKCS8 DER, encrypt
that DER using `AppleSigningKeyContext(handle)`, persist only the envelope, and
clear plaintext input. Provisioning is separate from the runtime operation;
the runtime constructor/request accepts neither raw keys nor caller claims.

```go
handle, err := providers.NewAppleSigningKeyHandle("vault:apple/team/key-v1")
// Handle err. Load the preprovisioned envelope through your configuration owner.
signer, err := providers.NewAppleClientSecretSigner(providers.AppleClientSecretSignerConfig{
    Envelope: envelopeService,
    Keys: []providers.AppleSigningKeyEnvelope{{Handle: handle, Envelope: encryptedKey}},
    Clock: clock,
    Timeout: 5 * time.Second,
})
// Handle err. The caller authorizes the exact team/client/key combination.
result, err := signer.Sign(ctx, providers.AppleClientSecretRequest{
    TeamID: "TEAMID1234", ClientID: "com.example.apple", KeyID: "KEYID12345",
    SigningKey: handle, Lifetime: 5 * time.Minute,
})
// Handle err before accessing result metadata.
defer result.Secret.Destroy()
err = result.Secret.Use(func(jwt []byte) error {
    // Synchronously encode jwt into the intended token request; do not retain
    // the borrowed slice, log it or copy it for later use.
    return encodeTokenRequest(jwt)
})
```

The complete executable external consumer in `apple_test.go` uses the actual
envelope service/keyring, independently verifies the resulting ECDSA signature
with its public key, checks exact header/claim bytes and performs synchronous
form encoding. It does not contact Apple or establish live-provider acceptance.

## Contract and ownership

- Key handles preserve exact ASCII bytes in `[A-Za-z0-9._:/-]+`, length 1..256.
  They perform no lookup or authorization and redact diagnostics/serialization.
- Team/key IDs are ten uppercase ASCII alphanumerics. The selected local
  client-ID boundary is 1..255 ASCII alphanumerics, periods and hyphens, with
  no normalization. The actual registered App/Services ID remains authoritative.
- Keys are an immutable construction-time set of 1..64 encrypted bindings. A
  key envelope must be bound to this operation/version/exact handle. The
  selected payload is PKCS8 DER at most 4096 bytes; only ECDSA P-256 is admitted.
  Reconstruct the signer when installing different immutable key configuration.
- Clock is read once per syntactically valid call. Zero or fractional-second
  values deny. Lifetime is an integral 1..15,777,000 seconds; expiry arithmetic
  is checked and metadata is UTC. Use only before the original `ExpiresAt`.
- Timeout defaults to 10s, with explicit 1ms..30s bounds, never extending the
  caller context. Trusted clocks must return promptly. The envelope provider
  must honor cancellation; local cryptography cannot be forcibly interrupted.
- `Sign` returns a zero result on failure. Its stable error `Code()` is
  `invalid_bounds`, `canceled` or `signer_failure`; collaborator diagnostics and
  panics are discarded. There are no automatic retries or durable effects.
- `Use` supports serial synchronous borrows until `Destroy`; aliases share
  custody. Overlapping/reentrant borrows deny. Each private callback copy is
  cleared even on callback error/panic, and callback diagnostics become only
  `AppleClientSecretUseError`. No custody lock is held during a callback.
- `Destroy` clears retained JWT bytes for every alias. Already-admitted private
  borrows can finish, then clear independently. Go, crypto internals and encoder
  copies prevent a claim of complete process-memory erasure.

Constructors start no goroutine and open no network or other resources. The
caller keeps envelope/clock collaborators alive and owns their shutdown. Never
log requests, configuration, JWTs, private keys or envelopes. There is no HTTP
route, OpenAPI registration, token exchange, Apple server validation or login.

## Sources and verification

[Official protocol pins and repository decisions](docs/protocol-sources.md)
distinguish Apple requirements from the stricter selected serialization contract.
The parent repository owns module registration, integration, independent review
and delivery. Run the focused module tests, race and vet under the repository's
serialized task-owned cache policy. Passing these checks is not provider-catalog
or release qualification.
