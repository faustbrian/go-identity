# Apple direct-signing sources

Reviewed 2026-11-13. These are source identities for the selected direct
operation, not a claim of Apple sandbox/live interoperability.

## Official Apple source

- [Creating a client secret](https://developer.apple.com/documentation/accountorganizationaldatasharing/creating-a-client-secret)
  defines the team/client/key claims, fixed Apple audience, ES256/P-256 and
  maximum 15,777,000-second expiry horizon.
- Canonical JSON source:
  `https://developer.apple.com/tutorials/data/documentation/accountorganizationaldatasharing/creating-a-client-secret.json`
- SHA-256 of the retrieved JSON response:
  `4c73f85956f8d1905aa3253b71f96e7864830d33383ca9404aac95812a5b5c75`.
- The official [Sign in with Apple REST API](https://developer.apple.com/documentation/signinwithapplerestapi)
  root JSON's `Creating a client secret` reference links to that shared article.
  Its older guessed `signinwithapplerestapi/creating-a-client-secret` path is
  absent; the shared location is not an unrelated third-party replacement.
- [Apple bundle identifier syntax](https://developer.apple.com/help/glossary/bundle-id/)
  supplies the alphanumeric/period/hyphen alphabet. This runtime preserves the
  client secret's case-sensitive subject rather than normalizing it. The
  selected 255-byte bound is local resource policy, not an Apple protocol limit.

To refresh, retrieve the same canonical JSON over HTTPS, verify the source and
the Sign in with Apple reference, compute SHA-256, compare changed field
semantics, update this review date/hash and exercise affected contract tests.
Do not silently update a pin or infer support from changed metadata.

## Selected repository contract

The complete retained `identity-oauth-providers` goal additionally requires
exact ordered `alg,kid` and `iss,iat,exp,aud,sub` objects, no `typ` or extra
claims, integral injected time/lifetime, checked arithmetic and a64-byte JOSE
signature. JSON ordering is this repository's reproducibility boundary, not an
assertion that Apple requires member order. The64-byte R||S representation is
the JOSE ES256 format in [RFC7518 section 3.4](https://www.rfc-editor.org/rfc/rfc7518#section-3.4).

Envelope AAD binds the direct operation, schema version 1 and a domain-separated
SHA-256 digest of the exact opaque handle. It never exports the handle itself
through the public envelope Context projections. Exact case/bytes still select
distinct bindings; hashing is not normalization or authorization.
The signer copies the encrypted key set, resolves only that set and decrypts
PKCS8 DER through public `github.com/faustbrian/go-secret-envelope/v2 v2.0.1`.
It uses Go 1.27 standard-library ECDSA/SHA-256 and does not expose general JWT
signing, state/session authority or provider-token validation.

Team/key identifiers select the explicit uppercase ten-character profile.
One-to-thirty-second or longer key-provider delays cannot extend the configured
1ms..30s operation deadline. Local crypto and a trusted clock are synchronous
and non-preemptible; after those operations, cancellation is checked before
success is returned. Callers authorize invocation and protect wrapping-key
delivery; possession of a syntactically valid handle proves neither.

The selected 64-key limit bounds constructor work and retained encrypted-key
storage, while permitting explicit overlapping rotation histories. The 4096-byte
DER limit bounds ASN.1 input/work with ample room for a PKCS8 P-256 key, rather
than accepting the envelope owner's general-purpose multi-megabyte payload.
The 255-byte client-ID limit bounds signed claims independently of provider
responses. These are explicit local resource policies, not Apple-imposed limits.
