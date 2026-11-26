# One Tap callback validation prerequisite

This independently versioned module is the **read-only callback-mode validation
slice**, not a complete One Tap login operation or a qualified M19 browser
integration. It consumes the published generic OAuth Google credential validator
and the existing opaque session pre-auth transaction. It adds no session, store,
nonce generator, transaction reservation or claim parsing authority.

## Trusted composition

Construct `NewValidator` with one exact Google Accounts RS256 provider, tenant,
canonical authorized HTTPS origin, policy ID/version and trusted clock. The
provider must use the built-in Google endpoint/algorithm/scope profile. The
provider's client ID, key set, clock skew, token bound and timeout remain explicit
in that owner's configuration; close it after all admitted operations finish.
The validator freezes its policy without reading a clock, fetching keys or
performing discovery. Verification may call the provider's configured key set,
which must authenticate signatures and honor its context. There are no owned
goroutines or hidden services.

At initiation, the trusted owner must persist the purpose-specific
`identity.oauth.onetap-start` pre-auth intent with the exact tenant, origin,
policy/version, original nonce, resolved RememberPolicy and empty CallbackURL
for this callback-only mode. It must also bind the selected provider ID/version
and client ID to that same native transaction. This leaf does not create a new
store or invent missing initiation authority.

At callback, the adapter resolves that same original transaction and independently
derives the existing session cookie digest from the presented flow cookie. It
supplies `AdapterBinding` from that **trusted server context**, not request JSON.
Copying a stored digest, constructing expected state from browser fields, or
trusting an arbitrary caller-supplied binding does not establish cookie/state
binding. The adapter must preserve all `g_csrf_token` cookie and body occurrences,
not select the first value or collapse duplicates. Transport decoding happens
exactly once before the call; all credential bytes remain borrowed.

```go
result, err := validator.Validate(ctx, originalAdapterBinding, onetap.Callback{
    Origin: requestOrigin,
    CSRFCookies: allGCSRFCookies,
    CSRFBody: allGCSRFBodyValues,
    Credential: oauth.GoogleCredential{IDToken: credentialBytes},
})
```

There must be exactly one nonempty canonical cookie and body value, each at most
1KiB and consisting only of RFC 6265 cookie-octets. This is a local admission
bound, not a Google encoding or maximum. Values are opaque and compared verbatim
using fixed-size SHA-256 digests and constant-time comparison. Whitespace,
quotes, escapes, duplicates, mismatches and missing values deny before any JWT
parse or key-set call. Both exact authorized request origin and the independently
cookie-bound original transaction are checked before credential verification.
The module never uses the credential or redirect as CSRF state.

Only after those checks does Google's pinned validator verify signature, issuer,
audience/authorized party, times, subject and the original transaction nonce.
The result exposes the existing `oauth.ProviderIdentity` and unchanged original
`session.PreAuthTransactionSpec`, including exact version, nonce, cookie digest,
timeline and RememberPolicy. Missing `auth_time` never becomes `iat` freshness.
Errors and default diagnostics contain no credential, CSRF, nonce, PII, origin,
claims or underlying key-set messages. Context cancellation remains discoverable
with `errors.Is`.

## Not supported or claimed

Validation does not read current durable state, reserve/consume a transaction,
prevent replay, check lifecycle invalidations, link an account, issue a session,
emit the complete operation's audit event or recover an unknown commit. Repeated
read-only validation may succeed. The next native owner must re-read current
state and policy, fence the exact version, preserve RememberPolicy through MFA,
atomically reserve/apply/finalize, and recover before retrying unknown completion.
Never treat this result as active-state or local authentication authority.

Redirect mode (including any nonempty inbound Redirect or stored CallbackURL),
prompt/button initialization, login hints, prompt dismissal/cancellation signals,
hosted-domain restrictions, email verification/linking policy, HTTP parsing and
live browser/FedCM interoperability are not implemented. No raw claim API or
email/domain assertion is fabricated to cover those gaps. The selected origin
profile accepts lowercase canonical HTTPS DNS/IPv4 origins, optional non-default
canonical ports, and rejects case/default-port/path aliases. HTTP loopback, IPv6
and Unicode hostnames are not supported in this slice.
Numeric-ending host labels follow the WHATWG special IPv4 boundary: only exact
canonical dotted-decimal IPv4 literals are admitted, not abbreviated, integer,
octal or hexadecimal aliases or DNS-looking hosts browsers reject as IPv4.

The later browser seam must document Google's required script origin
`https://accounts.google.com/gsi/client`, applicable CSP allowances and popup COOP
constraints, and qualify supported FedCM modes. This module does not render HTML,
load scripts or claim those browser requirements are already proven.

## Sources and proof

Google's [server-side validation guide](https://developers.google.com/identity/gsi/web/guides/verify-google-id-token)
was checked on 2026-11-26 for double-submit ordering and opaque `g_csrf_token`
semantics. The [GIS JavaScript reference](https://developers.google.com/identity/gsi/web/reference/js-reference)
defines callback versus redirect configuration; this slice intentionally selects
only the former. Local tests use SDK-compatible RS256 JWTs signed by generated
test-only RSA keys and the real pinned validator with a signature-verifying
static key set. They are not Google-issued fixtures or live browser proof.
The [WHATWG host parser and ends-in-a-number rule](https://url.spec.whatwg.org/#ends-in-a-number-checker)
define which ASCII numeric-ending hosts enter the IPv4 parser; aliases are
rejected rather than normalized into a different stored origin.
