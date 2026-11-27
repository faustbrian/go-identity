# One Tap browser-option and callback-validation prerequisites

This independently versioned module provides **typed non-secret browser options
and read-only callback or explicitly selected redirect validation**, not a
complete One Tap login operation or a qualified M19 browser integration. It consumes the published generic OAuth
Google credential validator and the existing opaque session pre-auth transaction.
It adds no session, store, nonce generator, transaction reservation or claim
parsing authority.

## Closed browser-start option choice

Use `NewOneTapPromptOptions(OneTapPromptConfig{...})` for prompt context and an
explicit outside-tap cancellation choice, or
`NewOneTapButtonOptions(OneTapButtonConfig{...})` for button type, theme, size
and optional minimum width. The constructors reject empty or unknown enums;
all opaque option zero values are invalid. There are no silent enum defaults.
For prompt cancellation, explicitly supply `true` to retain GIS's default;
`false` disables it. Context controls wording, not signup, sign-in or account
linking authority. Button width zero means omitted; positive width is at most
400 pixels. The supported closed values come from the
[GIS JavaScript reference](https://developers.google.com/identity/gsi/web/reference/js-reference).

Pass the constructed prompt and a zero `OneTapButtonOptions`, or a zero
`OneTapPromptOptions` and the constructed button, to `NewBrowserStartOptions`.
Neither and both are rejected. `Projection()` returns the explicit `prompt`
or `popup_button` experience with fresh typed storage for only that selection.
The immutable options are safe for concurrent reads. Configuration and projection
copies cannot mutate retained options; JSON cannot construct validated options.

The projection is **only a non-secret option slice**, not a complete GIS request
or an authenticated/keyed native initiation intent. Its JSON uses stable enum
spellings; width remains a typed number, not GIS's documented width string.
For a button, `ux_mode` belongs to initialization, while type/theme/size/width
belong to rendering. A future browser adapter must map these separately and
obtain provider, client, authorized origin and nonce from trusted native binding.
The option contract accepts or returns none of those values, hints, identities,
credentials, arbitrary callback functions or redirects. Mutating or decoding a
projection grants no authority and cannot replace the constructors.

Both existing JavaScript experiences deliver credentials through a JavaScript
callback. Popup-button selection does not select redirect mode or a `login_uri`.
There is no durable start operation, credential release or browser execution
here, and the existing credential callback API remains unchanged.

### Explicit redirect-button selection and original launch projection

Use `NewBrowserRedirectStartOptions(button)` to opt into `redirect_button`
and `ux_mode: "redirect"` with the same closed button presentation choices.
It accepts no prompt or callback option, URL, nonce or state. Existing
`NewBrowserStartOptions` calls and prompt/popup projection JSON stay unchanged.
The existing `NewBrowserStartRequest` remains callback-mode only and rejects
redirect options. Use the distinct `NewBrowserRedirectStartRequest(spec)` with
the same `BrowserStartRequestSpec` and explicitly selected redirect options for
trusted native redirect start. The new type cannot be assigned or converted to
`BrowserStartRequest`; prompt and popup options are rejected by its constructor.
It retains the exact tenant, canonical origin/peer IP, bounded device, retry key,
options and resolved Remember policy, and `Bindings()` returns only that
unchanged original to trusted native execution. Both request types are immutable,
zero-invalid, redacted in diagnostics and deny JSON/text export. They add no
provider, client or URL input, authorization, reservation or native flow issuance.

After its exact fresh durable start commit, the native owner may call
`redirectValidator.BrowserRedirectStart(options, originalTransaction)` using
the separately configured `NewProviderBoundRedirectValidator`. The method
requires the original provider-bound Google redirect transaction and matches
its exact provider/version/client, endpoint, tenant, origin and policy. It
derives `ClientID`, `LoginURI`, the unpadded base64url `Nonce`, `State` equal
to the original canonical flow ID, `AllowedParentOrigin`, and the unchanged
`IssuedAt`/`ExpiresAt`; the detached `Button` retains the selected presentation.
No browser-supplied launch values can replace those original fields.

This typed representation is not a complete GIS object. Client ID, nonce,
`login_uri` and button UX mode map to initialization, presentation and `State`
map to the button, and numeric width maps to GIS's width string. The exact
allowed parent origin is a transport restriction, not a request to enable
One Tap's intermediate iframe. Do not invoke the prompt for this profile.
`State` is a public locator, never cookie custody or Google's separate CSRF
proof. Google's [button state reference](https://developers.google.com/identity/gsi/web/reference/html-reference#data-state)
documents its return with the credential; the
[server-side integration reference](https://developers.google.com/identity/gsi/web/reference/html-reference#server-side_integration)
requires ignoring unrecognized response parameters. A later bounded decoder
must preserve that rule without relaxing singleton checks for recognized fields.

Projection does not read time, issue/consume state or confirm activity. It can
project expired records. The native owner must freshly fence current activity,
original expiry and the exact original option fingerprint/journal at commit,
then invoke this method without renewing the lifetime. Mutation or decoding of
the detached representation grants no authority. JSON intentionally carries
the browser-facing nonce and locator; do not log it. No HTML/JavaScript renderer,
credential release, browser interoperability proof or HTTP decoder is added.

Use `NewBrowserStartRequest` to hand the native owner one bounded, immutable
original. Supply the tenant, exact canonical HTTPS origin, canonical peer IP
and bounded device from trusted transport, the opaque client retry key, the
selected prompt or button, and a session Remember policy resolved exactly once.
Do not decode this type directly from HTTP. Validation makes no authorization
or risk decision and releases no credential; the provider, actor, login flow,
nonce and cookie belong to native execution.

### Browser deployment prerequisites, not interoperability proof

Load Google's client from `https://accounts.google.com/gsi/client`; do not
self-host it. Follow Google's current
[setup guidance](https://developers.google.com/identity/gsi/web/guides/get-google-api-clientid)
for registered authorized origins, CSP and COOP. Where CSP directives apply,
allow the GIS client for scripts, `https://accounts.google.com/gsi/` for
connections/frames and the documented GIS stylesheet URL for styles. Popup
COOP requirements depend on FedCM: Google documents no adjustment with FedCM
enabled and popup-compatible policy when it is disabled. These are consumer
deployment requirements, not headers generated or browser behavior verified by
this option contract. Embedded parent-origin policy, FedCM qualification and
cancellation/dismissal signals remain part of the future complete browser seam.

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

### Provider-bound callback composition

For provider-selected initiation, use `NewProviderBoundValidator` with
`ProviderBoundConfig`. It freezes the same exact Google profile, tenant,
origin and policy as the legacy validator, and derives the provider ID, version,
client ID and callback mode privately from the configured provider. The adapter
cannot select a different provider through the callback command.

Initiation must use the existing session provider-bound issuance/persistence
path. At callback, pass `ProviderBoundAdapterBinding` with the original
`session.PreAuthTransaction`, its exact `Expected` binding and the flow-cookie
digest independently derived with `Token.ProviderPreAuthDigest` from the cookie
actually presented. Legacy or unbound transactions and legacy cookie digests
are not provider-bound authority. The validator calls `CheckProvider` before
credential verification and again afterwards, so an initiation that expires
during verification returns no identity evidence. These checks do not replace
the durable owner's current-state admission.

An optional `HostedDomain` string is trusted startup configuration. It is
validated with `oauth.NewGoogleHostedDomain` without normalizing or fetching
anything, then enforced only by
`VerifyGoogleCredentialForHostedDomain` against the signed exact `hd` claim.
Missing or mismatching `hd` denies even when a verified email has that suffix;
email, browser hints, suffix matching and organization membership never grant
access. An empty setting leaves the signed domain unrestricted. Bind changes to
this restriction to the initiating policy ID/version, not callback fields.

```go
validator, err := onetap.NewProviderBoundValidator(onetap.ProviderBoundConfig{
    Provider: googleProvider,
    TenantID: tenantID,
    Origin: authorizedOrigin,
    PolicyID: policyID,
    PolicyVersion: policyVersion,
    Clock: clock,
    HostedDomain: "workspace.example", // Optional trusted exact-domain policy.
})
// Handle err before accepting callbacks.
result, err := validator.Validate(ctx, onetap.ProviderBoundAdapterBinding{
    Transaction: originalTransaction,
    Expected: originalBinding,
    Cookie: independentlyComputedProviderFlowDigest,
}, callback)
// On success result.Original() returns the unchanged complete
// session.ProviderPreAuthTransactionSpec, including provider/client/mode.
```

`ProviderBoundResult.Identity()` is the same generic verified OAuth evidence.
The result is read-only and redacted, and neither consumes the callback nor
issues a session, links an account, stores a flow or renders browser options.
The legacy `NewValidator`, `AdapterBinding` and `Result` remain unchanged and
do not accept provider-bound records or gain hosted-domain enforcement.

### Separately configured provider-bound redirect validation

Use `NewProviderBoundRedirectValidator(config, exactRedirectURL)` to opt into
read-only Google button redirect validation. The existing `NewValidator` and
`NewProviderBoundValidator` remain callback-only; supplying a redirect to either
does not change its mode. The new constructor takes the same trusted
`ProviderBoundConfig`, including optional signed hosted-domain enforcement,
and returns the existing `ProviderBoundValidator` and `ProviderBoundResult`.

The endpoint is explicit trusted startup configuration, not a browser option,
request-body URL or fallback to the current page. It must be at most 2048 visible
ASCII bytes beneath the exact canonical HTTPS origin, with a clean literal path
and no query, fragment, percent escapes or semicolon. Aliases are rejected, not
normalized. Google additionally requires this exact `login_uri` to be registered
for the configured client; this constructor does not check remote registration.

```go
validator, err := onetap.NewProviderBoundRedirectValidator(config,
    "https://app.example/oauth/onetap-redirect")
// Handle err before accepting provider credentials.
result, err := validator.Validate(ctx, originalProviderBinding, onetap.Callback{
    Origin: originalInitiatingOrigin,
    Redirect: trustedExactEndpoint,
    CSRFCookies: allGCSRFCookies,
    CSRFBody: allGCSRFBodyValues,
    Credential: oauth.GoogleCredential{IDToken: credentialBytes},
})
```

Initiation must retain `session.PreAuthProviderRedirect`, the exact endpoint in
the original intent's `CallbackURL`, and the same provider/client, tenant,
origin, policy, nonce, RememberPolicy and original cutoff. The adapter must
independently derive the provider cookie digest from actual original browser
custody. `Callback.Origin` means that trusted original initiating context, not an
unchecked raw `Origin` header on a redirect POST. `Callback.Redirect` is the exact
endpoint established by trusted transport. Both must match the selected policy
and original transaction before JWT verification. The original authority is
checked again after verification; no mode, URL, time or Remember choice renews.
Google's separate bounded `g_csrf_token` cookie/body proof is still required
before token parsing. A credential, redirect URL or button `state` cannot replace
it or the original provider-bound browser possession check.

This is not redirect HTTP delivery or browser qualification. Google's
[JavaScript reference](https://developers.google.com/identity/gsi/web/reference/js-reference#login_uri)
specifies a POST credential to the exact registered endpoint and no `select_by`
in that POST. Its [HTML server-side integration reference](https://developers.google.com/identity/gsi/web/reference/html-reference#server-side_integration)
documents a URL-encoded body with `credential` and `g_csrf_token`, plus optional
button `state`. The current popup HTTP JSON `flowId` is not a GIS redirect field.
An eventual redirect transport must resolve the original per-flow locator from
its own trusted transport/cookie custody before credential parsing, without
adding a second state or replay owner. It must separately qualify redirect POST
origin and cookie behavior; popup's same-origin JSON/Lax-cookie assumptions are
not redirect interoperability evidence. No such HTTP adapter or cookie policy
is supplied here. The explicit redirect-button launch projection supplies only
the original flow ID locator; it does not establish cookie possession or consume
that flow.

### Legacy callback composition

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

Durable redirect initiation, browser credential delivery and HTTP completion,
browser initialization/execution, login hints, prompt dismissal/cancellation signals,
email verification/linking policy, HTTP parsing and
live browser/FedCM interoperability are not implemented. No raw claim API or
email/domain assertion is fabricated to cover those gaps. The selected origin
profile accepts lowercase canonical HTTPS DNS/IPv4 origins, optional non-default
canonical ports, and rejects case/default-port/path aliases. HTTP loopback, IPv6
and Unicode hostnames are not supported in this slice.
Numeric-ending host labels follow the WHATWG special IPv4 boundary: only exact
canonical dotted-decimal IPv4 literals are admitted, not abbreviated, integer,
octal or hexadecimal aliases or DNS-looking hosts browsers reject as IPv4.

The complete browser seam must qualify supported FedCM modes and the deployment
requirements above. This module does not render HTML, load scripts or claim
those browser requirements are already proven.

## Sources and proof

Google's [server-side validation guide](https://developers.google.com/identity/gsi/web/guides/verify-google-id-token)
was checked on 2026-11-26 for double-submit ordering and opaque `g_csrf_token`
semantics. The [GIS JavaScript reference](https://developers.google.com/identity/gsi/web/reference/js-reference)
defines callback versus redirect configuration; redirect validation is selected
only through its separately named constructor. The redirect endpoint and POST
references above were checked on 2026-11-27. Local tests use SDK-compatible RS256
JWTs signed by generated test-only RSA keys and the real pinned validator with a signature-verifying
static key set. They are not Google-issued fixtures or live browser proof.
The [WHATWG host parser and ends-in-a-number rule](https://url.spec.whatwg.org/#ends-in-a-number-checker)
define which ASCII numeric-ending hosts enter the IPv4 parser; aliases are
rejected rather than normalized into a different stored origin.
