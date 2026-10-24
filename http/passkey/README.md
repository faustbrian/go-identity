# Optional passkey HTTP

This nested module contributes only explicitly selected cookie-only passkey
operations. The base HTTP module imports neither this package nor a
PostgreSQL adapter. Omitting the feature exposes no passkey routes or metadata.

`FeatureConfig.Signup` explicitly selects the `mode: "signup"` registration
variant. Options accepts only `mode` and original `flowID`, with one header-only
`Idempotency-Key`; completion adds original `commandID`, `ceremonyID`, raw
WebAuthn `response` and optional `label`, and forbids that header. Original
`__Host-identity_flow` and signed device cookies plus exact Origin are required.
Session cookies, session CSRF, proof IDs, email/password and remember overrides
are rejected. Native `SignupService` owns account creation and actual session
issuance, not this transport. Obtain the original flow from that owner or a
selected `http/session` pre-auth method; do not fabricate authority.

When `Registration` is also selected, the same two routes dispatch disjoint
closed schemas: signup requires its explicit mode; enrollment retains its
original proof-ID/session/synchronizer shape without a mode. Both configurations
must use identical ingress limits/host/proxy lists, Origin, session cookie and
shared rate-owner pointers. No failed branch falls back to another method.
Fresh signup alone returns `registered`, `signedIn`, committed command/session
metadata, the owned secure session cookie and synchronizer. Historical and
unknown outcomes return no credential. Selection is off by default and does
not enable conditional UI, other methods or a standalone deployment graph.

Construct `NewFeature(FeatureConfig{Registration: registration, Signin: signin,
Inventory: inventory, Update: update, Delete: deletion})`, where each pointer is optional and at least one is
selected. Pass the returned contribution to `identityhttp.FeatureServices` and
the existing `NewRouter`. `NewFeatureWithMiddleware` uses the same owner stages;
standalone handler constructors are also available. Construction performs no
native IO. Borrowed services, rate owners and clocks must support concurrent
requests and outlive the handlers.

| Path | Body/query | Idempotency-Key |
| --- | --- | --- |
| POST `/v1/passkey/register-options` | Enrollment: `proofID`; signup: `mode:"signup"`, `flowID` | Required |
| POST `/v1/passkey/register-verify` | Same selected registration variant plus `commandID`, `ceremonyID`, `response`, optional `label` | Forbidden |
| POST `/v1/passkey/signin-options` | `mode`, `flowID`, identified `identifier` | Required |
| POST `/v1/passkey/signin-verify` | Same original mode/flow/identifier plus `commandID`, `ceremonyID`, `response` | Forbidden |
| GET `/v1/passkey/list` | Optional `after`, `limit` (1..100, default100) | Forbidden |
| POST `/v1/passkey/update` | `proofID`, `referenceID`, `expectedVersion`, `name` | Required |
| POST `/v1/passkey/delete` | `proofID`, `referenceID`, `expectedVersion` | Required |

## Composition and custody

`RegistrationConfig` borrows the real session reader, committed signed proof
lookup and native enrollment/source owner. Supply the original secure session
cookie, retained version-distinct synchronizer keys, signed device profile,
exact HTTPS Origin, trusted authorization revision, **session** audience, shared
options/verification rate owners and bounded clock. Each phase needs a distinct
genuine password action proof for its exact native action; a body proof locator
is not a proof. Native owns proof audience, signature, original expiry and use.
The original stored synchronizer must match `X-CSRF-Token`; no token-age lease
replaces session validity. A consumed or expired enrollment proof cannot cause
an options retry to regenerate a challenge.

`SigninConfig` borrows the native identified/discoverable workflow and original
rate-source methods. Supply the real original-flow cookie policy named
`__Host-identity_flow`, matching signed device profile, session cookie, exact
Origin, shared rate owners, fixed trusted actor/revision/session audience, and
the same concrete `email.AddressParser` as the original identity owner.
Local-part comparison and nontransitional IDNA domain processing remain separate.
`SigninConfig.DiscoverableOnly:true` additionally requires `Discoverable:true`
and selects identifier-free signin exclusively. Leave `Address` unset in that
profile: neither handler nor its OpenAPI request accepts identified mode or an
identifier field. Original flow/device/origin, native discovery policy, UV,
rates and one-use completion remain required. The default combined profile
still requires the configured email parser; there is no failure fallback.

`SigninConfig.Conditional:true` explicitly selects conditional presentation for
discoverable options. It requires `Discoverable:true` and the same borrowed
`Service` must implement `ConditionalSigninService`; old implementations gain
no new requirement when this flag is false. Keep the request's existing
`mode:"discoverable"`: fresh options add `mediation:"conditional"` beside
`publicKey`, not inside it. Identified options and discoverable completion are
unchanged. Original keys, commands, flow/device/origin, remember choice, UV,
risk and server expiry retain their native owner. Retries disclose no options.
Applications check browser support and deserialize `publicKey` before calling
`navigator.credentials.get()`; this backend does not implement browser UI or
prove which mediation the browser actually used. No separate ceremony mode,
fallback or longer expiry is introduced.

There is no account lookup in normalization. `Discoverable:true` explicitly
permits `mode:"discoverable"`; no identifier or fabricated user accompanies it.
Omitting that selection denies discovery, never falling back from identified
signin. Initiate the native passkey flow separately; its original remember
choice, target, mode, browser custody and validity remain authoritative.

`InventoryConfig` borrows the real cookie session reader, native safe inventory
and shared safe rate owner. Listing never accepts a user/tenant target. It
projects only native reference ID/version/state/label/AAGUID/backup flags and
timestamps, with a bounded keyset cursor. RP credential IDs, public keys, user
handles, counters and proofs are absent. Native read-risk policy remains separate
from shared HTTP safe admission.

`UpdateConfig` independently selects display-label rename under a genuine
password-authenticated session, its original synchronizer and a signed
`identity.passkey.update` proof. Supply the native management owner's actual
session/proof readers, shared `KeyedSecretRateLimiter`, retained CSRF keys,
session audience, exact HTTPS Origin and trusted revision/clock. No device
ceremony or browser-supplied command, user, tenant or RP is accepted. ReferenceID
is the safe inventory reference, not raw WebAuthn credential bytes; the positive
expected metadata version and exact non-whitespace/control-free UTF-8 name
(at most128bytes) belong in the closed JSON body. The sole retry key comes from
one `Idempotency-Key` header. Native owns signature, freshness, current authority,
one-time proof use and the protected transaction. Install its forward metadata
and password proof migrations before enabling management.

Fresh acknowledged update returns original command metadata, `replayed:false`
and one safe `credential` projection. Matching original-key retries return
`replayed:true` and no `credential`, including after proof consumption/expiry;
they still need the original current authorized session. Protocol keys, counters
and authentication authority are not changed. Unknown/error outcomes disclose
only validated original durability metadata, never replacement authentication.
HTTP shared secret quotas do not replace native mutation-risk admission.

`DeleteConfig` independently selects self-removal under the native deletion
owner's actual password session reader and original signed
`identity.passkey.delete` proof. It uses the same retained synchronizer, exact
Origin, session audience and shared keyed secret-rate owner as update, without
a device ceremony. The body contains only proof/reference locators and the
positive observed metadata version; exactly one header carries the original
retry key. Consumers supply the actual native deletion owner with its configured
reset-backed recovery source, not a boolean recovery assertion or another store.

Both fresh deletion and matching historical retry return only `commandID`,
`commitOutcome:"committed"` and `replayed`. Native atomically owns protocol key
invalidation, mapping/reference removal, passkey authority and session effects.
No authenticator-local erasure is claimed. HTTP does not clear or renew the
original password session: it remains usable for authorized metadata-only
retries. Unknown outcomes do not establish rollback and disclose only validated
original durability metadata. No removed credential projection is returned.

## Rates, responses and retries

Options admit the shared IP budget before device/proof crypto; identified
options additionally debit the exact canonical identifier. Completion admits
IP first, then authenticates native original-ceremony metadata, then debits its
original five-minute challenge and user, identifier or anonymous-flow dimension.
This metadata is not an execution lease: historical consumed metadata can be
readable, while native completion independently revalidates and consumes once.
No metadata read renews expiry or establishes account eligibility.

Fresh options return `commandID`, `commitOutcome:"committed"`, `replayed:false`
and `options`, containing the **exact** native `TransferJSON` document with its
`publicKey` wrapper. Save that original command/ceremony ID for completion.
A matching options retry returns only the original command metadata and
`replayed:true`, with no `options`. Changed key scope/input denies. Never use
a new key to recover an ambiguous original admission.

Enrollment success returns `registered:true` and committed command metadata,
not authentication. Fresh committed signin or explicitly selected signup returns `signedIn:true`,
command/session metadata and the owned secure HttpOnly session cookie plus
`X-CSRF-Token`. Tokens are absent from JSON and never redelivered on replay.
Typed unknown outcomes preserve their original command ID without challenge or
credentials; unknown is not rollback and must not trigger another completion.
An already validated native command observation survives later timeout or
delivery expiry as error-only durability metadata, including `committed` when
commitment was acknowledged. It never retains `signedIn`/`registered` success,
challenge bytes or credentials, and does not renew authorization. Middleware
body fields cannot create such an observation.

Every response is no-store/nosniff. JSON responses are synchronously buffered
and bounded; streaming, writer unwrapping and detached hooks are not supported.
Owned successful payload bytes bypass middleware writers and are flushed only
after all synchronous hooks and final validity checks. Middleware cannot change frozen browser inputs, acquire response credentials or
renew the original session/device/proof delivery validity. Earlier context
deadlines win. Use the existing session HTTP feature independently for actual
authenticated reads and logout.

## Limits and exclusions

Configure trusted host-to-tenant mapping and strict body/header/query limits.
Requests reject alternate bearer credentials, body identity/CSRF/cookie/remember
overrides, duplicate fields/headers, wrong mode and foreign origins. Selected
OpenAPI comes from the same real handlers, not the direct Go contract catalog.
Browser/WebAuthn cryptographic validity and one-use atomic effects remain the
native owners' responsibility; HTTP admission is not substitute authority.

Signup, label update and deletion are explicit selections, never defaults.
This feature does not select conditional UI, MFA fallback, recovery endpoints,
cookie-to-bearer exchange or default routes.
Choosing cookie delivery is explicit and cannot be changed by middleware.
