# hCaptcha Publisher/Pro adapter

Experimental, Go 1.27. This independent module implements one explicit hCaptcha
Siteverify Publisher/Pro profile. It returns neutral provider facts through
`Verify` and the exact `risk.CaptchaEvidenceIssuerConfig.Verify` callback through
`Observe`. It never issues permission, reusable evidence or policy decisions.

## Public composition

`New(Config, *httpclient.Client, clock.Clock)` constructs a concurrent `*Client`
without IO. The [compiled example](example_test.go) demonstrates construction;
[public-path tests](hcaptcha_test.go) exercise the actual POST, native result and
risk callback, not a substitute parser or authority.

Select provider `hcaptcha`, API `siteverify`, version `2026-08-11`, tier
`publisher_pro`, API profile `siteverify/publisher_pro`, a configured site key,
configuration version and exact canonical hostname set. The version is the
preserved reference contract revision, not a version sent to hCaptcha's endpoint
or a claim that current documentation is dated that day. ExpectedAction must be
empty because unsupported—not a literal `unsupported` comparison. Action, score,
score reasons, origin, cdata, remote-IP disclosure, Enterprise and arbitrary
endpoint overrides are not selected or inferred.

Endpoint must be exactly `https://api.hcaptcha.com/siteverify`. Supply non-secret
User-Agent (1..256 visible ASCII including spaces), response budget 1KiB..64KiB,
timeout 1..15s, evidence lifetime 1s..2m, challenge age 1s..2m, token byte limit
1..8192 and concurrency 1..256. Budgets are explicit, with no admission queue or
fallback defaults. Every call preserves the caller's original canonical command
and trusted opaque `risk.FlowContext`; borrow the unchanged token synchronously
and do not mutate it concurrently. Risk alone derives keyed replay identity and
coordinates durable one-use issuance and later protected consumption.

## Secret and resource ownership

Secret bytes must be 1..4096 visible ASCII bytes; size is checked before string
conversion or copying. The adapter owns a copy, not the caller's mutable slice.
Supply credentials from the host's approved secret manager. No credential
persistence or competing envelope format is created. Only the supplied HTTP
primitive's RoundTripper is borrowed—not its cookies, headers, middleware,
telemetry or redirect policy. The host transport must verify HTTPS, honor
context, support concurrency and never retain or log bodies.

`Close(ctx)` rejects new exchanges, cancels and drains active exchanges, clears
retained secret bytes and closes only the adapter's isolated HTTP primitive.
If Close times out, call again to await drainage. Host HTTP/transport resources
remain borrowed and must outlive the adapter. Transient byte buffers are cleared
where practical; Go cannot guarantee erasure of every runtime/string copy.

## Request, native evidence and failures

Each call makes one form POST with exactly `secret`, `response` and the configured
expected `sitekey`. No remote address, action, command ID or invented idempotency
field is transmitted. There are no automatic retries, redirect following, token
cache or coalescing. A possibly consumed token is not replay-safe: hCaptcha has
no documented Siteverify idempotency contract. A new challenge does not authorize
retry under a fresh identity command.

The strict bounded parser accepts only documented Publisher/Pro fields:
success, challenge timestamp, hostname, optional deprecated credit and optional
error codes. It rejects duplicate/escaped-alias field names, unknown/Enterprise
fields, malformed tails, invalid types, oversized fields and arbitrary diagnostic text.
Absent optional fields remain unavailable, separately from present false/empty.
Credit is evidence only and never controls solved classification.

Configured site attribution and returned site-key status are distinct. The
documented response does not return a sitekey, so `HCaptcha.ReturnedSiteKey`
remains unavailable rather than copying the configured key. An undocumented
`sitekey` response field fails closed. Sending expected `sitekey` binds the
provider's verification; provider rejection is not locally rewritten as success.
The provider describes hostname as browser-derived and sometimes `not-provided`:
it is not authentication. The exact local hostname comparison is an additional
consistency condition, never independent identity/site proof. No suffix,
Unicode, port, case folding or wildcard substitution occurs.
The `not-provided` sentinel cannot be configured as an allowed hostname.

All eleven currently documented error codes are preserved in redacted native
evidence. Response errors, expiry and already-seen are rejected; secret/request
configuration errors are unavailable; `sitekey-secret-mismatch` is a binding
mismatch; remote-IP-required/invalid responses are unsupported under this
non-disclosing profile. Safe unknown code tokens (1..64 lowercase-letter/digit/
hyphen bytes, starting with a letter, at most 16) remain only in native evidence,
normalize to `unknown-provider-code` and produce unusable malformed results.
No error is authoritative proof of a risk-owned replay-table transition.

429 is throttled; other non-200 responses unavailable; transport failures and
partial bodies retain unknown-consumption ambiguity. Every body closes. Future,
missing or exclusively expired challenge timestamps fail without skew allowance;
age is capped at the configured bound, never beyond the documented 120s default.
Original provider read time and earliest challenge/lifetime expiry are conserved.
Cleanup/telemetry passing the original deadline cannot publish solved facts.
Every failed result has zero usable expiry and safe stable error identity.

Automatic formatting redacts config/result/native evidence, and automatic
serialization is refused. Do not separately log token/secret/site/native codes or
provider bodies. Optional `Config.Observe` receives only closed exchange outcome,
transport class and duration before neutral binding normalization. Host callbacks
must be bounded/concurrent-safe; panics are contained. Telemetry is neither final
risk policy nor canonical event delivery.

## Sources, lifecycle and qualification boundary

Protocol decisions follow the official
[hCaptcha server verification contract](https://docs.hcaptcha.com/#verify-the-user-response-server-side)
and [error-code table](https://docs.hcaptcha.com/#siteverify-error-codes-table),
refreshed on 2026-10-18. Test bodies are synthetic schema-derived fixtures with
verified local TLS; no live hCaptcha/test-key request was performed. They do not
establish provider interoperability. The retained source manifest identifies
`hcaptcha-siteverify-20260719190355`, archive revision `20260719190355`, SHA-256
`fb21f1f49e6b6c0d30b57ce3c8c585e986cf4aee2a00bcccda4053f88f0f5f54`;
that is historical planning identity, not a newly downloaded fixture.

For secret rotation/configuration change, construct the new explicit immutable
client and drain/Close the old one. This local resource action does not disable
durable evidence: the neutral/risk lifecycle owners remain responsible for
`captcha.site_disabled.v1`, `captcha.configuration_changed.v1` and
`captcha.secret_rotated.v1` effects under their trusted configuration generations.
This adapter emits none of those events and adds no private lifecycle store.

Development uses a disposable external workspace to consume the neutral hCaptcha
extension. Delivery requires a real public neutral-extension pin and public-only
consumer proof. Canonical events, durable/reference composition, live-provider
interoperability, complete coverage/mutation, benchmarks and release/supply-chain
qualification remain separate pending work. No whole-unit/M35 closure is claimed.

## FAQ

**Does false credit reject a challenge?** No. Credit is optional deprecated
metadata; provider success, supported fields and original bindings govern facts.

**Can I enable score or action?** Not for this documented Publisher/Pro profile.
An independently evidenced profile is required; no fallback is inferred.

**Does Close close my supplied HTTP client?** No. Drain the adapter before
closing host-owned resources.
