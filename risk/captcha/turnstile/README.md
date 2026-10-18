# Cloudflare Turnstile adapter

Experimental, Go 1.27. This adapter implements only explicit Siteverify v0/free
verification at `https://challenges.cloudflare.com/turnstile/v0/siteverify`.
It returns neutral provider facts and an exact `risk.CaptchaObservation` callback,
never allow/deny decisions, replay authority or a durable evidence reference.

## Use and ownership

`New(Config, *httpclient.Client, clock.Clock)` constructs a concurrent `*Client`.
Set the exact endpoint, non-secret User-Agent, provider secret bytes, response
budget and neutral profile. The supplied clock becomes the profile clock.
`Verify(ctx, request)` returns private native/normalized facts; `Observe` is directly
assignable to `risk.CaptchaEvidenceIssuerConfig.Verify`. The
[executable public-path tests](turnstile_test.go) demonstrate construction,
original opaque flow/command custody, request fields and risk projection.

The adapter copies 1..4096 visible-ASCII secret bytes, borrowing neither their
mutable slice nor an application-owned secret store. Deliver static credentials
through the host's approved secret manager. No credential persistence or key
provisioning is performed here; this adapter does not invent a second secret
envelope format. Caller ownership remains unchanged after construction.

Only the supplied primitive's trusted RoundTripper is borrowed. Its middleware,
cookies, headers, telemetry and redirect callbacks are not inherited. Configure
TLS/proxy/dial policy before sharing; the transport must verify HTTPS, honor
context, support concurrency and never retain or log request bodies. Keep it
alive until adapter shutdown finishes. `Close(ctx)` rejects new exchanges,
cancels and drains active work, and clears retained secret bytes; if it times
out, call it again to await completion. The borrowed HTTP client is not closed.

The fixed endpoint cannot be overridden. Profile origin/score/Enterprise fields
and remote-IP disclosure are unsupported. Responses are bounded to an explicit
1KiB..64KiB before parsing. Tokens are bounded by the selected byte budget and
Cloudflare's 2048-character limit. Neither token nor secret is trimmed or
normalized. Transient byte buffers are cleared where practical; Go cannot
guarantee erasure of every runtime/string copy.

## Protocol and retry contract

Each call sends one form POST containing `secret`, `response`, and the derived
`idempotency_key`; `remoteip` is never sent. Redirects and non-200 responses do
not become successful verification. There are no automatic retries or cached
token results. Transport errors/partial bodies retain unknown-consumption
classification, not a fabricated unused token.

Transport idempotency is a domain-separated SHA-256 projection of the original
canonical command, original trusted flow kind/tenant/operation/subject or
anonymous flow/pre-auth transaction/session/administrator/challenge/intent,
immutable provider/site/API/configuration/bindings, and token
digest, encoded as an RFC 9562 version-8 UUID. Equal logical inputs conserve it;
changed token, command or configured binding changes it. It is neither returned
nor stored as a replay fingerprint. The risk issuer independently checks exact
flow/token custody and owns keyed durable replay identity and same-command
reconciliation. A retry classification never authorizes a fresh command/replay.

The parser consumes the complete bounded body before returning evidence. It
rejects duplicate JSON fields (including escaped aliases), unknown fields/error
codes, invalid types, oversized fields, malformed tails and extra JSON values.
Missing optional fields remain unavailable and present-empty remains explicit.
Native `success`, timestamp, hostname, action, cdata, error codes and documented
metadata availability are retained in a closed bounded envelope. Enterprise-only
`metadata.ephemeral_id` cannot yield solved evidence in the free profile.

Configured hostname, action and optional cdata are exact bindings. Site key and
API/profile labels come from trusted server configuration: Siteverify does not
return a site key that could independently attest that configuration. Challenge
expiry is exclusive and capped at the configured age, at most five minutes;
future challenge timestamps fail. Provider read time is not reset on projection.

Optional `Config.Observe` receives only closed provider-exchange outcome,
transport class and duration before neutral binding normalization. It describes
provider completion, not usable evidence or a policy decision. The host owns
bounded/concurrent telemetry and exporters. Observer panics are contained;
telemetry cannot turn cancellation or malformed evidence into success. Canonical
verification/rejection/replay/binding-mismatch events belong to the neutral
owner and its shared identity-event prerequisite, not this provider callback.

## Protocol sources and verification limits

The implementation follows Cloudflare's official
[server-side validation contract](https://developers.cloudflare.com/turnstile/get-started/server-side-validation/)
and [widget field constraints](https://developers.cloudflare.com/turnstile/get-started/client-side-rendering/widget-configurations/),
consulted 2026-10-18, and [RFC 9562 section 5.8](https://www.rfc-editor.org/rfc/rfc9562.html#section-5.8)
for transport UUID layout. The preserved program protocol manifest names the
2026-07-28 Siteverify snapshot with SHA-256
`f9a773129cd6b16a7b79c70289386e3adb5d201522a5356d12a8dc0c8a987905`;
that historical source identity is not represented as a newly downloaded fixture.

Local tests derive synthetic response fixtures from those documented fields and
codes. They exercise complete POST/parse/normalization/risk-callback behavior,
verified local TLS, redirect/cookie isolation, expiry/rejection/ambiguity,
cancellation, bounded bodies, idempotency scope and shutdown. No real user token,
production credential or live Cloudflare validation is used. These are protocol-
derived fixture checks, not a claim of live provider interoperability. Canonical
events, public-pin delivery, complete unit/release gates and reference integration
remain pending until separately verified.
