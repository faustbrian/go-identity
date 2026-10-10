# Email

Email-owned address parsing, canonical comparison and original signup mailbox
verification grant policy. This development checkpoint does **not** implement
scanner-safe confirmation, address mutation, persistence, delivery or
authentication. Those remain requirements of this module.

## Quick start

```go
profile, err := identifier.NewNormalizationProfile(identifier.NormalizationProfileSpec{
    ID: "email-comparison", Version: 1,
    Unicode: identifier.UnicodeNormalizationNFC, MaximumBytes: 4096,
})
// Handle err; choose CaseFold and TrimSpace deliberately, not per request.
parser, err := email.NewAddressParser(email.AddressPolicy{
    MaximumBytes: 4096, Canonicalization: profile, PreserveDisplay: true,
})
// Handle err.
address, err := parser.Parse(email.AddressInput("User+tag@BÜCHER.example"))
// Handle err. Explicit sensitive persistence projection:
record := address.Canonical().Record()
```

See the compiling example for complete error handling. The parser copies policy
and is reusable concurrently, without resources, callbacks, DNS or stores.
The same policy/version must govern stored identifiers, delivery destination
selection and rate-key comparison. Changing it requires collision-aware migration;
never silently reinterpret stored identities under a new profile.

## API and policy

- `NewAddressParser(AddressPolicy)` freezes byte bounds, explicit identifier
  normalization and display retention. Zero/incompatible policy denies.
- `Parse(AddressInput)` bounds raw UTF-8 before normalization and grammar work.
  It accepts one dot-atom mailbox with an internationalized local part, then
  canonicalizes its domain using identifier's fixed nontransitional STD3 IDNA.
  Local case/Unicode/edge trimming follow the explicit comparison profile.
  That profile applies only to the local component: an ASCII `@` is required,
  and domain whitespace is rejected rather than trimmed. IDNA-mapped root dots
  are rejected too. Local comparison settings cannot rewrite the DNS destination.
- `Address.Canonical()` explicitly exposes sensitive version-bound identity;
  `Display()` exposes accepted original input only when retention is selected.
- `ErrInvalidPolicy` and `ErrInvalidAddress` disclose no input or existence.
  `ErrSensitiveSerialization` denies implicit JSON/text export.

Local parts are capped at 64 UTF-8 bytes, canonical mailboxes at 254 bytes, and
both raw/canonical input by `MaximumBytes` (3..4096). Domains obey the
normalization owner's IDNA and DNS-length checks. Internationalized local parts
require separate SMTPUTF8-capable sender selection; parsing proves no delivery
capability. See [RFC 5321](https://www.rfc-editor.org/rfc/rfc5321) and
[RFC 6531](https://www.rfc-editor.org/rfc/rfc6531) for transport requirements;
this deliberately restricted identity parser is not full mailbox/SMTP conformance.

## Tradeoffs, security and FAQ

### Signup verification grants

`NewRegistrationVerificationPolicy` freezes the real address policy, issuer,
single audience, exact HTTPS callbacks, explicit lifetime (whole seconds,
positive and at most 24 hours), and dedicated retained HMAC binding keys.
`Payload(RegistrationVerificationSpec)` returns unsigned input with no grant ID
for the native registration issuer. It binds the original anonymous signup
command and ingress actor separately from the prospective new user; no logged-in
session is invented. Canonical IDs, including already-admitted ULIDs, are kept
unchanged. Identifier and verification versions, token version, exact canonical
mailbox/profile and callback are committed with a domain-separated keyed digest,
not a public unkeyed mailbox index. Returned maps/slices are caller-owned.

The internal one-use purpose is `identity.identifier.verify`; the explicit
`email.confirm_operation` caveat selects `identity.email.verification-confirm`.
This is **not** the authenticated-session identifier-management proof profile.
`Authorize` checks an already cryptographically authenticated grant against
the exact original intent and exclusive expiry using explicit current time.
It does not verify a signature, check revocation/current primary versions,
consume the grant, change an identifier or issue a session. Those checks and
effects must belong to the eventual native confirmation transaction. A payload
or successful shape authorization must never be treated as completed email
verification. Retain original binding keys until their grants cease to exist;
rotation selects the current version only for new issuance, without renewal.

`CapabilityPayload` and verification configuration/specification expose explicit
sensitive fields for trusted composition. Direct formatting/logging redacts and
implicit JSON/text serialization denies. As with raw `AddressInput`, Go can
bypass these methods when traversing private enclosing fields: do not place raw
configuration or sensitive field projections into diagnostic objects. Keep
binding keys independent of signing, replay and encryption keys. The policy
owns no resources, goroutines, callbacks, network requests or stores.

Names, groups, comments, quoted local parts, domain literals, trailing-dot
domains and multiple recipients are explicitly unsupported. C0/C1 controls,
malformed UTF-8 and the fixed invisible separator syntax deny. Plus tags and
provider-specific aliases are never stripped. DNS existence is not inferred.

Preserving local case is recommended unless the owning product deliberately
chooses case-insensitive comparison; do not conflate a comparison policy with
SMTP server behavior. Display text is not safe HTML and must never select a
lookup key or authority. Canonical equality proves neither uniqueness nor
ownership; tenant-scoped persistence and verified proof remain separate owners.
Keep explicit projections out of logs, diagnostics and public errors.
Parsed `Address` uses immutable pointer custody so formatting a consumer's
private enclosing field cannot traverse its retained canonical/display bytes.
`AddressInput` deliberately remains the required raw string scalar: direct
formatters redact, but Go can bypass them in private enclosing fields. Never
log raw input or put it in diagnostic objects. Explicit canonical records,
display strings and string conversions are equally sensitive projections.

Full lifecycle workflows, privacy contributors, real-adapter/reference journeys,
provider qualification, exact coverage/mutation, clean published consumers and
release gates remain pending. No memory persistence fallback is provided.

Release notes are in [CHANGELOG.md](CHANGELOG.md).
