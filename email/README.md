# Email

Email-owned address parsing and canonical comparison policy. This development
checkpoint does **not** implement verification, address mutation, persistence,
delivery or authentication. Those remain requirements of this module.

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

Full lifecycle workflows, privacy contributors, real-adapter/reference journeys,
provider qualification, exact coverage/mutation, clean published consumers and
release gates remain pending. No memory persistence fallback is provided.

Release notes are in [CHANGELOG.md](CHANGELOG.md).
