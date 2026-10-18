# Username policy

`RenameService` owns keyed self-rename through
`password/postgres.NewUsernameRenameService`. Supply the already selected native
action-proof source, fixed policy, concrete risk/counter configuration and local
keyring. `RenameRequest` carries trusted tenant/caller/network, the exact username
identifier and observed versions, original bearer/proof/CSRF custody and a retry
key. It cannot choose another user's target. Preserve the raw spelling and all
original fields for matching retries; a case-only spelling change is still a
different input for the same key.

The native reference profile uses a thirty-day old-name cooldown. Display-only
edits preserve verification and create no retirement; canonical changes reset
verification and retire the old canonical value. Both advance identifier
authority and invalidate existing identifier-bound sessions. Subsequent signin
uses the new canonical value. A fresh proof and known-empty current MFA state
are required; enrolled-factor continuation is not silently approximated.
Cookie transport also requires the original synchronizer. Recovery and matching
terminal retries return original metadata, never credentials or a second rename.
Username HTTP/reference composition remains a separate selection.

`AvailabilityService` is the advisory workflow port. Its native implementation
is `password/postgres.NewUsernameAvailabilityService`: supply the same fixed
username policy, actual durable counter/audit/identifier configuration and
bounded normalized risk sources. Tenant and network are trusted server-derived
scope, not browser authority. Every call is a separate metered attempt, and an
available result never reserves the name or overrides atomic signup/rename.

`username` is the syntax/normalization and enrollment-validation component of
the identity username workflow, not a store, signup service, or authentication
engine. Use `Validate` once for signup/rename; use `Canonicalize` for signin and
lookup. Only an atomic identity-owned transaction can reserve or swap a name.
Availability is advisory, never a reservation. Do not expose policy errors as
account-existence signals in signin responses.

```go
policy, err := username.NewPolicy(username.ReferencePolicySpec())
if err != nil { return err }
name, err := policy.Validate(ctx, "Straße")
if err != nil { return err }
record := name.Record() // sensitive; canonical "strasse", original display
// Persist Canonical, ProfileID, ProfileVersion, and Display together.
_ = record
```

## Fixed Latin-v1 contract

Profile `identity.username.latin-v1`, version 1, uses the published identifier
primitive's fixed Unicode 15.1 NFC → full default non-Turkic fold → NFC.
It never trims whitespace. Both supplied and final values must contain 3..32
Unicode codepoints and at most 128 UTF-8 bytes; combining marks count separately
before normalization and fold expansions count afterward. No grapheme-count
claim is made. Canonically equivalent Latin forms share a lookup key, but an
input outside the pre-normalization bounds remains invalid.

Allowed characters are Unicode 15.1 Latin letters, ASCII digits, underscore,
dot and hyphen, plus basic inherited combining diacritics U+0300..U+036F only
following a Latin base (not U+034F). Punctuation is permitted anywhere, with no
implicit trimming or separator rewriting. The narrow Common punctuation set
avoids control/format characters, emoji and confusable symbol lookalikes.
The same syntax applies before and after normalization. No other script is
permitted; inherited marks do not introduce another base script. See the
[bounded official-source provenance](unicode151/README.md).

This is not UTS #39 confusable-skeleton matching: visually similar Latin names
can remain distinct, and fullwidth Latin letters are not compatibility-folded.
Changing script/syntax/normalization requires a new profile and collision-aware
migration, not a compiler upgrade or reinterpretation of stored bytes.

## Enrollment and persistence

Startup requires an explicit reserved manifest version and checksum. Reference
v1 is exactly `admin`, `administrator`, `api`, `auth`, `login`, `logout`, `me`,
`oauth`, `oidc`, `root`, `scim`, `sso`, `support`, `system`, `webhook`, matched
after folding. `me` remains in the manifest even though below the selected
three-codepoint enrollment minimum. Version 1 cannot be redefined. Later
manifest versions may replace the enrollment set; checksums authenticate
configuration identity, not an untrusted source's authority.

Custom validators are copied in order and run synchronously without locks,
under the earlier caller deadline or configured timeout (1 second reference,
positive and at most 30 seconds). They must cooperate with cancellation; no
goroutine or timeout preemption is promised. Cancellation is checked before and
after every callback. Errors/panics deny and never escape as raw diagnostics.
Callbacks must be concurrency-safe and must not log the sensitive `Name` fields.

`Canonicalize` and `Restore` intentionally do not apply reserved/custom
enrollment checks: a later restriction must not prevent existing users signing
in. `Restore` proves exact profile, canonical fixed point and correspondence to
the display value; it is not ownership or authentication proof. `Name` redacts
formatting and structured logging and refuses implicit JSON/text serialization.
`Record` and `Display()` are explicit sensitive projections. `Name.Equal`
compares canonical bytes and the exact profile identity/version independently
of display; invalid zero names never compare equal. No opaque primitive
canonical accessor is exposed: the upstream value contains inline sensitive
strings that private enclosing-field diagnostics can disclose even when normal
formatting is redacted. Canonical bytes and profile metadata leave `Name` only
through the intentionally sensitive `Record` projection.
Do not use display as the unique key or names/user IDs as unbounded metric labels.

The module has no tenant-global mutable configuration. Compose one immutable
policy per tenant when enrollment sets differ, preserving the fixed canonical
profile and identity-owned tenant uniqueness boundary. Errors are stable typed
constants usable with `errors.Is`; denial yields no partial `Name`.
