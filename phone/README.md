# Phone number policy

This module provides bounded number canonicalization, **not** phone ownership,
verification history, SMS transport, deliverability, carrier intelligence,
authentication, risk decisions, signup, signin or recovery. Those composing
owners must enforce their own tenant scope, uniqueness and transactional proofs.
It requires Go 1.27.0 or later.

## Existing-account verification contracts

`VerificationService` defines separately selected native `SendVerification`,
`Verify` and `RecoverVerification` operations; this module does not implement
them. `EnrollmentRequest` carries the already canonicalized Number, original
session/action proof, trusted self-user caller and network/device context.
Structural validation bounds input and requires exact tenant, user and action;
it does not authenticate caller assertions or proof signatures, prove freshness,
or authorize a phone attachment. Bearer requests may omit CSRF; native cookie
configuration owns synchronizer enforcement. The native owner must authenticate
original proof/session, current account/factor/risk policy and uniqueness, and
coordinate identifier, purpose-bound OTP, delivery and audit in one transaction.

Verification and recovery accept authenticated-session OTP flows only.
Both requests carry the current `CSRFToken` for cookie-authenticated admission;
zero remains structurally valid for the bearer profile. Native transport
selection must authenticate that synchronizer, never infer it from retained
session state or treat the field's presence as permission.
`VerificationRecovery` wraps the OTP owner's original code-free attempt
correlation; send and consuming command IDs cannot alias. Its explicit Bindings
projection is sensitive correlation, not a recovery capability or permission to
resubmit. Recovery uses `identity.phone.verify.recover`, authenticates original
custody and current query policy, and never compares another code. Results retain
observed durability, replay state and original recovery independently of later
disclosure errors; an unknown outcome must not be guessed to mean rollback.
Requests, recovery and results are closure-backed opaque handles: even formatting
an enclosing private field cannot traverse retained proof, bearer, number or
correlation. Construct the three request and two result types with their explicit
`New...` constructors and sensitive `...Spec` values; native consumers use
`Bindings` for an explicit projection. Constructors validate before copying,
clone Caller maps/groups, and return independent copies from each projection.
Zero request handles deny; zero results may accompany errors but cannot project.
Specs expose sensitive fields and are not opaque safe logging handles: never log
or serialize them or place them in private diagnostic containers, even though
their ordinary formatters redact. These handles reject implicit JSON/text
serialization. Result construction checks exact native operation/binding and
original tenant/record/recovery correlation; a verified-phone projection appears
only for fresh committed nonreplayed verification, never unknown/replay history.

Before cloning Caller, admission bounds IDs/groups/attribute names to 128 bytes,
actions/resource types to 256, attribute strings/set entries to 4096, each group
or set collection and attribute map to 64 entries, and the total Caller payload
to 64 KiB. String-set cardinality is checked before requesting the copied set
projection. These are this phone profile's limits, not generic authorization
defaults. Native signature, proof freshness and current policy checks remain
independently required. These contracts issue no session or suppression
choice and do not implement signup, signin, replacement/removal or password
recovery. Interface presence is not native workflow or milestone completion.

```go
policy, err := phone.NewNumberPolicy(phone.NumberPolicySpec{
    Profile: phone.CurrentNumberProfile(),
    MaximumInputBytes: 64,
})
if err != nil { return err }
number, err := policy.Canonicalize(ctx, "+12025550123")
if err != nil { return err }
record, err := number.Record() // sensitive explicit persistence projection
```

## Frozen comparison and input policy

Select `CurrentNumberProfile()` explicitly. The supported profile ID is
`identity.phone.e164-ascii-v1.metadata-v9.0.40`, version 1, metadata `v9.0.40`.
Its ID already binds metadata, so a native identifier owner storing profile ID
and version need not invent a concatenation. Store the complete `NumberRecord`
for restoration, including its exact profile and optional display provenance.
Equality compares E.164 and all profile fields, never display. Byte-equal E.164
under different metadata profiles is not automatically a proven profile match.

ASCII-v1 accepts only `+` followed by ASCII digits for international input.
It requires an exact E.164 fixed point and at most 15 digits. There is no
trimming, separator removal, Unicode digit folding, vanity expansion, RFC3966
URL extraction or extension handling. These deliberate restrictions prevent
the parser's user-friendly repair/extraction rules from changing an identity.
Formatted phone numbers are unsupported in this first named profile.

National input is disabled unless `AllowNational` is true and `DefaultRegion`
is an explicitly supported uppercase two-letter region. It must contain only
ASCII digits, be valid for that region and exactly match the digits in the
metadata's NATIONAL format (including its national prefix). IDD prefixes,
missing-plus inferred country codes and omitted national-prefix variants deny.
International input is always parsed with an empty region, even when national
input is enabled. Shared calling-code territories remain distinct for national
validation; non-geographic country code `001` is not a default region.
Short codes and structurally invalid numbers deny. These checks describe the
selected profile, not every possible valid telephony presentation or dial plan.

`MaximumInputBytes` must be 16..128 and bounds raw bytes before upstream work;
E.164 output is independently bounded to 16 bytes including `+`. Retaining
original display is disabled unless `PreserveDisplay` is explicit. Retained
display obeys the input bound. `NationalRegion` is retained only with original
national display. Restoration rejects mismatched original display/region,
noncanonical E.164, incompatible profiles and unsupported metadata, rather than
guessing. An absent display stays absent; restoration never invents it.

## Password-signin original target binding

`PasswordSigninIdentifierBinding(number, tenant, key)` computes an opaque,
domain-separated commitment over the canonical E.164 number and its fixed
profile/version, tenant and distinct password-signin action. Supply a 32..64-byte
deployment-owned independent key. Display and national spelling are not identity.
The helper borrows the immutable key for this call and owns no database or IO.
It proves neither phone ownership nor a password, factor or authenticated user.

Trusted initiation passes this server-derived value into the actual session
pre-auth issuer's `IdentifierBinding`; the selected native password owner must
recompute it before comparison. Do not accept a commitment supplied by a client
or reuse an OTP-login flow. The session issuer binds it to the original cookie,
remember choice and deadline; copying the commitment cannot retarget that flow.
The native password adapter's adoption guide documents selected composition.

## Ownership, privacy and concurrency

`RemovalService` is independently selected self-service removal, not number
replacement or recovery. Construct its opaque `RemoveRequest` from a canonical
`Number`, exact identifier/verification versions, original bearer and signed
password proof for `identity.phone.remove`, CSRF where applicable, registered
reason and stable idempotency key. These selectors alone grant no authority.
The native owner must authenticate the original proof, current phone/factor
authority and an actual independent recovery path. It atomically removes and
retires the phone, consumes proof, advances identifier authority and queues the
required old-channel notice and pending lifecycle cascade. Old identifier-bound
sessions deny; physical session cleanup and external SMS delivery are separate.
No OTP is consumed and no session is issued. Preserve original request custody
on retry; use `RecoverRemoval` for an uncertain original outcome, not a new
mutation. `RemoveRequestSpec` projections are sensitive and must not be logged.

`NumberPolicy` and its `Number` results are immutable and support concurrent
callers without owned goroutines, callbacks or IO. Nil/zero policy denies;
zero Number cannot project a usable destination or record. Nil context denies,
and cancellation before or after bounded parsing returns a redacted error.
There is no global default policy.

`Number` uses closure-backed private state so ordinary `fmt`, enclosing private
fields, and `slog` do not reveal digits. Implicit JSON/text serialization denies.
`Record`, `DeliveryNumber` and `Display` explicitly expose PII: do not log them.
`NumberRecord` deliberately permits persistence serialization, but direct
formatting and structured logging redact; its exported fields remain sensitive.
Protect stored records, tenant-bind lookups, escape displays, and include them
in the owning application's privacy export/deletion policy. No record field is
a verification fact. A valid number can be recycled or ported and is never
ownership, verified status, SMS deliverability, risk evidence or authority.

The upstream parser exposes process-global metadata override/mutation APIs.
Applications using this profile must not call `metadata.Use` or mutate upstream
metadata collections/maps. This module never does so or exposes upstream
objects. The supported concurrency/profile contract assumes those globals
retain their embedded pinned state; it cannot defend against other trusted
in-process code deliberately replacing upstream internals.

## Provenance and upgrades

The parser is pinned to
[`github.com/nyaruka/phonenumbers/v2@v2.0.14`](https://github.com/nyaruka/phonenumbers/tree/v2.0.14),
origin commit `d586aeb6aac459d04c2f2b61ab9e4d7c8a9c7d43`.
Authenticated Go module content checksum:
`h1:hgxmpkDTy/rvl/3yx5oPXiRHWZmkw8Tbd6WkBpavJBA=`;
go.mod checksum: `h1:ch3CB5vKpdcQXyRLWm+ELlEdiUwagKR6pYvXgVXRiN0=`.
Download/verify through `proxy.golang.org` and `sum.golang.org`; `go.sum` binds
the source. No private parser, copied metadata or vendored dataset is maintained.

The downloaded and
[official tagged metadata/version.go](https://github.com/nyaruka/phonenumbers/blob/v2.0.14/metadata/version.go)
both identify upstream metadata **v9.0.40**; the constructor checks that binding.
This is independent of Java-code synchronization: upstream
[SYNC.md](https://github.com/nyaruka/phonenumbers/blob/v2.0.14/SYNC.md)
records code synchronization against v9.0.38. Upstream's
[ParseAndKeepRawInput/MaybeExtractCountryCode](https://github.com/nyaruka/phonenumbers/blob/v2.0.14/phonenumberutil.go)
and country-code source enum document the inference that this profile denies.
`IsValidNumber` is structural metadata validity, not proof that a number is used.

The Go port's [LICENSE](https://github.com/nyaruka/phonenumbers/blob/v2.0.14/LICENSE)
is MIT; Google-derived protobuf files retain Apache-2.0 notices.
The runtime dependency `google.golang.org/protobuf@v1.36.11` is BSD-3-Clause.
Preserve upstream copyright/license notices when redistributing dependencies.
Test-only upstream dependencies in go.sum are not added as runtime imports.

A metadata/parser upgrade requires authenticated source, license and behavior
review, a new immutable comparison profile binding, regression/fuzz proof and
an explicit migration/reverification decision by the owning lifecycle service.
Do not overwrite old profile IDs, relabel old records, merge lookups across
profiles automatically, or restore old records under new metadata. Preserve
the old interpreter in an explicitly supported version or migrate through an
audited owner operation; newly invalid/changed numbers deny pending that choice.
Reverification must independently establish present ownership, with recycling,
porting and recovery risk policy; canonicalization never supplies that proof.
