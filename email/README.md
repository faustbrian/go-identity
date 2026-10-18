# Email

Registration verification also accepts the exact anonymous
`identity.username.signup`/`username-signup` v1 origin. Its keyed intent includes
that distinct original operation; a password-signup proof cannot be retargeted
to it or vice versa. Existing password-signup intent bytes are unchanged.
Neither policy construction nor unsigned payload preparation reserves a name,
creates an account, signs a proof, consumes it or enables an HTTP route.

## Optional verification callbacks

`NewVerificationHooks` selects ordered `identity.Hook` callbacks for supported
native signup/managed verification, managed new-address change, or purpose-bound
email OTP confirmation. Configure each native workflow independently;
constructing this policy alone enables no workflow. The
selection is optional and must be disabled by default. Only command, user and
identifier IDs are exposed as sensitive, read-only correlation. Addresses and
credentials are never supplied, and enrichment is rejected.

Before callbacks run outside SQL before reservation or durable OTP attempt
metering and may deny. They must be
side-effect-free: concurrent attempts may invoke them more than once. Existing
native authority, expiry and atomic consumption checks remain mandatory. After
callbacks observe only fresh known commits outside SQL; their failure preserves
commit/recovery while suppressing subsequent projection/signin. Scanner reads,
replay and recovery invoke neither phase; rollback and ambiguous results never
invoke success observers. Callbacks
are cooperative and bounded; durable notifications belong in the outbox.
Change the enclosing native configuration identity when callback semantics
change. Native/reference selection is delivered separately from this policy.

## Explicit registration verification and signin

`RegistrationVerificationSigninService` is independently selected. Its request
borrows the delivered original signup proof and original browser cookie, with
trusted origin/network/device inputs. It accepts no new remember choice.
`VerificationConfirmAndSignin` commits verification before attempting a distinct
signin command; inspect both outcomes and the returned error. A committed
verification is not rolled back by a later denied/unknown login. Replay and
`VerificationSigninRecover` are metadata-only and cannot redeliver credentials.
The initial native profile admits known-empty MFA only; enrolled/unknown state
denies without fallback. Existing `RegistrationVerificationService` remains
verification-only. Native composition is in `password/postgres`; typed operation,
transaction and acceptance semantics are in
[verification_signin_contracts.json](verification_signin_contracts.json).

An explicitly TOTP-enabled native owner may instead return `Challenge` after
verification commits. That pending result contains no session, cookie or CSRF
token. Its opaque proof is fresh-delivery-only; replay and recovery never mint
another proof. Complete through the selected verification-origin TOTP owner,
using the original signup browser and immutable challenge deadline/remember
choice. Default known-empty admission and verification-only services do not
implicitly select this capability.

`ChangeRequestRequest` accepts the exact multi-factor TOTP projection for
`identity.email.change-request` as well as the original password profile.
`Validate` is structural, not signature validation or current authority. Only
an explicitly selected native TOTP owner may authenticate and atomically consume
that proof. Verification-send and removal retain their password-only contracts.

## Safe self-removal

For explicitly selected administrative removal, set `TargetSubjectID` to the
other account. Keep `Caller.Request.Subject` and `Primary` bound to the actual
administrator, and `Caller.Request.Resource` bound to that target. The native
owner must independently enable this capability and authorize the exact current
actor/action/tenant/target. Empty target keeps legacy self-removal. The selected
password profile requires known-empty MFA for both accounts; enrolled or unknown
authority denies without downgrade. Target session/capability effects never
revoke or replace the administrator's session. This is a backend API, not a UI.

`AddressRemoveRequest` names an exact address and independent identifier/
verification versions, registered reason, original key and action-bound fresh
`RequestPrimary`. Choose `PreserveRemainingPrimary` for a nonprimary target or
explicitly `LeavePrimaryUnassigned`; no replacement is chosen by ordering.
The selected recovery disposition is `PreserveVerifiedEmailRecovery`.
Alternatively choose `ReplacePrimaryWithVerifiedEmail` and supply
`ReplacementPrimary` with an exact different verified email ID and its independent
identifier/verification versions. The native owner promotes only that record in
the removal transaction, without renewing verification. Replacement fields with
other dispositions deny; unverified, foreign, missing or stale records deny.

The selected implementation refines planning contract
`contract:operation:identity.email.address-remove:v1`: its optional
`ReplacementPrimaryID` is represented by `ReplacementPrimary`, which also binds
both independent predecessor versions. The catalog's single `ExpectedVersion`
maps to the removed address's identifier and verification fences; `ActorReason`
maps to the registered, bounded `Reason` code, never free-form audit text.
The existing keyed owner allocates/reuses the stable command ID; callers keep
the original key and complete intent rather than inventing another command.

`AddressRemovalService` is implemented by the native password PostgreSQL owner
and reference graph. It conserves actual selected password signin/reset eligibility
under current credential and known-empty MFA authority, not merely an address
count. Exact-target unused-link retirement, identifier/session invalidation,
audit and complete pending lifecycle admission commit with removal. Missing or
enrolled factor authority never falls back to password-only permission.

Exact retries preserve original key/input/proof/cookie/CSRF; changed intent
conflicts. `AddressRemoveRecover` observes original scope under current query
policy, not another mutation. `CommandResult.Cascade` is historical pending
admission, not consumer acknowledgement/completed cleanup. Unknown is not rollback.
`AddressRemovalRateSource` authenticates original possession for transport rate
admission without removal or renewed freshness; returned subject metadata is sensitive.

Email-owned address parsing, canonical comparison, original signup mailbox
verification contracts and authorized address reads. Native password-signup
confirmation is composed by the existing password adapter and reference backend;
the core does not own persistence, mail transport or password authentication.
The full add/change/removal lifecycle remains under development.

`VerificationSendService` and `ChangeRequestService` are storage-neutral keyed
request ports. They borrow original password/session/CSRF custody, bind exact self
scope and callback, and leave command/address choice, atomic proof use, delivery
and replay to the native owner. `ChangeRequestRequest` explicitly selects
`NotifyCurrentAddress`; no omitted proof policy silently becomes a weaker one.
Queued results mean committed local intent, not delivery, verification or signin.
Native password PostgreSQL and reference implementations of these new request
ports remain pending delivery. Persistence and HTTP are not mandatory
dependencies of the foundation contracts provided here.

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

### Primary email changes

`ChangeProfile` explicitly selects current-address and session policy. Zero denies.
`RequirePrimaryAddress` needs a verified primary; `PrimaryOrSoleVerifiedAddress`
also permits establishing the first primary when exactly one pre-existing verified
email exists. It never invents or promotes the old address, chooses by ordering or
uses the candidate as the notification recipient. Independent identifier and
verification versions remain bound to original intent.

`ChangeConfirmRequest` and `ChangeRecovery` select `identity.email.change-confirm`,
not verification-only history. Original fresh-password authorization and new-address
possession must commit with verified primary selection, old-address notification
and `InvalidateIdentifierSessions`. Confirmation issues no session/cookie. A fresh
commit can disclose the verified primary under policy; replay and recovery expose
only original metadata. Rollback recovery preserves both known noncommit and its
original failure cause; an aborted grant cannot be resurrected.

Native change-service delivery in `password/postgres`, opt-in management HTTP
composition, safe removal and stronger-factor profiles remain under development.

### Authorized address reads

`NewAddressQueryService` composes the existing primary identifier repository,
authorization service and redaction callback with `identity.UserQueryConfig`.
It selects self reads only. Administrative consumers must instead use
`NewAuditedAddressQueryService` with `AdministrativeReadAuditConfig`: an existing
`audit.Sink` and a positive `MaximumDuration` no longer than the query budget.
The owner records administrative successes and policy denials using the existing
audit recorder's fail-closed delivery. Only a validated primary acknowledgement
allows disclosure; unavailable, unknown, forged and panicking acknowledgements
withhold projections. The sink is borrowed and must honor cancellation and
concurrent calls. There is no background write, retry journal or fail-open mode.
Records retain safe actor/tenant/action/policy and authorized target metadata,
not mailboxes, cursors or arbitrary denied target inputs. Self reads create no
administrative access record. Configuration reports are not authorization.
It owns no database, goroutines, sessions or verification tokens. The query
port accepts a trusted current caller from authenticated composition; caller
IDs, groups and resource attributes must never be decoded from public input.
Storage implementations are platform-owned adapters, not missing application
domain stores. Delivery of the selected PostgreSQL/reference consumer proof
remains pending; these core contracts alone do not demonstrate that journey.

`AddressGet` and `AddressList` require exact action, tenant, target and policy
scope before primary access and repeat policy against observed status and
versions. Omitted `TargetSubjectID` means the authenticated human's own subject;
an explicit other target requires the authorization engine's administrator
policy. An administrator role string or target-selection field grants nothing.
Absent, forbidden, non-email and cross-tenant get targets return the same
redacted `identity.ForbiddenError`. Dependency failures and malformed primary
partitions return `identity.UnavailableError`, never partial observations.

Reads retain the kernel's original canonical/display text and independent user,
identifier-authority, identifier and verification versions. They do not
normalize stored addresses, create verification or establish current validity
leases. The callback selects exactly both address values or neither using
`canonical_value` and `display_value` under the configured policy/version and
registered reason. A partial or malformed selection fails closed; metadata
already requires current query authorization. Explicit `Values()` disclosure
belongs only in an authorized no-store response, not logs or caches.

List limits are 1..100 with a default of 25. The primary partition is complete
and capped at 128 identifiers; an unavailable partition is never truncated.
Non-email rows are filtered without skipping email pagination positions. The
opaque cursor is bounded to 512 bytes and binds tenant, target, actor, operation,
policy and effective page size. A changed user/identifier-authority version
returns a conflict: restart pagination rather than mixing snapshots. Cursors
are not signed credentials and grant no authority; each page is separately
authorized and read from primary storage. Diagnostics redact; implicit JSON/text
export is refused. HTTP owns the eventual explicit wire representation.

These read-only results report `CommitOutcomeNotCommitted` on success because
there is no mutation to commit. A successful read is not a command receipt or
proof of verification ownership. Cancellation, earlier deadlines and callback
panics return no partial data. This checkpoint is not the full email lifecycle:
add/resend/change/removal, their atomic effects and opt-in query HTTP composition
remain in the active M04 implementation.

### Explicit confirmation input

`VerificationConfirmRequest.Validate` admits a borrowed live opaque proof of
32..4096 canonical bytes, a stable command ID, an HTTPS callback of at most
2048 bytes and trusted tenant/caller/network input. It bounds raw URL components
before rendering, and caller collections before copying attribute sets. Neither
success nor repeated validation authenticates the proof, proves callback
allowlisting, consumes one-use authority, commits verification or issues a
session. A concurrent proof transfer invalidates custody after observation.
The native service checks the exact original intent and current policy and
coordinates every effect. The existing password signup adapter implements the
typed registration-only binding; the reference backend selects its scanner-safe
inspection and explicit HTTP confirmation without automatic session issuance.

`RegistrationVerificationService` is the narrow original-signup,
require-before-signin port. Its result conserves observed commit status even
when the later authorized address read fails. Inspect the returned error before
using an address: `Committed` alone is not proof that disclosure succeeded.
Fresh successful confirmation returns an active verified email projection;
replay returns metadata only. This profile does not issue a session. Explicit
auto-signin, remember-policy continuation and the full email lifecycle remain
required work, not implied by the reserved typed session field.

`NewVerificationRecovery` retains immutable original tenant/user/address/actor
and command correlation. `VerificationRecover` must enforce current query
authorization, never repeat consumption or disclose address/session payloads.
Correlation is not authority; reconstruction cannot prove a durable receipt.
In-progress results carry a positive delay of at most one minute; terminal
results carry no retry delay. Result validation is structural, not a primary
read, freshness lease or proof of execution. Recovery owns no resource or IO.

Inputs are caller-owned and immutable during calls. Direct formatting/logging
redacts and JSON/text serialization denies; explicit field projections and
private enclosing diagnostic fields remain sensitive and must not be logged.

### Signup verification grants

Authenticated address management uses `NewManagedVerificationPolicy` and
`ManagedVerificationSpec`, not a fabricated anonymous signup. It reuses the
bounded address/issuer/callback/key configuration but has its own `management-v1`
commitment. Exact original actor, session, request, address versions and token
generation are bound; verification-send and change-request select different
confirmation actions. `Authorize` checks an already authenticated grant and
exclusive original expiry only. Native workflows must still perform current
authority/factor/risk checks, persist issued state and encrypted delivery, and
consume atomically with the actual directory mutation. This policy alone is
neither a delivery service nor a safe confirmation endpoint.

`NewMagicLinkPossessionPolicy` is a separate signup-by-link policy; it does not
widen password registration verification. It freezes the address comparison,
issuer, audience, exact HTTPS callbacks, lifetime and nonzero policy revision.
`Authorize` checks an already authenticated grant against the complete original
prospective account, mailbox, request, browser binding and exclusive expiry.
Unsigned input, signin-only grants and substituted original fields deny.
The native consumer must invoke it using transaction-owned database time before
creating a verified identifier, and atomically enforce one-use, current authority,
collision admission and required session/lifecycle effects. Success is neither
a reusable possession receipt nor proof of committed signup. The policy itself
owns no store, signing keys, clock, network callbacks or resources. Public native
signup consumption and required MFA continuation remain integration work.

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
