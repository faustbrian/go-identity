# MFA (in development)

## Safe factor inventory

`ListService.List` authenticates the actual `ListRequest.Credential`, derives
the subject from the owned session result, authorizes `identity.mfa.list`, reads
bounded safe metadata and rechecks current session authority before disclosure.
Pass the trusted tenant and bounded correlation only; there is no target-user,
proof, command, idempotency key or mutation-CSRF input. Original acceptance expiry
always wins, even after a fresh second read.

`NewListService` borrows the real session owner, `FactorListReader`, authorization
engine and trusted clock through explicit `ListConfig`. `FactorListSnapshot`
requires a known positive generation: unavailable authority is not an empty list.
Collections and remaining codes are bounded to100. Empty lists and zero remaining
codes are valid. `ListResult.Outcome` stays zero because this is a read, not a
mutation or recoverable commit. `ValidateAt` checks display shape only.

Projections expose IDs, method/state, bounded untrusted labels, recorded dates
and optimistic versions; they never contain secrets, verifiers, replay counters
or reusable authority. Unknown usage times are omitted by HTTP, not fabricated.
Native selected-profile adoption is documented in `postgres/README.md`; HTTP and
reference selection remain independent. Full MFA qualification remains pending.

This Go 1.27 module owns second-factor authority, separate from primary
authentication. The initial API distinguishes explicitly known empty state from
unknown state. It now defines immutable browser partial-authentication continuation
bindings and shared attempt budgets. Selected native paths now support TOTP
enrollment, password-first TOTP/recovery login, authenticated step-up and recovery
regeneration. OTP/security-key orchestration, trusted devices and administrative
factor recovery remain unfinished; this is not the complete MFA capability set.

## Authenticated step-up and recovery regeneration

`TotpVerifyRequest.StepUp` explicitly selects current-session active-factor
verification. It is disjoint from login and `Enrollment`; inactive-arm inputs
must be absent. Submit the actual session, synchronizer, factor, opaque code,
trusted caller/origin/network and the exact selected protected purpose.
Unselected owners deny rather than fall back. This issues no session
and accepts no trusted-device bypass.

Step-up admission recognizes exactly `identity.mfa.recovery-regenerate`,
`identity.mfa.factor-update` and `identity.mfa.disable`. HTTP defaults to
regeneration only, but an explicit closed purpose set can select the other
management purposes independently. Proof production does not select management
routes or implement a disabled mutation owner. Original proofs remain action-bound
and cannot be reused as a different protected action.

`FactorUpdateRequest` defines bounded self-management input for `Rename`,
`Remove` and `Replace`, with an exact factor, positive non-exhausted optimistic
version, caller key and separately issued factor proof. `Rename` may clear an
optional label; `Remove` and `Replace` forbid label input. Structural validation
does not authenticate custody, prove a recovery path, consume a proof or mutate
storage. Native confirmed-TOTP rename and independently selected HTTP/reference
composition are implemented as described below. Remove, replace, disable and
other management operations remain unfinished and deny in this selected profile.

Only fresh known commitment returns `ContinuationProof`. Its `Bindings()`
projection retains the original session/version/action/timestamps but grants
no authority. `NewContinuationProof` validates structure, not signed issuance.
Native regeneration must authenticate original evidence and current owners.
Replay, uncertainty, cancellation and code-free recovery return no proof.

`RecoveryRegenerationService.RecoveryRegenerate` replaces every predecessor
recovery set atomically with proof consumption, factor advancement, subject
session revocation and audit/lifecycle effects. `RecoveryCodes` are owned
reveal-once secrets: explicitly deliver, then destroy them. Matching retries
and `RecoverRecoveryRegenerate` return original outcomes without codes. Sign
in again after successful replacement. PostgreSQL and opt-in HTTP/reference
composition provide these workflows without consumer-written domain stores.

Trusted adapters construct `FactorAuthority` from current owner storage.
`RequireEmailRecovery` denies unknown, cross-subject, or enrolled state. Successful
admission still requires verified email, current account and risk checks, and a
purpose-bound capability. Never accept authority records from a client or cache
them as authorization. PostgreSQL admission holds the generation lock through
the protected transaction. Primary passkey credentials are not MFA enrollments.

Public API semantics are documented on `AuthorityRecord`, `FactorAuthority`,
`NewFactorAuthority`, `Version`, and `RequireEmailRecovery`.

## Partial authentication

Construct `PartialAuthContinuation` from trusted `ContinuationSpec` storage,
not client fields. Retain the original primary-proof identity/digest, browser
flow/origin, independent factor and policy generations, allowed methods, resolved
remember policy and absolute lifetime (at most five minutes and never beyond
the original primary proof expiry). `Bindings` returns
an owned projection. The projection is not authenticated or committed authority.

`CapabilityPayload` maps the immutable scope to the existing capability format,
with one use and no raw primary credential. The actual capability issuer owns
signing and replay storage. `Authorize` compares an already verified grant
read-only; repeat validation consumes nothing and cannot refresh expiry.
`ScopeDigest` supplies that same immutable binding to durable adapters without
signing, consuming or granting authentication. Mutable attempts and terminal
states cannot renew or change it.

`RecordAttempt` projects one shared-budget transition for an allowed factor
method. The durable MFA owner must CAS the exact stored version and persist the
transition atomically with the factor outcome. Switching methods cannot restore
attempts. Exhaustion is `Revoked`; absolute expiry and terminal states deny.
These pure methods do not authenticate factors, create durable continuations,
consume capabilities or issue sessions. Required MFA must never fall back to a
single-factor session while its continuation service is unavailable.

## TOTP computation and custody

`TotpVerifyRequest` binds the original child challenge, selected enrolled factor,
opaque code and original browser cookie to a trusted transport caller. `Validate`
checks structure only, including fragment-free HTTPS origin/callback URLs; it
does not authenticate the caller, consume a proof or check a factor. Current
policy must explicitly handle `TrustDevice`; unsupported policy denies it.
`TOTPCompletionService` describes the login-completion boundary, but a concrete
public service and reference/HTTP composition are still being implemented.
Recovery cannot disclose another credential or repeat primary authentication.

`TOTPProfile` explicitly selects SHA1/SHA256/SHA512, 6..10 digits, a whole-second
15..120-second period, 0..2 skew steps and an exact provisioning issuer. Zero
skew is supported. Validation never repairs a stored enrollment profile.

`NewTOTPVerifier` retains an independent, trusted comparison key behind opaque
custody. `Verify` borrows an owned `password.Secret`, accepts only an opaque
`authentication.OneTimeCode`, and compares through authentication's existing
keyed-digest contract. The native caller supplies authoritative time and an
injective tenant/subject/factor/challenge scope including the retained comparison
key version. The caller destroys the secret after use; verification retains no
factor bytes. Submitted codes have no plaintext accessor.

The returned counter is metadata, not a proof or consumed factor. Read and fence
`TOTPReplayState` under native durable authority and advance it atomically with
the shared attempt budget, continuation completion and original-primary session
effects. Verification alone must never issue a session. Those durable completion
operations and enrollment remain unfinished.

## Selected factor rename

`FactorManagementService.FactorUpdate` accepts an owned `IdempotencyKey`, an
actual session/synchronizer, the original factor-update proof and the observed
factor version. A fresh keyed call leaves `CommandID` empty; only the native
request-key owner selects it. A supplied retry ID must match retained input.
`Rename` changes a bounded presentation label; an empty label clears it. The
label is never credential authority, a provisioning URI or HTML.

The native TOTP profile authenticates original signed proof provenance and the
exact source session, fences current account/factor authority, and atomically
updates the label, consumes proof, revokes all subject sessions and records
audit/lifecycle effects. Do not expect the source session to remain usable.
Fresh known commits return safe `FactorProjection`; replay, recovery, errors and
uncertain/expired delivery return no factor projection. Use
`RecoverFactorUpdate` with the original command for outcome reconciliation,
not another mutation or renewed proof. HTTP exposure is separately selected.
Remove, replace, disable and other MFA management remain unfinished; defining
their action names does not enable them in this selected native profile.
