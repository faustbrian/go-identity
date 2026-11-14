# API keys

## Current validity of an authenticated delegation source

`NewSourceAuthorityBinding` snapshots the nonsecret root and effective ceiling of
a still-fresh `VerificationResult` supplied by the real `AtomicVerifier`.
The binding selects user-owned keys under the exact modern or explicitly
verify-only legacy SHA-256 configuration. Existing imported IDs, restrictions
and expiry remain unchanged; absent historical expiry is allowed only by
`AllowLegacyNoExpiry`. It never permits unbounded validity evidence or new
legacy issuance. `SourceAuthorityObservation`
represents a separate, bounded primary read of current key/owner/policy facts;
neither value nor structural validation authenticates a bearer or proves a human
actor/session. Existing `Service` and `AtomicVerifier` interfaces are unchanged.

The owned native adapter supplies `ObserveSourceAuthority` and an existing-Work
`RequireSourceAuthority` fence. Consumers must preserve original verification
timestamps separately, retain exact root/security versions and credential expiry,
intersect grants and use the earliest contributing current deadline. A genuine
later primary read is distinct from copying or replaying an expired observation.
User ownership never converts the API-key actor into a human. These existing
USER types and methods remain USER-only. Legacy observation/fencing requires a
native adapter that explicitly adopts `LegacyConfiguration`; this root extension
alone does not provide that adoption. This seam is not an OAuth exchange.
Bindings/observations deny implicit JSON export. A composing durable owner must
use its explicit nonsecret projection, not a public proof factory or raw key.

Organization-owned modern sources use the distinct
`NewOrganizationSourceAuthorityBinding` and
`OrganizationSourceAuthorityObservation` contracts. Native
`ObserveOrganizationSourceAuthority` / `RequireOrganizationSourceAuthority`
consume actual organization credential authority, not the creator's membership
or USER epochs. Member removal does not revoke independent integration ownership;
human management/delegation still needs its own current member permission.
Organization aggregate version is separately fenced, while the exact credential
epoch prevents archive/restore from reviving a key. Original read-start freshness,
key root/security versions, finite source expiry and non-expanding grants remain
mandatory. Organization read/verified/expiry timestamps retain the owner's
original clock domain separately from the outer primary-database timestamps;
neither is retimed or required to nest exactly across clocks. Overall validity
uses the earliest original deadline. Legacy organization sources are not selected.
Adopting these root
types alone does not implement the native reader/fence or OAuth exchange.

`Updater` is an optional name/permission-management extension; it does not
change the existing `Service` interface. Supply the genuine human bearer,
stable idempotency key, exact record version, required name and explicit sorted
permission ceiling. Send the unchanged grant to rename only; an empty nonnil
grant explicitly removes all permissions, while nil is invalid. No owner,
credential, configuration or expiry replacement is accepted. Organization
updates select an explicit target and require current membership/permission.

`UpdateResult` retains the sole coordinator's receipt and only attaches safe
record/configuration snapshots for proven commitment. Exact user and organization
schemas remain distinct: `apikey-update-v1` and
`apikey-update-organization-v1`. A name-only change advances the record CAS
version, not the credential or configuration security epochs; narrowing advances
the existing security dimensions once. Current native authorization, atomic
required effects and original request-key recovery are mandatory; these shape
contracts alone do not implement a durable update. No secret is revealed.

`MetadataService` is an additive `Get`/`List` contract; the existing `Service`
interface is unchanged. Requests retain the genuine human bearer. An empty
`OrganizationID` means that human's own keys, not an arbitrary user override;
organization reads require an explicit target and current membership/permission.
The owned native adapter supplies actual session, tenant, owner and selected
configuration checks, including on every later page. Root shape validation alone
does not provide any of those authorities.

Results are copied stored `Record` metadata, including revoked/expired records,
never a secret, digest, verification result or current effective permission.
The stored grant is only a historical immutable ceiling. Reading metadata does
not verify a credential, debit quota, narrow grants or authorize later actions.
Implicit request serialization and diagnostics remain credential-redacted.

`ListRequest` accepts 1..200 records and up to sixteen sorted distinct selected
configuration IDs; absence selects all configured profiles. IDs retain the
existing configuration contract of 1..128 bytes rather than a different read-only
normalization. Cursors are opaque, at most 512 bytes, bound to the exact
tenant/human/owner/configuration scope, and carry no authentication authority.
Paging is a deterministic ascending-key-ID live view, not a historical snapshot:
inserts behind the cursor are omitted, inserts ahead may appear, and existing
keys are not repeated. No transaction is retained between pages. The actual
native implementation and its PostgreSQL consumer must be adopted before this
new contract is usable; no metadata HTTP/Reference profile is provided here.

`github.com/faustbrian/go-identity/apikey` defines explicit user/organization
ownership and an explicit verify-only legacy profile. New issuance uses fixed
`idk_` plus 32 CSPRNG bytes in unpadded base64url, with
HMAC-SHA-256 lookup separated by tenant, configuration/revision, pepper version,
issuer, environment and audience. Raw keys are transient and reveal once across
copies. No key plaintext belongs in a durable preparation, receipt or journal.

```go
secret, err := apikey.GenerateSecret()
// Handle err. Derive and persist only secret.Digest(pepper, tenant, configuration).
// Reveal only after the sole durable command owner proves issuance committed.
wire, err := secret.Reveal()
// Deliver wire exactly once; never log it. Handle err.
```

The owned PostgreSQL adapter supplies `Service`; application code supplies
configuration, actual human credentials and explicit external policy, not a
domain store or a replacement transaction/replay engine. Owner and human actor
remain distinct. User-owned management requests have no user/owner override.
`OrganizationService.CreateOrganization` separately accepts an explicit
`OrganizationCreateRequest`; it cannot silently become a self-owned `Create`.
The target organization ID grants no membership or permission. Committed
organization results require the exact `apikey-create-organization-v1` or
`apikey-rotate-organization-v1` schema with the real human manager as actor,
while the record retains its separate organization owner. The native adapter
must prove current membership and permission before protected issuance; this
root contract does not supply that authority. Original invocation reveal-once
and status-only recovery semantics are identical for both owner kinds.
`ParseKeyID` preserves bounded existing IDs including canonical ULIDs; native
composition owns canonical identifier policy. `NewKeyID` is a separate modern
random-ID generator, not a constraint on imported durable identity.

`ScopePolicy` intersects immutable grants with real current owner, tenant and
policy authority. A removed permission denies before any persistence completes.
Narrowing decisions retain the exact command, owner epoch, key/API-key versions
and policy revision; a store must persist them atomically with required effects.
Restoring owner eligibility cannot restore revoked keys or withdrawn immutable
permissions. Verification is not a durable session or an assertion that the key
creator is a currently authenticated human.

For an organization owner, `Owner.Version` is the terminal credential-revocation
epoch, separate from organization policy and membership versions. Current
authority must match the record's epoch exactly; archive/delete followed by
restore cannot make an older credential eligible again. User-owner current
policy versions retain their existing equal-or-newer comparison.

Every key is its own shared-issuer credential root: `RootID == ID` and
`RootVersion == AuthorityVersion`, including after permission narrowing.
A rotation successor gets a new root; `PreviousID` preserves replacement/audit
lineage without depending on the revoked predecessor's authorization. Old root
credentials and their descendants remain denied, while the successor uses its
own actual current root/version. Delegation itself is not selected here.

The shared `ConfigurationAuthorityBinding` is a different dimension scoped to
tenant plus configuration ID. Native permission/configuration/rotation/revocation
transitions advance that aggregate independently of the affected key's
credential-security epoch. Known verification carries the actual current
configuration binding. Reduction decisions fence its expected value and committed
results report its successor; unknown results report no invented post-state.
Changing key A does not rewrite or revoke key B's independent credential root:
a fresh B verification reads the new configuration epoch and preserves B's root.

Configurations explicitly disable caches and select unlimited quota or the
modern-only `QuotaTokenBucket` profile. For a finite profile, set the value
`TokenBucket: TokenBucketPolicy{Capacity: 1000, RefillAmount: 1000,
RefillInterval: time.Hour}` and submit a positive `DebitAmount` no greater than
capacity. Capacity is 1..1,000,000; refill amounts are positive uint64 values,
and intervals must be positive, microsecond-exact Go durations. Unsupported
precision is rejected, not rounded. Zero policy with `QuotaUnlimited` retains
the original JSON/configuration fingerprint bytes. Policy/configuration revision
and debit amount bind the exact original attempt; changing them is not a retry.

The PostgreSQL adapter must install its optional quota migration before finite
selection. Only authenticated current-owner requests with the required grant
can debit. `QuotaMetadata` reports the original transaction's whole remaining
tokens and database observation time, not current allowance or renewed authority.
Continuous fractional accrual remains with the native owner. Known debit is
`VerificationAttemptDebited`; exhaustion is a known non-debit with no principal.
A submitted uncertain debit returns `ErrDebitOutcomeUnknown` with the same
attempt ID, `VerificationAttemptPossibleDebit`, and no principal or quota
metadata. Reconcile that original ID, never guess by issuing another attempt.
Current authority denial can prevent even observing an older same-ID attempt.
That result is also possible debit, uniformly without revealing whether history
exists. A zero fingerprint/scope means nothing was disclosed, not proven absence.
Retain any earlier fingerprint/scope for reconciliation; if none was disclosed,
retry only that original request after current authority permits observation.

Both profiles record one exact verification attempt/fingerprint. Known unlimited
success is `VerificationAttemptNotApplicable`. A replay returns its original
result, not a new verification; its original validity must still pass
`VerificationResult.ValidateAt` before reuse. Reconciliation carries only the
exact attempt, tenant, fingerprint and original safe coordinator scope. It
contains no raw key/digest and cannot verify/debit again. Known-key attempts
preserve the actual API-key actor. User keys retain their actual user target;
known organization keys have no user and use the attempt ID as their anonymous
namespace. Unknown-key denials retain their separate service-account actor and
cannot acquire a positive result. Current record state cannot
reinterpret that historical routing. Modern verification remains secret-only;
no caller-supplied key ID is required.

Management requests carry the transport's canonical client `Network` for the
existing protected-counter owner. It is not a trusted body/header value and is
never silently normalized from a different address form. Session authentication,
current self-policy/grant checks, protected admission, mutation, required audit
and lifecycle effects remain the native owners' responsibility in the sole
coordinator. Root request validation alone grants none of these authorities.

Positive authority evidence expires at most 20 seconds after the original read
begins. Read duration is bounded and clock/decision-race budgets total at most
10 seconds, preserving the shared issuer's 30-second revocation ceiling.
Missing, inactive, mismatched, unavailable or expired authority denies.

`IssuanceResult` distinguishes commitment from reveal delivery. Unknown outcomes
reveal nothing. Recovery is status-only and must not re-reveal or regenerate the
original key; lost delivery requires an explicitly authorized later rotation or
revocation/reissue. Retain `IssuanceResult.Recovery()` when a command may outlive
its request: even an unknown result preserves the exact original coordinator
binding without exposing a fresh record or secret. `Service.Recover` returns
only the original coordinator status, including for revocation. Every management
mutation belongs to the existing sole coordinator, with required audit/lifecycle
effects and original-key recovery.

Legacy configuration explicitly selects `AlgorithmLegacySHA256V1` and
`ConfigurationVerifyOnly`; it cannot issue keys. The zero algorithm retains the
modern profile and its exact historical configuration serialization and HMAC
digest. `ParseSecret` remains modern-only. `ParseLegacySecret` instead preserves
1..4096 historical bytes without normalization or an invented prefix, and offers
only the configured SHA-256 digest, never reveal. `AtomicVerificationRequest`
requires exactly the credential arm selected by the server configuration; the
wire value cannot select an algorithm or trigger profile scanning.

`LegacyImporter` is additive to the unchanged modern `Service` interface.
`ImportRequest` carries only a nonzero `LegacyDigest`, bounded source ID/version
and the exact typed metadata record, including stable canonical key ID, owner,
permission ceiling, absolute expiry, terminal status and replacement lineage.
The record may carry a user or organization owner in the human bearer's tenant.
Native import must authenticate the real human and authorize that exact owner
and source, including current membership and permissions for organization
management. The shape validator grants none of that authority. Native import
must validate canonical IDs, retain tombstones, and use the existing coordinator for
atomic effects and original status recovery. A digest constructor or request
validator alone establishes neither authentication nor a durable import.
Imports are not issuance, and cannot reveal or regenerate historical plaintext.
Legacy imports require explicit positive absolute expiry by default. A trusted
verify-only configuration may explicitly set `AllowLegacyNoExpiry` to preserve
an absent historical expiry as zero `Record.ExpiresAt`, never an invented
deadline. This option is rejected for modern configurations. Present expiries
retain their exact validation and enforcement; current owner, revocation and
original evidence freshness remain mandatory even for a key without expiry.
Legacy record eligibility does not apply modern issuance-age limits to original
times. The owning native adapter must implement this selected profile before
it is usable; these core contracts alone do not provide durable verification.

Administrator management, cache, API-key
session adapters and OAuth delegation remain separate profiles, not fallbacks.
Deprecated configurations still deny construction.
Reference/native expiry remains the selected 1-day..365-day profile; a shorter
positive core `MaximumLifetime` cap describes an explicitly stricter alternate
configuration, not a change to that Reference policy.
Core contracts/constructors alone do not establish the full durable journey.

## Explicit modern USER metadata projection

`PositiveProjectionConfig` is a distinct opt-in composition; it does not change
`Configuration.Cache`, existing serialized profiles or native verification.
Its `Store`, `Verifier` and `Authority` are real borrowed public source owners,
not cache-provided domain stores. `Begin` calls `AtomicVerifier` exactly once for
the original supplied attempt, then obtains current source epochs. An admitted
result must pass through `Complete` before use: `Begin`'s intermediate result
does not yet apply a later observed permission withdrawal or cache narrowing.
There is no public operation to seal a caller-invented successful result.

Only encrypted positive/known-quota metadata may be persisted. The opaque
admission and lookup contain no bearer or lookup digest. A restored projection
can only narrow the current native grant/deadline; the current attempt,
fingerprint, commit/debit outcome and quota remain native. Original projection
read-start/deadline survive copying and republishing without renewal. Missing or
corrupt ciphertext can use the already-obtained native result, never a second
verification; an obtained narrower/expired authority observation cannot be
ignored. Later denial retains known committed debit or unlimited history with
no principal and an error, never an invented `not-debited` outcome. Legacy and
organization projection profiles are not selected by this constructor.

`PermissionReductionUnknownError` adds original recovery custody without changing
existing result/decision/query layouts. Use its validated `Recovery` only with
the same fixed native Store. It unwraps `identity.UnknownCommitError`, not a
successful mutation. Keep the exact original decision for retry too: a query
cannot reconstruct missing pre-Apply history, prove noncommit or select a new
command. Recovery metadata is historical, never a fresh permission principal.
