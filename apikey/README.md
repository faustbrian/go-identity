# API keys

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

The selected profile explicitly disables caches and selects unlimited quota.
It still records one exact verification attempt/fingerprint. Known unlimited
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

Organization-owned and administrator management, finite quota, cache, API-key
session adapters and OAuth delegation remain separate profiles, not fallbacks.
Deprecated configurations still deny construction.
Reference/native expiry remains the selected 1-day..365-day profile; a shorter
positive core `MaximumLifetime` cap describes an explicitly stricter alternate
configuration, not a change to that Reference policy.
Core contracts/constructors alone do not establish the full durable journey.
