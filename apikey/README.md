# API keys

`github.com/faustbrian/go-identity/apikey` defines the user-owned modern API-key
profile. It uses fixed `idk_` plus 32 CSPRNG bytes in unpadded base64url, with
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
remain distinct. The selected management requests have no user/owner override.
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
preserve the actual user target and API-key actor; unknown-key denials preserve
their separate anonymous-flow/service actor. Current record state cannot
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

Organization-owned and administrator management, legacy digest import, finite
quota, cache, API-key session adapters and OAuth delegation are retained goals,
not selected fallback profiles. Verify-only and deprecated configurations deny
construction until an explicit bounded migration policy is implemented.
Reference/native expiry remains the selected 1-day..365-day profile; a shorter
positive core `MaximumLifetime` cap describes an explicitly stricter alternate
configuration, not a change to that Reference policy.
Core contracts/constructors alone do not establish the full durable journey.
