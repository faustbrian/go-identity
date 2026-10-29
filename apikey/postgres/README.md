# Native PostgreSQL API keys

`github.com/faustbrian/go-identity/apikey/postgres` implements the selected
human-owned and explicitly selected organization-owned, unlimited-quota modern
and legacy API-key workflows. It uses the actual
identity coordinator, PostgreSQL authority, password bearer sessions,
authorization, risk counters, audit and transactional outbox owners. It does
not issue browser sessions or treat the creator as the API key's human actor.

## Composition and use

1. Apply the selected owners' migrations, including identity preparation,
   protected risk counters, audit and outbox. Apply this module's
   `MigrationSource` through the public migrations runner. Never edit an
   already applied migration or replace a native owner with application SQL.
2. Construct `ServiceConfig` with the real native session service and its exact
   storage/admission profile, bounded authorization policy, coordinator request
   and fingerprint keys, protected risk custody, pepper and envelope keyring.
   `NewService` validates composition without querying SQL or generating keys.
3. Explicitly call `InitializeConfiguration` for the tenant/configuration.
   Keep the PostgreSQL pool and all injected owners alive for the service;
   the service owns no pool, goroutine or shutdown obligation.
4. Call `Create` with a genuine current human bearer session, trusted network
   provenance and an idempotency key. Only a known committed invocation may
   reveal the raw key once. Copies and retries do not reveal it again.
5. Present that key through `VerifyAndConsume` with one stable attempt ID,
   tenant/configuration and sorted required permissions. Preserve its returned
   `Fingerprint` and `Original` even when the outcome is unknown. Use
   `ReconcileVerifyAndConsume` for secret-free original outcome inquiry.
6. Use `Rotate` or `Revoke` with fresh current self-authority and the exact
   expected key version. Rotation has zero overlap: it revokes the predecessor
   and issues an independent successor. A lost reveal requires an explicit
   later authorized rotation, never reconstruction of the original secret.

The executable consumer in `consumer_integration_test.go` composes the public
owners from fresh migrations, registers a real user, captures and confirms the
verification delivery, signs in through native bearer authentication, and
exercises issuance, verification, reduction, rotation, revocation and recovery.
It controls only external delivery/HIBP responses and explicit infrastructure
faults, not identity, sessions, credential comparison or transaction authority.
With a disposable loopback PostgreSQL cluster and task-owned Go caches:

```sh
GOWORK=off go test -mod=readonly -race -tags=integration \
  -run '^TestGenuinePasswordCreateCommitsBeforeOneTimeReveal$' -count=1 .
```

Set `GOLIB_APIKEY_TEST_POSTGRES_DSN` to that disposable cluster. The fixture
creates and removes its own database and native audit roles; do not point it
at an existing service or shared cluster.

## Security and recovery

Modern keys retain only HMAC-with-pepper digests; explicitly imported legacy
keys retain their historical SHA-256 digests. Prepared output never contains
recoverable key plaintext. Keep peppers, envelope keys and coordinator keys
private and retain versions needed by pending original commands. Do not log
request, result, key or session material.

Verification intersects the stored ceiling with current owner, tenant and
policy authority. Only Narrow reduction is supported; construction rejects
Revoke rather than emit the wrong terminal lifecycle. It persists a strict
reduction and its required update audit/lifecycle atomically even when the requested removed
permission denies authentication. Restoring policy never expands that ceiling.
Ordinary successful or denied attempts retain their distinct authentication
audit without inventing an update event.

The original authority read, immutable preparation and final protected fence
bound positive evidence to at most 20 seconds from the original read beginning,
less configured clock/decision budgets. Replay and reconciliation preserve all
original timestamps; expired committed history returns no usable principal.
Failed attempts restore the same original key version from the existing
coordinator's authenticated preparation even after an independent key change.
That read grants no authentication: complete incoming intent must still match
the sole original claim before any retained result can escape.
Keep the original attempt ID and fingerprint rather than retrying ambiguity
with a new command. Recovery is not fresh authentication.

Current API-key configuration and exact key locks serialize mutation and
verification; directory/user authority is fenced first. Required audit/outbox
failure rolls back the protected mutation. Missing or unavailable authority
never permits a fallback store or weaker authentication profile.

Create, import, rotate and revoke also require the original primary authentication
to remain within its 15-minute sensitive-operation window. A new session read
or refresh does not restart that window; protected work cannot cross its
original deadline. Status-only recovery does not perform a new mutation.

## Retained scope

Finite quota, cache projection,
API-key sessions, general CRUD/metadata, and HTTP/Reference composition are
remaining platform work, not selected fallback behavior. This experimental
module's native profile is not whole M21 or final release qualification.

## Explicit organization ownership

Apply the organization's unchanged base migrations and its optional
`CredentialAuthorityMigrationSource`, followed by this module's
`OrganizationMigrationSource` at a permanently allocated new migration version.
Keep the original key migration history: the extension preserves populated
user-key rows and checksums. It makes `user_id` nullable and enforces exactly
one user or organization owner, with a tenant-scoped organization foreign key.
The runner must bound DDL lock waits; removing the extension after organization
issuance is not a safe downgrade.

Select `NewOrganizationService(pool, config, organizationRepository)` using
the actual native organization repository. Ordinary `NewService` still denies
organization management and authentication, including original-attempt replay
and reconciliation. Keep both owners and their pool alive; no worker or
application domain store is introduced.

Call `CreateOrganization` with an `OrganizationCreateRequest`, a genuine fresh
human bearer and the exact organization ID. Policy receives the real human and
organization target; grants must be authorized independently. The resulting
record belongs to the organization and has no creator `UserID`. `Import`,
`Rotate` and `Revoke` select the record's actual owner. Digest-only organization
imports retain the same explicit legacy configuration and canonical-ID policy
described below. `RecoverOrganization` additionally takes the original target
organization; retain that target with the recovery query, including when an
unknown creation has no readable key row. Recovery is status-only, never reveal.

Management checks current membership and policy, then fences those observations
in the existing protected transaction. Verification uses the actual API-key
actor and owner-only organization authority, never the creator's user status.
Member removal denies that human's next management/recovery but preserves the
key. Organization archive/deletion advances a separate credential epoch;
restoring the organization cannot revive earlier keys. Current organization
policy and non-expanding permissions remain authoritative, with the original
20-second evidence ceiling preserved by retry and reconciliation.

Run the real populated-state consumer with the same disposable fixture setup:

```sh
GOWORK=off go test -mod=readonly -race -tags=integration \
  -run '^TestGenuineOrganizationKeySurvivesCreatorRemoval$' -count=1 .
```

This is the uncached, unlimited, Narrow native profile. Organization HTTP and
Reference wiring are separate integration work, not implied by this constructor.
## Explicit deployment configuration checks

`CheckConfiguration` reads the exact selected native configuration without
provisioning, resetting its lifecycle epoch or issuing authority. It rejects
absent, different and disabled configurations. This is a bounded trusted
deployment check, not authentication or a reusable validity proof.

`InitializeConfiguration` remains first-install provisioning and still conflicts
on an existing row. A reconstructing graph can observe that conflict, then call
`CheckConfiguration`; it must not treat conflict alone as compatible startup or
overwrite disabled authority. Runtime operations independently read/fence their
current configuration and never inherit a startup authorization cache.

## Explicit digest-only legacy profile

Keep `Configuration` as the current modern HMAC issuance profile. Opt in to one
distinct `LegacyConfiguration` selecting `AlgorithmLegacySHA256V1`,
`ConfigurationVerifyOnly`, unlimited quota, no cache and Narrow permission
reduction. Both profiles must share issuer, environment and audience. Supply a
bounded, concurrency-safe `ValidateCanonicalKeyID` policy that accepts existing
canonical IDs unchanged, including supplied replacement lineage; it is required
only when selecting legacy support and never supplies missing owner authority.

Apply `LegacyMigrationSource` with the unchanged original `MigrationSource` as
its `Base` and a permanently allocated later version. This additive migration
retains old records and migration checksums. It refuses ambiguous existing
tenant/key IDs rather than selecting a profile or rewriting data. Zero in the
internal pepper-version column denotes the explicitly selected legacy
algorithm, not a usable modern pepper or a token-selected fallback. Explicitly
provision with `InitializeLegacyConfiguration`; use `CheckLegacyConfiguration`
to observe exact existing authority without resetting or enabling it.

`Import` takes a digest-only `ImportRequest`: the exact typed metadata record,
source ID/version and `LegacyDigest`, never plaintext. It authenticates a real
fresh self-owner session and separately authorizes the source and each grant.
Record version and source version remain distinct; snapshot import records a
truthful absent-local `0 -> imported record version`, including full-width
terminal metadata. It does not generate a key, emit a created-key event or
reveal material. Imported original creation/expiry times, status, ownership,
restrictions and predecessor remain unchanged. Legacy profiles require explicit
absolute expiry by default. Set `AllowLegacyNoExpiry` only in the selected
verify-only legacy configuration to retain absent expiry as zero `ExpiresAt`.
This does not invent a deadline, enable unbounded modern issuance or relax the
original 20-second authority ceiling. Historical lifetime is not constrained by
modern issuance-age limits. Existing finite configuration bytes remain unchanged;
select a new immutable configuration rather than changing an installed profile.

Identical original client-key retries recover that exact command, including a
failed original after a later explicit import of the same source. For an unused
client key, an already committed identical source is a status-only read of its
original command; that read creates no new mapping, command, counter or effect.
Different-key contenders may conflict. Older source versions have a typed stale
outcome. Changed snapshots, including newer tombstones, explicitly conflict:
they are unsupported source updates, never silently reported as applied or
upserted. A revoked or rotated key cannot be resurrected by reimport. Required
audit/outbox failure rolls back key/source/effects together; lost commit
acknowledgements retain the original unknown outcome for status recovery.

For verification, supply `LegacySecret` and the exact server-selected legacy
configuration to `VerifyAndConsume`. Bare bytes are SHA-256 hashed unchanged,
then looked up through the bounded exact tenant/configuration/digest index.
No prefix is invented, no configuration is inferred from token text, and no
profile scan or fallback occurs. Current owner/tenant/policy, original grant,
present absolute expiry and terminal status remain authoritative. Original attempt
replay/reconciliation preserves source timestamps and cannot refresh authority.

`Rotate` always creates a modern successor and terminates the legacy root in
the same protected transaction. Its expiry is the earlier of a present legacy
absolute expiry and the rotation instant plus current modern maximum lifetime,
conservatively floored to database precision; it never extends authority.
Ordinary modern-to-modern rotation still preserves its exact original expiry.
Both configuration fences and the exact predecessor are locked in a fixed
order. Imported source metadata/tombstones remain retained; owner restoration
cannot restore a revoked root or narrowed permission.

The real populated-state consumer is `TestGenuineLegacyDigestImportVerificationAndModernRotation`.
Run it with the same disposable loopback fixture and task-owned caches:

```sh
GOWORK=off go test -mod=readonly -race -tags=integration \
  -run '^TestGenuineLegacyDigestImportVerificationAndModernRotation$' -count=1 .
```

That command selects the finite user-owned import/verification/rotation journey.
`TestGenuineLegacyNoExpiryImportVerificationAndModernRotation` additionally proves
the selected absent-expiry variant, required-effect rollback and original unknown
recovery. `TestGenuineOrganizationNoExpiryKeySurvivesCreatorRemoval` exercises
the same metadata through current organization authority without a creator-user
dependency. Quota, cache and broader management remain separate profiles.
