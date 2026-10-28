# Native PostgreSQL API keys

`github.com/faustbrian/go-identity/apikey/postgres` implements the selected
modern, human-owned, unlimited-quota API-key workflow. It uses the actual
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

Only HMAC-with-pepper digests are durable; prepared output never contains
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

Create, rotate and revoke also require the original primary authentication
to remain within its 15-minute sensitive-operation window. A new session read
or refresh does not restart that window; protected work cannot cross its
original deadline. Status-only recovery does not perform a new mutation.

## Retained scope

Organization ownership, legacy digest import, finite quota, cache projection,
API-key sessions, general CRUD/metadata, and HTTP/Reference composition are
remaining platform work, not selected fallback behavior. This experimental
module's native profile is not whole M21 or final release qualification.
