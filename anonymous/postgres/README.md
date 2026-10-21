# PostgreSQL anonymous lifecycle

Primary storage and same-Work lifecycle effects for public anonymous signin,
recovery, self-deletion and the selected permanent-target password upgrade.
The native services compose authenticated public dependencies; the upgrade
profile and its limitations are documented below. HTTP/reference composition
and broader anonymous lifecycle profiles remain unfinished, so this is not
a delivered complete M09.

The adapter owns anonymous metadata, original expiry and lifecycle versions.
Kernel identities/placeholders remain kernel-owned; session records remain
session-owned. No independent transaction, command journal, identity store or
bearer storage is introduced. Constructors borrow an already migrated primary
pool and perform no IO; callers close it after operations finish.

Install the kernel anonymous-placeholder history, this module's forward schema
and the selected session issuance suffix through the existing migration runner.
Stage creation only in the exact closed anonymous participant's original Work,
then repeat current lifecycle checks in its final commit phase. Structural reads
and recovery correlation do not authenticate a browser, renew original expiry
or grant permission to erase legally retained data.

`NewSessionService` composes those real primary owners and the existing
anonymous-only session validator. Configure the lifecycle schema, session schema,
directory/policy/audience profile and bounded session validation explicitly.
`Get` returns `session.AnonymousGetResult`, not verified-user authentication.
Every read checks current lifecycle/status, all kernel and policy epochs and
session/family state. Its original evidence expires within 20 seconds of the
first lookup and never outlives anonymous expiry; copies and later owner reads
cannot renew it. This factory performs no issuance, cache fallback or activity
update. This reader does not perform permanent-account upgrade; that operation
requires the explicit native composition below.

See [anonymous policy](../README.md), [changelog](CHANGELOG.md) and
[security](../../SECURITY.md).

## Public anonymous signin

`NewSigninService` composes the actual kernel, anonymous lifecycle, session,
durable risk and audit/outbox owners. It accepts an already issued primary
pre-auth transaction/cookie through `anonymous.SigninRequest`; caller and
network/device/origin metadata require trusted ingress. Supply an admitted
system display-name attribute, explicit unprivileged namespace/audience, stable
configuration identity and independently purposed keys. No caller-selected user
or application domain store is accepted.

Install kernel request-key preparation and admission-preparation history,
directory and anonymous-placeholder history, authorization authority, this
module's schema, session issuance/anonymous/pre-auth/pre-auth-issuance **and
CSRF** histories plus the actual audit/outbox histories. Installing only the
base session schema correctly rejects genuine CSRF-bearing issuance.

`Signin` atomically consumes the original flow and creates the kernel identity,
reserved placeholder, anonymous lifecycle and session. Only an acknowledged new
commit reveals bearer/CSRF once. Persist its credential-free `Recovery` scope
before attempting recovery. Same-key retry and fresh-service `RecoverSignin`
return historical outcomes without generating or disclosing another token.
Changed intent conflicts; recovery still requires original-cookie possession
and current disclosure policy. Unknown is not rollback. The resulting guest is
read only through the anonymous session service, not verified-user admission.

## Authenticated anonymous self-deletion

`NewDeletionService` composes the real anonymous reader and concrete kernel,
session, risk, authorization, audit and outbox owners. Supply a bounded pure
`identity.PolicyEvaluator` retention decision, registered reasons/origins,
retained session lookup/CSRF keys, explicit protected-counter configuration and
configuration identity. The runtime input cannot select a target or cleanup
policy; cleanup is the original subject's stored policy. No permanent password
or application-supplied domain store is needed.

Append kernel `AnonymousDisposalMigrationSource` after anonymous creation and
legal-hold/status histories, session `AnonymousDisposalMigrationSource` after
its installed anonymous issuance history, and this module's
`DisposalMigrationSource` after subjects. Install the existing native risk
protected-counter history in its selected schema. Keep every installed
predecessor byte/version unchanged and allocate suffix versions permanently.

The selected retention profile accepts explicit Allow only. Legal holds,
deferred retention, policy failure and changed hold generation deny before
erasure; no callback executes while SQL locks are held. Delete and anonymize
remove kernel attributes/profile and terminalize the user distinctly; retain
preserves payload but still permanently withdraws authentication. Minimal opaque
identity/lifecycle/command tombstones remain for non-resurrection, legal audit
and ambiguous-outcome recovery. This is not a claim of physical row erasure or
full-platform privacy cleanup. Extra contacts or credentials deny self-disposal.

`Delete` commits kernel state, anonymous lifecycle, every anonymous session and
family, and required audit/outbox in one Work. Protected attempt counters retain
their existing reservation/replay semantics: a later disposal rollback does not
refund the attempt or charge replay again. Original expiry and the earliest
<=20-second admission deadline are rechecked without renewal. Required late-owner
failure rolls back disposal and its audit/outbox. An ambiguous commit returns
Unknown; save its full query and call `RecoverDeletion` with the original
credential/CSRF and exact ingress. Recovery authenticates original encrypted
input even after self-revocation, reconciles the existing owners and returns
metadata only. It never issues credentials or authorizes live access. Calls
remain bounded and no background jobs, private ledger or cache are introduced.

## Permanent-target upgrade

`NewUpgradeService` composes the existing owners through `UpgradeConfig`:
`Guest` supplies actual anonymous/session/kernel/risk/retention configuration;
`Primary` is the password adapter's action-primary source for
`identity.anonymous.upgrade` and `ProofAudience`; `Target` selects the real
permanent password-session profile. Supply both retained CSRF key sets, the
session issuer and the actual capability issuer/preparation configuration.
Guest and permanent namespaces may differ, but tenant/global/audience/storage
ownership must agree. The constructor performs no migration or network work.

Install the selected kernel `AnonymousUpgradeDisposalMigrationSource`, password
`AnonymousUpgradeReauthenticationMigrationSource`, the existing MFA factor-
authority history, session `AnonymousUpgradeMigrationSource` and this module's
`UpgradeMigrationSource`,
plus the actual capability issuance/one-use and protected-risk-counter histories.
Append these to their documented predecessors without rewriting installed steps.

Call password verification for the selected upgrade action, then submit that
fresh target proof, both original cookie credentials and CSRF synchronizers, the
actual anonymous subject in a typed `anonymous.MergePlan`, matching remember
policy, trusted ingress and one idempotency key to `Upgrade`. This finite profile
preserves an existing permanent target, including canonical ULIDs and historical
authentication. It transfers no application resources. Only no-conflict or
`profile.display_name`/`KeepTarget` plans are supported; resource-transfer,
other conflict decisions and enrolled/unknown MFA fail closed.

The first durable command issues the real one-use capability. The second consumes
that original grant and target proof atomically with anonymous disposal, all
guest-session/family revocations, the new permanent session and required
audit/outbox effects. Original evidence expires within 20 seconds of the first
authoritative read, or the earlier proof/guest deadline; waits and retries never
renew it. Acknowledged new completion alone reveals the new cookie/CSRF once.

Persist both credential-free queries in `UpgradeResult`. Unknown is not rollback:
`RecoverUpgrade` requires those exact queries, both original credentials/CSRF
and original ingress. It reconciles the original commands without reexecution,
new grants, fresh authentication or credential redelivery. Successful same-key
replay is likewise metadata-only, including after the original grant expires.
Retain original lookup/CSRF, request/envelope and capability verification keys for
their respective recovery lifetimes. Keep `Guest.IntentKey` stable for retained
requests; independent transport-key rotation does not change original intent.
