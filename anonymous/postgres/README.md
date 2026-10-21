# PostgreSQL anonymous lifecycle

Experimental primary storage and same-Work lifecycle effects. Public anonymous
signin/recovery and self-deletion are implemented with authenticated public
dependencies. Upgrade and HTTP/reference composition are still in development;
this is not a delivered complete M09. No local replacement is required.

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
update. Permanent-account upgrade is not yet implemented by this profile.

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
