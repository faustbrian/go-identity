# Organization composition

This selected backend profile connects real registration, verification and
password signin to organization creation, metadata/role updates, scoped reads, member admission and
removal, encrypted invitation delivery/resend, cancellation/rejection/expiry and once-only acceptance.
Optional local archive/restore, teams and custom roles are described below.
This is not an administrative UI or full organization/external lifecycle,
domain ownership or another login profile.

## Custom roles and effective permissions

Select a bounded immutable `Organization.Core.DynamicRoles` catalog explicitly:

```go
organization.DynamicRoleConfig{
    Version: 1, MaximumRoles: 10,
    Catalog: []organization.Permission{
        {ID: "document-read", Action: "document.read", ResourceType: "document"},
    },
}
```

Zero disables this profile. Native services copy the catalog; changing its
semantics requires the deployment policy/configuration epoch, not a mutable
permission registry. Wildcards, conditions and custom organization-management
permissions are not supported. Static owner/admin roles grant management, not
implicit application access. `OrganizationService` exposes guarded
`CreateDynamicRole`, `GetDynamicRole`, `ListDynamicRoles`, `UpdateDynamicRole`,
`DeleteDynamicRole` and `CheckPermission`. Reads/checks require a nonempty
`CorrelationID`; checks apply to the authenticated member at an exact current
organization epoch. A snapshot or allow is never a reusable authority lease.

Apply the operator plan with `organization/postgres` before enabling writers.
It appends separate `identity_organization_roles` history: unchanged native
`DynamicRoleMigrationSource` at1 and nullable original-delete correlation at2.
The latter's transactional index requires a bounded maintenance window and
operator lock/transaction budgets. No existing organization/team/invitation
history is rewritten, and legacy effects are not backfilled. Retain native
storage selection when disabling HTTP so original history stays owned.

For team inheritance, additionally select `DynamicRoles.TeamBindingsVersion: 1`
and `Teams.LifecycleVersion: 1` with complete bounded team configuration. The
unchanged native team-role migration appends role history3 after terminal team
identities. Direct and team assignments remain existing native organization
APIs, not HTTP endpoints in this selected CRUD profile. Revoking membership or
deleting a role/team invalidates derived permission; retained bindings never
revive terminal identities. Explicit deny overrides allow.

Independently opt into `HTTPOrganization.RoleCreate`, `RoleGet`, `RoleList`,
`RoleUpdate` and `RoleDelete`. Strict tenant-mapped bearer HTTPS is required.
Create/update share administrative rates and require an unchanged
`Idempotency-Key`; natural delete forbids keys. Their closed JSON includes
`organizationID`, `roleID`, positive advanceable `organizationVersion`, plus
`roleVersion` for update/delete. Create/update also require `name` (1..256 UTF-8
bytes) and ordered `statements`, each exactly `permissionID`, `resourceID` and
`effect` (`allow`/`deny`). Empty arrays grant nothing; limits are64 statements
and8192 native encoded bytes. Configure transport field/byte bounds for the
desired bounded profile. Native catalog membership remains mandatory.

Routes are `/v1/organization/role/create`, `/update`, `/delete`, `/get` and
`/list`, with the same prefix. Get accepts exactly `organizationID`/`roleID`;
list accepts `organizationID`, canonical decimal `limit`1..100 and optional
exclusive nonempty ID `cursor`. Reads share safe rates, require current manager
authority and withhold an entire failed result. Disabled flags expose neither
routes nor metadata. Caller actor/tenant/command envelopes and historical
generic `StatementIDs` are not request fields: this composes published native
root`895ac99`/adapter`6bcfd9e` typed statements, not a second policy store.

Retain original keys, selectors and safe receipt/recovery metadata. Matching
retries recover actual original outcomes under current write/query authority;
missing rows do not prove success, and unknown outcomes never permit automatic
redispatch. Role deletion terminally retires its ID. Fresh-session and rebuilt
graph recovery retains the original receipt; actual logout denies history.

`TestReferencePostgresOrganizationRolesHTTPS` and its `PopulatedUpgradeHTTPS`
counterpart exercise real signup/session -> role HTTP CRUD -> direct permission,
revocation and team-only permission -> deny precedence -> terminal deletion ->
reconstructed originals/logout. The populated case starts with real native
teams, an active binding and original receipts before selecting roles. Required
outbox failure proves rollback; no grants, sessions or domain stores are faked.

## Team membership

Set `Organization.Core.Teams` explicitly, for example:

```go
organization.TeamConfig{Version: 1, MaximumTeams: 100, MaximumMembers: 1000}
```

Zero disables teams; quotas have no defaults. Leave `LifecycleVersion` zero
for membership-only composition, or select version1 as described below.
Apply the operator migration plan before enabling
team writers. It adds independent `identity_organization_teams` history: native
`TeamMigrationSource` at version1 followed by
`TeamMemberOperationLookupMigrationSource` at version2. Previous organization,
invitation, local lifecycle and self-leave histories are unchanged. The native
transactional lookup index blocks writes: use a bounded maintenance window and
operator lock/transaction timeouts. Existing effects retain NULL correlation;
there is no backfill or second outcome journal. Retain this storage selection
when disabling HTTP so installed histories and original recovery remain owned.

The guarded `OrganizationService` exposes original-key `CreateTeam` (empty
team), `AddTeamMember`, naturally repeated `RemoveTeamMember`, `ListMyTeams`
and `ListTeamMembers`. Supply canonical caller-selected team IDs to native
creation. Teams grant no organization roles or standalone permissions. Native
current manager/action/query/session authority and atomic effects remain the
only owners; configured-tenant, initialization and shutdown guards also apply.

HTTP is separately selected through `HTTPOrganization.TeamMemberAdd`,
`TeamMemberRemove`, `TeamListMine` and `TeamMemberList`. All use strict bearer
sessions over tenant-mapped HTTPS. Writes share existing administrative budgets;
reads share safe budgets. These four flags do not enable team creation,
rename/deletion, dynamic-role or active-team routes.

- `POST /v1/organization/team/member-add` requires one original
  `Idempotency-Key`; `/v1/organization/team/member-remove` forbids it.
  Both require exactly `organizationID`, `teamID`, `userID`,
  `organizationVersion`, `teamVersion`, `organizationMemberVersion` and
  `membershipVersion`. First admission uses zero binding version; subsequent
  admission uses the retained tombstone version. Removal requires its current
  positive binding version. Native APIs validate these observations against
  current authority; caller versions are not grants.
- `GET /v1/organization/team/list-mine?organizationID=...&limit=20` selects
  only the current human's live teams. `/v1/organization/team/member-list`
  additionally requires `teamID`; native team authorization filters current
  bindings. Both require canonical decimal limit1..100 and accept an optional
  exclusive ID `cursor`. No caller actor/tenant, body or key is accepted.
  Safe response arrays and observed epochs grant no authority; errors withhold
  the entire page, not a partial result.

Matching retries return actual original receipts, not another mutation.
Natural removal cannot infer success from absence. Receipt before/after epochs
are organization policy epochs, not team/binding versions. Retain unknown
outcomes and safe original recovery binding; never automatically redispatch.
Organization departure/readmission cannot revive old team bindings, and an old
removal cannot affect a newer admission. New admission must explicitly name the
new organization membership and retained team-binding versions. Logout denies
history even when the original receipt exists. Disabled flags expose neither
routes nor OpenAPI metadata.

## Team creation and terminal lifecycle

`HTTPOrganization.TeamCreate` and `TeamList` independently select empty-team
creation and manager-only listing with any valid native team policy. Select
`Organization.Core.Teams.LifecycleVersion = 1` before enabling `TeamUpdate`
or `TeamDelete`. Native selection never enables HTTP automatically. Apply the
operator check/plan/apply workflow before activation: the existing independent
team history appends `TeamLifecycleMigrationSource` at version3 and
`TeamDeleteOperationLookupMigrationSource` at version4. Steps1/2 and all other
histories retain their installed identity and bytes. Native step3 preserves
live IDs and bindings; step4 leaves legacy command correlation NULL. The
transactional lookup index requires bounded write-blocking maintenance and
operator lock/transaction timeouts. Keep the native policy when disabling HTTP
so migration and original-recovery ownership remain available.

After genuine registration, verification and password signin, use the issued
bearer session and a current organization to perform this journey:

1. `POST /v1/organization/team/create` accepts exactly `organizationID`,
   `teamID`, `organizationVersion` and `name`, plus one `Idempotency-Key`.
   Supply a canonical team ID; success creates an empty team at version1.
2. `GET /v1/organization/team/list?organizationID=...&limit=20` is manager-only,
   uses safe rates, requires canonical limit1..100 and accepts an exclusive
   optional ID `cursor`. Membership admits no permission to list every team.
3. `POST /v1/organization/team/update` accepts the create fields plus exact
   `teamVersion` and one original key. Read current versions after any member
   change; rename advances organization/team epochs without changing bindings.
4. `POST /v1/organization/team/delete` accepts exactly `organizationID`,
   `teamID`, `organizationVersion` and `teamVersion`, with no key. Deletion is
   terminal, removes the live team and denies old binding reads. A new key
   cannot revive the retired ID.

All writes share the existing administrative budget. Current native manager,
action, session and outcome-query authority remain required. Mutations return
organization before/after epochs and original recovery metadata, not a member
projection or an independent authority grant. Repeat exact keys/input or the
same natural deletion to recover original history; retain Unknown outcomes
without automatic reexecution. Logout denies both direct and HTTP recovery.

The guarded handle additionally exposes `UpdateTeam`, `DeleteTeam`, `ListTeams`
and exact manager-only `GetTeam`. There is deliberately no new GetTeam HTTP
route. The fresh and populated-upgrade `TestReferencePostgresOrganizationTeamCRUD*`
journeys exercise actual signup sessions, HTTP mutations/reads, preserved
bindings and original receipts, reconstruction and logout. The populated case
starts with actual membership-only teams and active bindings before steps3/4.

## Local archive and restore

Select `Organization.Lifecycle` with distinct native password `Archive` and
`Restore` action-primary configurations. Both use bearer transport, the same
explicit issuance audience, bounded maximum age and no cookie CSRF keys. Add
both exact actions to the real `PasswordVerification.Native.Targets`; leave
`Organization.Core.Lifecycle` zero for graph injection. Missing or mismatched
proof owners reject construction. The current profile requires genuinely
known-empty MFA state; it never silently falls back from enrolled factors.

Native handles expose `Archive`, `Restore` and owner-only `GetLifecycle` for
current archived-version discovery. Independently select `HTTPOrganization`
`Archive` and/or `Restore` to enable strict-bearer HTTPS POSTs under
`/v1/organization/archive` and `/v1/organization/restore`. Each requires the
original `Idempotency-Key`, exact `organizationID`, `organizationVersion`,
1..64 visible-ASCII `reason` and retained `proofID`. Current owner/action/session
authority and one-use proof consumption remain native. Matching-key recovery
does not issue or renew a proof and may use a fresh current session. Ordinary
reads deny archived organizations; no post-transition active read is used to
declare a command successful.

Archive atomically denies local organization authority and cancels pending
invitations. Restore admits surviving local rights but does not revive terminal
invitations, removed memberships or revoked grants. Receipts prove local command
outcome, not asynchronous external cascade completion, external application
write disablement or hard deletion. External SSO/SCIM/integration links remain
unselected; those broader lifecycle obligations are not completed by this profile.

The graph installs native lifecycle migration13 after the unchanged complete
organization/invitation prefix1..12. If invitation workflows are off, their
physical prefix is still installed before lifecycle so later selection cannot
overwrite its cancellation constraint; no invitation route/owner is enabled by
storage. Install before enabling lifecycle writers in a bounded maintenance
window: native table/constraint changes may block writes and reject unsafe
existing state. Action consumption reuses the physical action21 prefix and
native lifecycle28 only when a newer selected anonymous/passkey suffix does not
already retain both purposes. Newer installed storage selections must remain in
the graph even with their HTTP handlers off; older consumption SQL is never
scheduled over those histories. No previous migration bytes are rewritten.

## Explicit configuration

Start with the existing concrete password/session/delivery configuration in
[the baseline walkthrough](BASELINE.md). Add `StoreConfiguration.Organization`:

- `Core`: stable native policy ID/version, canonical-ID validator, bounded
  duration and membership limits. Leave its clock nil for graph injection.
- `Repository` and `Counters`: native PostgreSQL configuration using the same
  graph risk schema/policy, protected command counters and enforced lockouts.
- `Custody`: native operation-custody encryption keys, retaining old versions
  while original commands remain recoverable.
- `ConfigurationID` and `SelectOrganizationID`: stable configuration identity
  and a bounded concurrent-safe ID callback. Change the configuration ID after
  a material policy change rather than silently reinterpreting original intent.

The graph supplies actual native repositories, session/current-authority reader,
authorization, risk, transaction coordinator, audit and outbox contributors.
Applications supply policy and configuration, not missing stores or workflows.
This selection requires the verified-password session profile; unsupported MFA
or other primary profiles fail closed instead of falling back to password.

Optionally add `Organization.Invitations`: native invitation policy, capability
issuer/preparation configuration with nil clocks, original-key configuration ID
and bounded invitation-ID callback. Select retained delivery policy/provider,
template version, locale chain, approved HTTPS endpoint and scope key. Retain
capability, encryption, request-key and delivery versions needed by originals.
Compose a delivery worker for the selected invitation provider for every tenant;
missing workers prevent feature composition. Templates and senders remain the
existing explicit bounded external seams.

Native selection enables no HTTP. Independently opt into `HTTPOrganization`
`Create`, `Update`, `Get`, `MemberList`, `MemberAdd`, `MemberUpdate`, `MemberRemove`, `InvitationGet`,
`InvitationListMine`, `InvitationList`, `InvitationSend`, `InvitationResend`, `InvitationCancel`,
`InvitationReject`, `InvitationExpire`, `SlugAvailable`, `List`, `MemberLeave`, `OwnerTransfer` and `InvitationAccept`.
Each requires its
actual native owner and the shared strong HTTP rate backend. Configure stable
safe/admin/secret namespaces and keys. The degradation and administrative-denial
callbacks retain the transport's bounded synchronous contracts: administrative
denials must be durably audited, without secrets. Namespace/key changes affect
rate budgets and require coordinated rollout, not per-request rotation.

## Invitation expiry

Configure nonempty registered `Organization.Invitations.Policy.ExpirationReasons`
before selecting `HTTPOrganization.InvitationExpire`. It needs the existing
native invitation owner and shared administrative rate configuration, not a new
application store, recipient proof or organization reader. Native selection
alone exposes no HTTP. `OrganizationInvitations().Expire` is the guarded direct
native API with the same exact original intent and graph lifetime/tenant guards.

Strict-bearer HTTPS `POST /v1/organization/invitation/expire` accepts only
`organizationID`, `organizationVersion`, `invitationID`, `invitationVersion` and
`reason`. Expected versions are positive advanceable integers; the non-secret
reason code must be1..64 bytes and registered by the native policy. Client keys,
caller commands, proofs and actor/tenant overrides are rejected. Current managers
expire without recipient credentials or organization-read permission. Proof
invalidation and required audit/lifecycle effects commit in the same transaction.

Reference `Check/Plan/Apply` appends the owned
`InvitationExpireOperationMigrationSource` at version12 in `identity_organization`.
Versions1..11 retain their bytes. The additive nullable original-epoch/reason
columns never backfill legacy history. Its transactional partial unique index
blocks writes: use a bounded maintenance window and lock/transaction timeouts,
then enable the endpoint. Raw native explicit expiry remains compatible without
the optional correlation migration; this guarded natural-repeat API requires it.

Matching repeats recover only an actual original receipt under current manager
and session authority, including after graph reconstruction or fresh signin.
Changed reason/epoch conflicts; a terminal row alone never proves an original.
Successful replies expose safe correlation and `state: "expired"`, without
membership, recipient address or delivery projections. Errors/unknown replies
have no successful terminal state. A late error retains known commitment, and
unknown never authorizes automatic redispatch. Logout denies original history;
disabled HTTP selection exposes neither route nor OpenAPI metadata.

## Ownership transfer

Select `Organization.OwnerTransfer` with an
`OrganizationOwnerTransferConfiguration`. Its `Primary` uses the existing
password adapter's `ActionPrimaryConfig`: exact action
`identity.organization.owner-transfer`, a target audience already allowed by
`PasswordVerification.Native.Targets`, a bounded `MaximumAge` and
`session.CredentialBearer` without CSRF keys. Leave
`Organization.Core.OwnerTransferAudience` empty; the graph injects that same
primary audience. The existing verified single-factor password profile is
required. There is no password fallback from an MFA or other primary profile.

Native selection exposes guarded `Organizations().OwnerTransfer`, not HTTP.
Independently select `HTTPOrganization.OwnerTransfer` for strict-bearer HTTPS
`POST /v1/organization/owner-transfer`; this requires shared administrative
rate admission and the selected real password-proof owner. Obtain `proofID`
through the selected password-verification workflow for the exact action and
audience. The bearer HTTP verification profile also needs its genuine signed
browser-device correlation cookie from pre-auth issuance; that cookie is not
session authentication. Transfer itself accepts only the bearer, required
`Idempotency-Key` and JSON `organizationID`, `targetUserID`,
`organizationVersion`, `sourceVersion`, `targetVersion`, `proofID`.

Apply Reference `Check/Plan/Apply` before enabling transfer. Selection reuses
the existing native action-proof consumption history in
`identity_username_actions` at version21 even when username is not selected;
installed history is neither copied nor rewritten. No new organization table,
request journal or application contributor is required. Native authority owns
proof signature/freshness/once-only consumption, both membership transitions,
scoped authority, audit and outbox in the existing transaction.

Keep the original key, versions and proof ID for matching historical retries.
They recover the original outcome under current authority, including a fresh
session after transfer, rather than consuming a new proof or granting another
mutation. Changed intent conflicts. Safe original recovery metadata survives
known-commit late failures; unknown outcomes never authorize automatic replay.
Logout or withdrawn disclosure authority denies history. Unsupported profiles
and disabled HTTP selection fail closed without advertised routes.

## Owner-only invitation listing

Select native `Organization.Invitations`, then independently opt into
`HTTPOrganization.InvitationList` with the shared safe-rate configuration.
No administrator/secret limiter is needed for list-only HTTP selection.
`GET /v1/organization/invitation/list?organizationID=ID&limit=20` requires one
strict bearer session at the mapped HTTPS tenant. The only query fields are
organization ID, required canonical decimal limit1..100 and optional exclusive
invitation-ID cursor1..128 bytes. This cursor differs from `ListMine`'s opaque
recipient cursor. Pages use current bytewise invitation-ID order, not snapshots;
restart to see earlier additions. Return `nextCursor` unchanged with the same
organization. Empty pages contain `invitations: []`.

Native current owner/session and configured action policy must allow
`identity.organization.invitation.list`; knowing an invitation, being its
recipient or possessing an old cursor grants no access. Role withdrawal and
logout deny later reads. Responses contain only safe invitation ID,
organization ID, role, status, version and expiry, never addresses, proofs,
delivery custody or internal authority. Any failed or malformed page is withheld
in full. Disabled selection exposes neither route nor metadata.

`FeatureSet.OrganizationInvitations()` also provides direct `List` using
`organization.InvitationReadRequest`, with the native exact bounds and current
owner policy. Retained handles preserve initialization, tenant, cancellation,
drain and closed-graph guards. Existing invitation migrations suffice; this
selection adds no schema or alternate store.

## Self-leave and original-outcome recovery

Independently select `HTTPOrganization.MemberLeave` with the shared safe-rate
namespace/degradation configuration; no invitation, administrator-rate or secret
owner is required. `POST /v1/organization/member/leave` accepts exactly
`organizationID` and its positive advanceable `organizationVersion` under the
current strict bearer/HTTPS tenant. There is no key, target, command, member
version or proof override. Native policy authorizes `identity.organization.member.leave`
for the actual human and organization; last-owner denial remains distinct.

The existing native transaction removes only self and advances scoped authority
with protected risk/audit/outbox effects. Natural matching repeats disclose an
actual original receipt even after departure; missing membership alone cannot
prove success. Save the safe returned recovery binding for direct
`OrganizationService.RecoverOperation` through `FeatureSet.Organizations()`.
Current verified self/session and explicit disclosure policy still apply. A
manager cannot recover another human's self-history. Unknown outcomes require
reconciliation of that original binding, never automatic replay.

Readmission never makes old leave intent actionable: natural old requests
conflict, while explicit original metadata recovery remains history-only.
`OrganizationService.LeaveMember` and recovery retain configured-tenant,
initialization and drain guards. No HTTP recovery route or post-leave membership
read is added; disabled HTTP selection exposes neither route nor metadata.

Before using native self-leave, apply the independent
`identity_organization_leave` migration history in the normal operator flow.
It selects `LeaveOperationLookupTransactionalMigrationSource` for the bounded
exact-epoch partial index without inserting steps into the existing organization/
invitation prefix. This transactional build blocks command-effect writes:
use a bounded maintenance window/lock budget. The native concurrent alternative
remains available to other compositions with explicit invalid-build recovery.

## Current-user organization listing

Independently select `HTTPOrganization.List` with `SafeNamespace`,
`EmergencyMaximumKeys` and the bounded `Degraded` callback. No invitation,
administrator-rate or secret-rate owner is required. Authorize
`identity.organization.list` for the current human and each `organization`
resource; explicit policy denials filter candidates. Native current primary
membership and organization-scoped authority remain mandatory.

Call `GET /v1/organization/list?limit=20` with the strict bearer credential at
the configured HTTPS tenant host. `limit` is required canonical decimal1..200,
with no default. A successful response contains `organizations`, including an
empty array at an empty observed end, with ID/name/slug/version views only.
If present, send the exact `nextCursor` unchanged as the optional `cursor` on
the next request. No user, tenant, organization override, request key or body
is accepted. Disabling `List` exposes neither route nor metadata.

The opaque cursor (at most512 bytes) binds tenant, authenticated subject and
deployed policy, not a snapshot or authority grant. Results use bytewise ID
order; earlier additions require restarting. Every call checks current session,
membership and policy; removal/logout/outage never falls back to old positive
authority or a partial page. The direct `OrganizationService.ListOrganizations`
method, obtained from `FeatureSet.Organizations()`, retains graph initialization,
tenant and active-call drain guards. No new migration or application reader
is required. The existing maximum-per-user cap bounds native scan work.

## Advisory slug availability

Independently select `HTTPOrganization.SlugAvailable`, with `SafeNamespace`,
`EmergencyMaximumKeys` and the bounded `Degraded` callback. It needs neither
invitations nor administrative-rate selection. Configure explicit
`identity.organization.slug-available` authorization for the authenticated human
and `organization.slug` candidate resource; membership is not a prerequisite.
The ordinary native organization/session/policy graph remains the sole owner.

Call `GET /v1/organization/slug-available?slug=candidate` with exactly one native
bearer credential at the configured HTTPS tenant host. A successful response is
only `{"available":true}` or `{"available":false}`. No body, key, tenant/user or
organization override is accepted. The same read is available directly through
`OrganizationService.SlugAvailable`, obtained from `FeatureSet.Organizations()`,
with its typed request and graph lifetime guards. Native selection alone adds no
HTTP route.

Availability is advisory, not a reservation: another create/update may win
immediately afterward. Retained archived rows still occupy their tenant's
unique name. Rename releases the prior name only once the owner commits it.
Current session/candidate policy and shared safe admission apply on each call;
logout, expiry, unavailable authority or source failure returns no availability.
This addition uses existing migration history unchanged.

## Bootstrap and populated upgrades

Include `organization/postgres` in the existing operator migration selection.
Use the normal `Check`, `Plan` and `Apply` flow before feature initialization;
the runtime does not migrate implicitly. Organization and prerequisite histories
append independently without rewriting installed baseline/session/risk prefixes.
Invitation migrations follow membership migrations, allowing later opt-in.
The original organization/invitation versions1..5 remain unchanged. The native
cancellation, rejection, expiry and resend histories append at6..9; migrate
before selecting resend. These prerequisites enable no sibling HTTP routes.
Natural cancellation adds the native original-epoch correlation migration at10,
without rewriting versions1..9. Apply it before enabling `InvitationCancel`.
Existing raw cancellation stays usable without that optional native migration;
legacy cancellation effects never gain invented original-version correlation.
Natural recipient rejection appends its independent original-epoch correlation
at11 without rewriting versions1..10. Apply it before selecting `InvitationReject`;
legacy rejection history remains NULL and cannot fabricate original recovery.

Reference deliberately selects the adapter's **transactional index variants**
because durable migration commands require atomic histories. These builds can
block writes: plan a bounded maintenance window and operator timeout appropriate
to existing data. The adapter's concurrent sources remain unchanged for other
operators. Do not apply both variants or adopt independently installed indexes
into this history without an explicit supported migration plan.

## Consumer operations and recovery

After initialization, `FeatureSet.Organizations()` exposes native create,
metadata replacement, add/update/remove member, scoped get/list and original operation recovery.
`OrganizationInvitations()` exposes original-key send/resend, owner-only get, authenticated-recipient
discovery, natural-repeat cancellation/rejection, retained acceptance preparation and
explicit original recovery.
Handles share graph initialization, tenant and shutdown guards; they do not own
another lifetime or authority system.

HTTP create, metadata update, member admission/role update and invitation send/resend
require `Idempotency-Key`; retry the exact original request/key. Metadata updates
carry the exact organization version, name and slug. Member-role updates carry
both exact organization and member versions; administrator/owner transitions
and last-owner safety remain native decisions. Retry recovery never grants a
removed administrator continuing access or turns changed intent into a new write.

For invitation sending, deliver the encrypted intent through the selected worker. Only the
intended current verified recipient can accept its purpose-bound proof. Preserve
the returned safe original binding for native `RecoverAccept` after an ambiguous
outcome or process reconstruction. Reposting a consumed proof is not recovery;
there is no added HTTP recovery endpoint. Recovery never renews proof, authority
or command custody. Revoked sessions cannot read protected history.

Resend accepts only the original key, organization/invitation IDs and their
exact versions. Recipient, member role and original exclusive expiry remain
native-owned. The organization epoch is read-only; the invitation version must
leave room for successor and terminal transitions. Its transaction supersedes
the predecessor proof and queues one encrypted successor. After delivery, only
the successor can be accepted. Matching-key recovery returns the original
receipt and authorized original delivery observation even after acceptance;
it does not regenerate proof, renew validity or redispatch. Late observation
failure retains known commitment without delivery state. Queue/provider
acceptance is not confirmed delivery. No proof or delivery-effect ID is exported.

Cancellation forbids `Idempotency-Key` and caller-supplied command/proof fields.
Supply only exact organization/invitation IDs and versions. Current managers
require invitation permission, independently of organization-read permission;
recipient withdrawal cannot prevent revocation. Native command allocation,
terminal effects and original-outcome recovery share the existing authority.
Matching repeats disclose only the actual original committed metadata, including
after graph reconstruction; absence/terminal state alone is not success.
Unknown remains an explicit reconciliation outcome, not automatic reexecution.
The response exposes neither membership nor delivery projections. Session
revocation denies both future mutation and protected original-history recovery.

Recipient rejection independently selects `InvitationReject`, current sessions
and shared safe-rate admission, not administrative or secret admission. Its
exact four ID/version fields forbid a key, caller command and proof. Only the
current verified intended recipient may act; neither manager privileges nor
membership substitute. The native transaction terminally rejects the invitation
and fences old/prepared acceptance. Matching natural retries and reconstructed
handles disclose only actual original history under current authority. Success
projects `state: "rejected"`, never membership or delivery. Unknown remains
explicit; logout denies future rejection and original-outcome recovery.

## Reproduce the complete profile

Against a task-owned loopback PostgreSQL instance with the fixture's disposable
`postgres` login and `identity_test` bootstrap database, run from this module:

```sh
GOWORK=off IDENTITY_REFERENCE_POSTGRES_PORT="$owned_postgres_port" \
  go test -race -tags=integration \
  -run '^TestReferencePostgresOrganization(HTTPS|PopulatedUpgradeHTTPS)$' -count=1 .
```

Use task-owned Go caches and remove the isolated cluster/caches after testing.
The tests exercise real HTTPS, PostgreSQL, migrations, registration, verification,
session authority, organization transactions and recovery. Only declared external
delivery and HIBP seams are controlled. The populated variant first creates a
working identity backend with no organization routes, then applies the forward
upgrade and runs the same journey while preserving existing identities/sessions.
This finite Reference profile is not full M22 or all-67-unit qualification.
