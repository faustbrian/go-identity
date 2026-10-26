# Organization composition

This selected backend profile connects real registration, verification and
password signin to organization creation, metadata/role updates, scoped reads, member admission and
removal, encrypted invitation delivery/resend, cancellation/rejection and once-only acceptance.
It does not implement an administrative UI or claim full organization lifecycle,
teams, dynamic roles, domain ownership, archive/restore or other login profiles.

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
`InvitationListMine`, `InvitationSend`, `InvitationResend`, `InvitationCancel`,
`InvitationReject`, `SlugAvailable` and `InvitationAccept`.
Each requires its
actual native owner and the shared strong HTTP rate backend. Configure stable
safe/admin/secret namespaces and keys. The degradation and administrative-denial
callbacks retain the transport's bounded synchronous contracts: administrative
denials must be durably audited, without secrets. Namespace/key changes affect
rate budgets and require coordinated rollout, not per-request rotation.

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
