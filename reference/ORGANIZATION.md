# Organization composition

This selected backend profile connects real registration, verification and
password signin to organization creation, scoped reads, member admission and
removal, encrypted invitation delivery and once-only recipient acceptance.
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
`Create`, `Get`, `MemberList`, `MemberAdd`, `MemberRemove`, `InvitationGet`,
`InvitationListMine`, `InvitationSend` and `InvitationAccept`. Each requires its
actual native owner and the shared strong HTTP rate backend. Configure stable
safe/admin/secret namespaces and keys. The degradation and administrative-denial
callbacks retain the transport's bounded synchronous contracts: administrative
denials must be durably audited, without secrets. Namespace/key changes affect
rate budgets and require coordinated rollout, not per-request rotation.

## Bootstrap and populated upgrades

Include `organization/postgres` in the existing operator migration selection.
Use the normal `Check`, `Plan` and `Apply` flow before feature initialization;
the runtime does not migrate implicitly. Organization and prerequisite histories
append independently without rewriting installed baseline/session/risk prefixes.
Invitation migrations follow membership migrations, allowing later opt-in.

Reference deliberately selects the adapter's **transactional index variants**
because durable migration commands require atomic histories. These builds can
block writes: plan a bounded maintenance window and operator timeout appropriate
to existing data. The adapter's concurrent sources remain unchanged for other
operators. Do not apply both variants or adopt independently installed indexes
into this history without an explicit supported migration plan.

## Consumer operations and recovery

After initialization, `FeatureSet.Organizations()` exposes native create,
add/remove member, scoped get/list and original operation recovery.
`OrganizationInvitations()` exposes send, owner-only get, authenticated-recipient
discovery, retained acceptance preparation and explicit original recovery.
Handles share graph initialization, tenant and shutdown guards; they do not own
another lifetime or authority system.

HTTP send requires `Idempotency-Key`; retry the exact original request/key.
Deliver the resulting encrypted intent through the selected worker. Only the
intended current verified recipient can accept its purpose-bound proof. Preserve
the returned safe original binding for native `RecoverAccept` after an ambiguous
outcome or process reconstruction. Reposting a consumed proof is not recovery;
there is no added HTTP recovery endpoint. Recovery never renews proof, authority
or command custody. Revoked sessions cannot read protected history.

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
