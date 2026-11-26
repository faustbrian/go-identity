//go:build integration

package reference_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	"github.com/faustbrian/go-identity/reference"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	scim "github.com/faustbrian/go-scim"
	scimorganization "github.com/faustbrian/go-scim/organization"
	scimpostgres "github.com/faustbrian/go-scim/postgres"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestReferencePostgresDirectoryGroupRoleApplyHTTPS(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{
		postgresBaseline: true, organization: true, directorySync: true,
		directorySyncStandalone: true, directoryGroupRoleApply: true,
	})
}

func configureReferenceDirectoryGroupRoles(c *reference.StoreConfiguration) {
	c.DirectorySync.GroupSource.Roles = &reference.DirectoryGroupRoleConfiguration{}
	c.Organization.Core.DynamicRoles = organization.DynamicRoleConfig{
		Version: 1, MaximumRoles: 10, TeamBindingsVersion: 1,
		Catalog: []organization.Permission{
			{ID: "document-read", Action: "document.read", ResourceType: "document"},
			{ID: "archive-read", Action: "archive.read", ResourceType: "document"},
		},
	}
	c.Organization.TeamRoleBindings = true
	c.Organization.DirectRoleBindings = true
}

func (p referenceDirectoryPolicy) ObserveDirectoryRoleAuthorization(ctx context.Context, d authorization.DecisionContext, version uint64) (ssopg.ProviderUpdateAuthorizationEvidence, error) {
	return p.ObserveDirectorySyncAuthorization(ctx, d, version)
}

func proveReferenceDirectoryGroupRoleJourney(t *testing.T, ctx context.Context, f liveStores,
	serverConfig reference.ReferenceConfig, selected reference.StoreConfiguration, deps reference.ReferenceDependencies, configs []deliverypg.WorkerConfig,
	features reference.FeatureSet, owner, member organizationTestHuman, source referenceDirectorySCIMSource,
	generation referenceDirectoryProjection, predecessor [32]byte, status func() referenceDirectoryProjection) [32]byte {
	t.Helper()
	port, err := features.Organizations()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := features.DirectoryGroupRoleApply(); err == nil {
		t.Fatal("schema-only role selection exposed an executor without an explicit mapping")
	}
	repository, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	epoch := func() uint64 {
		t.Helper()
		current, err := repository.ObserveCredentialAuthority(ctx, organization.CredentialAuthorityQuery{
			TenantID: otpTenant, OrganizationID: referenceDirectoryOrganization,
		})
		if err != nil {
			t.Fatal("read the native current organization version", err)
		}
		return current.Version
	}
	committed := func(result organization.StoreResult, err error) {
		t.Helper()
		if err != nil || result.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("commit genuine local role fixture through its public owner", err)
		}
	}
	committed(port.AddMember(ctx, organization.AddMemberOperationRequest{
		Authentication: owner.auth, IdempotencyKey: teamCRUDKey(t, "directory-role-local-member"),
		OrganizationID: referenceDirectoryOrganization, OrganizationVersion: epoch(), UserID: member.user,
		Role: organization.RoleMember, CorrelationID: "directory-role-setup",
	}, "127.0.0.1"))
	teamID, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	team := organization.ID(teamID)
	directoryRoleID, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	localRoleID, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	directoryRole, localRole := organization.ID(directoryRoleID), organization.ID(localRoleID)
	committed(port.CreateTeam(ctx, organization.CreateTeamOperationRequest{
		Authentication: owner.auth, IdempotencyKey: teamCRUDKey(t, "directory-role-team"),
		OrganizationID: referenceDirectoryOrganization, OrganizationVersion: epoch(), TeamID: team,
		Name: "Directory readers", CorrelationID: "directory-role-setup",
	}, "127.0.0.1"))
	for _, role := range []struct {
		id               organization.ID
		name, permission string
	}{{directoryRole, "Directory reader", "document-read"}, {localRole, "Local reader", "archive-read"}} {
		committed(port.CreateDynamicRole(ctx, organization.CreateDynamicRoleOperationRequest{
			Authentication: owner.auth, IdempotencyKey: teamCRUDKey(t, "directory-role-"+string(role.id)),
			OrganizationID: referenceDirectoryOrganization, OrganizationVersion: epoch(), RoleID: role.id,
			Name: role.name, CorrelationID: "directory-role-setup",
			Statements: []organization.RoleStatement{{PermissionID: role.permission, ResourceID: "one", Effect: authorization.Allow}},
		}, "127.0.0.1"))
	}
	committed(port.AssignTeamDynamicRole(ctx, organization.AssignTeamDynamicRoleOperationRequest{
		Authentication: owner.auth, IdempotencyKey: teamCRUDKey(t, "directory-role-team-binding"),
		OrganizationID: referenceDirectoryOrganization, OrganizationVersion: epoch(), TeamID: team,
		TeamVersion: 1, RoleID: directoryRole, RoleVersion: 1, CorrelationID: "directory-role-setup",
	}, "127.0.0.1"))
	committed(port.AssignDynamicRole(ctx, organization.AssignDynamicRoleOperationRequest{
		Authentication: owner.auth, IdempotencyKey: teamCRUDKey(t, "directory-role-direct-binding"),
		OrganizationID: referenceDirectoryOrganization, OrganizationVersion: epoch(), RoleID: localRole,
		RoleVersion: 1, UserID: member.user, OrganizationMemberVersion: 1, CorrelationID: "directory-role-setup",
	}, "127.0.0.1"))

	edge := source.createGroupEdge(t, ctx)
	// Account linking is outside this journey. As in the native SSO role
	// fixture, install only the exact pre-existing SCIM-to-local identity link;
	// the source owner still checks this stored link on every role operation.
	linked, err := f.pool.Raw().Exec(ctx, `UPDATE scim.users SET user_id=$6
 WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4 AND resource_id=$5`,
		string(edge.scope.TenantID), string(edge.scope.OrganizationID), edge.scope.ProviderID, edge.scope.ConnectionID, edge.userID, string(member.user))
	if err != nil || linked.RowsAffected() != 1 {
		t.Fatal("install exact pre-existing source identity fixture", err)
	}
	mapping := scimorganization.DirectoryRoleMappingConfig{
		Directory: scimorganization.DirectoryMappingConfig{
			TenantID: edge.scope.TenantID, OrganizationID: edge.scope.OrganizationID,
			ProviderID: sso.ProviderID(edge.scope.ProviderID), ConnectionID: edge.scope.ConnectionID, MappingVersion: generation.MappingVersion,
			Groups:  []scimorganization.DirectoryGroupTeamMapping{{GroupID: edge.groupID, TeamID: team}},
			Members: []scimorganization.DirectoryMemberUserMapping{{MemberID: edge.userID, UserID: member.user}},
		},
		Roles: []scimorganization.DirectoryGroupRoleMapping{{GroupID: edge.groupID, TeamID: team, RoleID: directoryRole}},
	}
	policy := referenceDirectoryPolicy{}
	apply := reference.DirectoryGroupRoleApplyConfiguration{Mapping: mapping, Authorization: policy, ApplyAuthorization: policy}
	roleFeatures, worker := bindReferenceDirectoryGroupRoleGraph(t, ctx, selected, deps, configs, apply)
	rolePort, err := roleFeatures.Organizations()
	if err != nil {
		t.Fatal(err)
	}
	server, err := reference.NewServer(serverConfig, deps, roleFeatures)
	if err != nil {
		t.Fatal("build the existing HTTPS permission route on the selected role graph", err)
	}
	network := httptest.NewTLSServer(server.Handler())
	defer network.Close()
	client := network.Client()
	permission := func(service *reference.OrganizationService, action string, want authorization.Outcome) {
		t.Helper()
		version := epoch()
		decision, err := service.CheckPermission(ctx, organization.PermissionCheckRequest{
			Authentication: member.auth, OrganizationID: referenceDirectoryOrganization, OrganizationVersion: version,
			Action: authorization.Action(action), ResourceType: "document", ResourceID: "one", CorrelationID: "directory-role-check",
		})
		if err != nil || decision.Outcome != want {
			t.Fatalf("authenticated member permission %s: got %v, want %v; %v", action, decision.Outcome, want, err)
		}
		if service != rolePort {
			return
		}
		query := url.Values{
			"organizationID": {referenceDirectoryOrganization}, "organizationVersion": {strconv.FormatUint(version, 10)},
			"action": {action}, "resourceType": {"document"}, "resourceID": {"one"},
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, network.URL+"/v1/organization/permission-check?"+query.Encode(), nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+member.auth.Bearer.Token())
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("check the genuine member permission over HTTPS", err)
		}
		wire, readErr := io.ReadAll(io.LimitReader(response.Body, 16385))
		closeErr := response.Body.Close()
		var projected organizationhttp.PermissionCheckResponse
		if readErr != nil || closeErr != nil || len(wire) > 16384 || response.StatusCode != http.StatusOK ||
			json.Unmarshal(wire, &projected) != nil || projected.Decision != want.String() || projected.OrganizationVersion != version {
			t.Fatalf("HTTPS member permission %s: status %d, decision %q at version %d; want %s at version %d; cleanup %v/%v",
				action, response.StatusCode, projected.Decision, projected.OrganizationVersion, want, version, readErr, closeErr)
		}
	}
	permission(rolePort, "document.read", authorization.Deny)
	permission(rolePort, "archive.read", authorization.Allow)
	permission(rolePort, "document.write", authorization.Deny)

	delta, err := sso.NewDirectoryGroupMembershipDelta(commandIDForReference(t), edge.groupID, edge.userID, sso.DirectoryMembershipAdd)
	if err != nil {
		t.Fatal(err)
	}
	request := ssopg.DirectoryGroupRoleApplyRequest{
		GenerationID: generation.GenerationID, ProviderID: sso.ProviderID(generation.ProviderID),
		MappingVersion: generation.MappingVersion, PredecessorCheckpoint: predecessor, Delta: delta,
	}
	type previewState struct {
		generation                       referenceDirectoryProjection
		attribution                      organizationpg.DirectoryTeamRoleAttribution
		organization                     string
		audits, events, commands, claims int
	}
	observeState := func() previewState {
		t.Helper()
		state := previewState{generation: status()}
		attribution, err := repository.ObserveDirectoryTeamRoleAttribution(ctx, organizationpg.DirectoryTeamGrantScope{
			TenantID: edge.scope.TenantID, OrganizationID: edge.scope.OrganizationID,
			ProviderID: organization.ID(edge.scope.ProviderID), ConnectionID: organization.ID(edge.scope.ConnectionID),
			GroupID: organization.ID(edge.groupID), TeamID: team, UserID: member.user,
		}, directoryRole)
		if err != nil {
			t.Fatal("observe the exact source role contribution around Reference role inspection", err)
		}
		state.attribution = attribution
		if err := f.pool.Raw().QueryRow(ctx, `SELECT jsonb_build_object(
 'organizations',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM organization.organizations r),
 'memberships',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM organization.memberships r),
 'teams',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM organization.teams r),
 'team_memberships',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM organization.team_memberships r),
 'grants',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM organization.directory_team_grants r),
 'roles',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM organization.custom_roles r),
 'bindings',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM organization.team_role_bindings r),
 'role_grants',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM organization.directory_team_role_grants r)
 )::text,
 (SELECT count(*) FROM audit.records),
 (SELECT count(*) FROM outbox_messages),
 (SELECT count(*) FROM identity.commands),
 (SELECT count(*) FROM identity.identity_command_id_claims)`).Scan(&state.organization, &state.audits, &state.events, &state.commands, &state.claims); err != nil {
			t.Fatal("observe organization state and protected effects around Reference role inspection", err)
		}
		return state
	}
	assertUnchanged := func(before previewState) {
		t.Helper()
		if after := observeState(); after != before {
			t.Fatal("Reference role inspection changed HTTPS Status, organization state, exact attribution, or protected effects")
		}
	}
	beforePreview := observeState()
	if beforePreview.attribution.Membership.Source || beforePreview.attribution.Membership.Local || beforePreview.attribution.RetainedGrantVersion != 0 {
		t.Fatal("live mapped role must begin without its exact retained role or team membership")
	}
	if missing, err := worker.ObserveDrift(ctx, request); err != nil || missing != (ssopg.DirectoryGroupRoleDrift{
		Kind: ssopg.DirectoryGroupRoleDriftMissing, Source: scimpostgres.DirectoryGroupEdgePresent,
	}) {
		t.Fatal("Reference role inspection did not report the exact live source's missing role contribution", err)
	}
	assertUnchanged(beforePreview)
	permission(rolePort, "document.read", authorization.Deny)
	permission(rolePort, "archive.read", authorization.Allow)
	permission(rolePort, "document.write", authorization.Deny)
	granted, err := worker.Apply(ctx, request)
	if err != nil || len(granted.ChildOutcomes) != 1 || granted.ChildOutcomes[0].Outcome != identity.CommitOutcomeCommitted ||
		granted.ChildOutcomes[0].Binding.ActorID != referenceDirectorySCIMActor || granted.ChildOutcomes[0].Binding.UserID != member.user || granted.Checkpoint == predecessor {
		t.Fatal("direct role Apply did not settle the exact source-account child for the authenticated member", err)
	}
	permission(rolePort, "document.read", authorization.Allow)
	permission(rolePort, "archive.read", authorization.Allow)
	permission(rolePort, "document.write", authorization.Deny)
	permission(port, "document.read", authorization.Deny)
	if replay, err := worker.Apply(ctx, request); err != nil || !reflect.DeepEqual(replay, granted) {
		t.Fatal("current role Apply did not replay its exact original receipt and checkpoint", err)
	}
	afterApply := observeState()
	if afterApply.generation.Checkpoint != base64.RawURLEncoding.EncodeToString(granted.Checkpoint[:]) ||
		afterApply.generation.ReadCount != 1 || afterApply.generation.AppliedCount != 1 || afterApply.generation.RejectedCount != 0 ||
		!afterApply.attribution.Membership.Source || afterApply.attribution.RetainedGrantVersion == 0 {
		t.Fatal("ordinary role Apply did not settle the exact source contribution and HTTPS checkpoint once")
	}
	if stale, err := worker.ObserveDrift(ctx, request); !errors.Is(err, sso.ErrDirectoryReconciliation) || stale != (ssopg.DirectoryGroupRoleDrift{}) {
		t.Fatal("superseded Reference role checkpoint disclosed a drift report", err)
	}
	assertUnchanged(afterApply)
	current := request
	current.PredecessorCheckpoint = granted.Checkpoint
	if aligned, err := worker.ObserveDrift(ctx, current); err != nil || aligned != (ssopg.DirectoryGroupRoleDrift{
		Kind: ssopg.DirectoryGroupRoleDriftInSync, Source: scimpostgres.DirectoryGroupEdgePresent,
	}) {
		t.Fatal("Reference role inspection did not converge at the exact current successor", err)
	}
	assertUnchanged(afterApply)
	permission(rolePort, "document.read", authorization.Allow)
	permission(rolePort, "archive.read", authorization.Allow)
	permission(rolePort, "document.write", authorization.Deny)

	removedSource, err := source.groups.Execute(ctx, scim.Request{
		Operation: scim.GroupReplace, ResourceID: edge.groupID, Credential: source.bearer,
		ContentType: "application/scim+json", IfMatch: edge.groupETag, IdempotencyKey: "directory-role-remove-source-edge",
		Body: []byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Reference directory group","members":[]}`),
	})
	if err != nil || removedSource.Status != http.StatusOK {
		t.Fatal("withdraw the actual SCIM Group membership through its owner", err)
	}
	permission(rolePort, "document.read", authorization.Deny)
	permission(rolePort, "archive.read", authorization.Allow)
	if replay, err := worker.Apply(ctx, request); err != nil || !reflect.DeepEqual(replay, granted) {
		t.Fatal("removed source edge prevented exact recovery of the original committed grant", err)
	}
	delta, err = sso.NewDirectoryGroupMembershipDelta(commandIDForReference(t), edge.groupID, edge.userID, sso.DirectoryMembershipRemove)
	if err != nil {
		t.Fatal(err)
	}
	withdrawal := request
	withdrawal.PredecessorCheckpoint, withdrawal.Delta = granted.Checkpoint, delta
	withdrawn, err := worker.Apply(ctx, withdrawal)
	if err != nil || len(withdrawn.ChildOutcomes) != 1 || withdrawn.ChildOutcomes[0].Outcome != identity.CommitOutcomeCommitted || withdrawn.Checkpoint == granted.Checkpoint {
		t.Fatal("direct role Apply did not commit source-only withdrawal", err)
	}
	_, reconstructed := bindReferenceDirectoryGroupRoleGraph(t, ctx, selected, deps, configs, apply)
	if replay, err := reconstructed.Apply(ctx, withdrawal); err != nil || !reflect.DeepEqual(replay, withdrawn) {
		t.Fatal("reconstructed role worker lost the current exact receipt and checkpoint", err)
	}
	if historical, err := reconstructed.Apply(ctx, request); !errors.Is(err, sso.ErrDirectoryReconciliation) || historical.Checkpoint != ([32]byte{}) {
		t.Fatal("historical grant disclosed a stale successor after withdrawal", err)
	}
	permission(rolePort, "document.read", authorization.Deny)
	permission(rolePort, "archive.read", authorization.Allow)
	permission(rolePort, "document.write", authorization.Deny)
	return withdrawn.Checkpoint
}

func bindReferenceDirectoryGroupRoleGraph(t *testing.T, ctx context.Context, selected reference.StoreConfiguration,
	deps reference.ReferenceDependencies, configs []deliverypg.WorkerConfig, apply reference.DirectoryGroupRoleApplyConfiguration) (reference.FeatureSet, *reference.DirectoryGroupRoleApplyService) {
	t.Helper()
	admin, source := *selected.DirectorySync, *selected.DirectorySync.GroupSource
	source.Roles = &reference.DirectoryGroupRoleConfiguration{Apply: &apply}
	admin.GroupSource = &source
	rate := selected.HTTPDirectorySync.Rate
	selected.HTTPOrganization = &reference.HTTPOrganizationConfiguration{
		PermissionCheck: true, SafeNamespace: rate.SafeNamespace,
		EmergencyMaximumKeys: rate.EmergencyMaximumKeys, Degraded: rate.Degraded,
	}
	selected.DirectorySync, selected.HTTPDirectorySync = &admin, nil
	stores, err := reference.ComposeStores(selected, deps)
	if err != nil {
		t.Fatal("compose the explicit native role graph on the same primary", err)
	}
	t.Cleanup(func() {
		bounded, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := stores.Close(bounded); err != nil {
			t.Error("close direct role graph", err)
		}
	})
	providers, err := reference.ComposeProviders(stores)
	if err != nil {
		t.Fatal(err)
	}
	workers, err := reference.ComposeWorkers(stores, providers, configs...)
	if err != nil {
		t.Fatal(err)
	}
	features, err := reference.ComposeFeatures(stores, providers, workers)
	if err != nil {
		t.Fatal(err)
	}
	if err := features.Initialize(ctx); err != nil {
		t.Fatal("initialize direct role graph against the installed schema", err)
	}
	worker, err := features.DirectoryGroupRoleApply()
	if err != nil {
		t.Fatal("obtain the explicitly selected native role executor", err)
	}
	return features, worker
}
