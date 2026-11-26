//go:build integration

package reference_test

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	"github.com/faustbrian/go-identity/reference"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	scim "github.com/faustbrian/go-scim"
	scimorganization "github.com/faustbrian/go-scim/organization"
	scimpostgres "github.com/faustbrian/go-scim/postgres"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestReferencePostgresDirectoryMixedApplyHTTPS(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{
		postgresBaseline: true, organization: true, directorySync: true,
		directorySyncStandalone: true, directoryMixedApply: true,
	})
}

func proveReferenceDirectoryMixedJourney(t *testing.T, ctx context.Context, f liveStores,
	selected reference.StoreConfiguration, deps reference.ReferenceDependencies, configs []deliverypg.WorkerConfig,
	features reference.FeatureSet, owner, member organizationTestHuman, source referenceDirectorySCIMSource,
	generation referenceDirectoryProjection, predecessor [32]byte, status func() referenceDirectoryProjection) [32]byte {
	t.Helper()
	if _, err := features.DirectoryMixedApply(); err == nil {
		t.Fatal("schema-only mixed selection exposed a worker without an explicit mapping")
	}
	port, err := features.Organizations()
	if err != nil {
		t.Fatal(err)
	}
	repository, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	current := func(actor identity.UserID) organization.CredentialAuthorityObservation {
		t.Helper()
		view, err := repository.ObserveCredentialAuthority(ctx, organization.CredentialAuthorityQuery{
			TenantID: otpTenant, OrganizationID: referenceDirectoryOrganization, ActorID: actor,
		})
		if err != nil {
			t.Fatal("read genuine organization authority", err)
		}
		return view
	}
	committed := func(result organization.StoreResult, err error) {
		t.Helper()
		if err != nil || result.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("commit the local member, team and role through their public owner", err)
		}
	}
	committed(port.AddMember(ctx, organization.AddMemberOperationRequest{
		Authentication: owner.auth, IdempotencyKey: teamCRUDKey(t, "directory-mixed-existing-member"),
		OrganizationID: referenceDirectoryOrganization, OrganizationVersion: current("").Version,
		UserID: member.user, Role: organization.RoleMember, CorrelationID: "directory-mixed-setup",
	}, "127.0.0.1"))
	newID := func() organization.ID {
		t.Helper()
		id, err := identity.NewSubjectID()
		if err != nil {
			t.Fatal(err)
		}
		return organization.ID(id)
	}
	team, role := newID(), newID()
	committed(port.CreateTeam(ctx, organization.CreateTeamOperationRequest{
		Authentication: owner.auth, IdempotencyKey: teamCRUDKey(t, "directory-mixed-team"),
		OrganizationID: referenceDirectoryOrganization, OrganizationVersion: current("").Version,
		TeamID: team, Name: "Mixed directory readers", CorrelationID: "directory-mixed-setup",
	}, "127.0.0.1"))
	committed(port.CreateDynamicRole(ctx, organization.CreateDynamicRoleOperationRequest{
		Authentication: owner.auth, IdempotencyKey: teamCRUDKey(t, "directory-mixed-role"),
		OrganizationID: referenceDirectoryOrganization, OrganizationVersion: current("").Version,
		RoleID: role, Name: "Mixed document reader", CorrelationID: "directory-mixed-setup",
		Statements: []organization.RoleStatement{{PermissionID: "document-read", ResourceID: "one", Effect: authorization.Allow}},
	}, "127.0.0.1"))
	committed(port.AssignTeamDynamicRole(ctx, organization.AssignTeamDynamicRoleOperationRequest{
		Authentication: owner.auth, IdempotencyKey: teamCRUDKey(t, "directory-mixed-team-role"),
		OrganizationID: referenceDirectoryOrganization, OrganizationVersion: current("").Version,
		TeamID: team, TeamVersion: 1, RoleID: role, RoleVersion: 1, CorrelationID: "directory-mixed-setup",
	}, "127.0.0.1"))

	edge := source.createGroupEdge(t, ctx)
	// As in the existing role journey, account linking is pre-existing fixture
	// state; real source reads still validate the exact SCIM-to-local link.
	linked, err := f.pool.Raw().Exec(ctx, `UPDATE scim.users SET user_id=$6
 WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4 AND resource_id=$5`,
		string(edge.scope.TenantID), string(edge.scope.OrganizationID), edge.scope.ProviderID, edge.scope.ConnectionID, edge.userID, string(member.user))
	if err != nil || linked.RowsAffected() != 1 {
		t.Fatal("install only the pre-existing SCIM identity link", err)
	}
	roleGroup, err := source.groups.Execute(ctx, scim.Request{
		Operation: scim.GroupCreate, Credential: source.bearer, ContentType: "application/scim+json",
		IdempotencyKey: "reference-directory-mixed-role-group",
		Body:           []byte(fmt.Sprintf(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Mixed explicit role","members":[{"type":"User","value":%q}]}`, edge.userID)),
	})
	if err != nil {
		t.Fatal("create the distinct real role-bearing SCIM Group", err)
	}
	roleGroupID := referenceDirectorySCIMResourceID(t, roleGroup, http.StatusCreated)
	var users [2]string
	var revisions [2]scim.Version
	observeUser := func(user string) scimpostgres.DirectoryUserObservation {
		t.Helper()
		response, err := source.native.Execute(ctx, scim.Request{
			Operation: scim.UserGet, Credential: source.bearer, ResourceID: user,
		})
		if err != nil {
			t.Fatal("read the exact current SCIM User revision for mixed inspection", err)
		}
		if got := referenceDirectorySCIMResourceID(t, response, http.StatusOK); got != user {
			t.Fatal("current SCIM User read replaced the exact source identity")
		}
		return scimpostgres.DirectoryUserObservation{State: scimpostgres.DirectoryMembershipUserActive, Revision: response.ETag}
	}
	members := []scimorganization.DirectoryMemberUserMapping{{MemberID: edge.userID, UserID: member.user}}
	for i := range users {
		response, err := source.native.Execute(ctx, scim.Request{
			Operation: scim.UserCreate, Credential: source.bearer, ContentType: "application/scim+json",
			IdempotencyKey: fmt.Sprintf("reference-directory-mixed-user-%d", i),
			Body:           []byte(fmt.Sprintf(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"ReferenceMixedUser%d","active":true}`, i)),
		})
		if err != nil {
			t.Fatal("create actual active SCIM User before mixed admission", err)
		}
		users[i] = referenceDirectorySCIMResourceID(t, response, http.StatusCreated)
		revisions[i] = observeUser(users[i]).Revision
		members = append(members, scimorganization.DirectoryMemberUserMapping{MemberID: users[i], UserID: identity.UserID(users[i])})
		if _, err := repository.ObserveCredentialAuthority(ctx, organization.CredentialAuthorityQuery{
			TenantID: otpTenant, OrganizationID: referenceDirectoryOrganization, ActorID: identity.UserID(users[i]),
		}); err == nil {
			t.Fatal("SCIM User CRUD itself admitted an organization member")
		}
	}
	groupMapping := scimorganization.DirectoryMappingConfig{
		TenantID: edge.scope.TenantID, OrganizationID: edge.scope.OrganizationID,
		ProviderID: sso.ProviderID(edge.scope.ProviderID), ConnectionID: edge.scope.ConnectionID,
		MappingVersion: generation.MappingVersion, Members: members,
		Groups: []scimorganization.DirectoryGroupTeamMapping{{GroupID: edge.groupID, TeamID: team}},
	}
	roleDirectory := groupMapping
	roleDirectory.Groups = []scimorganization.DirectoryGroupTeamMapping{{GroupID: roleGroupID, TeamID: team}}
	roleMapping := scimorganization.DirectoryRoleMappingConfig{
		Directory: roleDirectory,
		Roles:     []scimorganization.DirectoryGroupRoleMapping{{GroupID: roleGroupID, TeamID: team, RoleID: role}},
	}
	policy := referenceDirectoryPolicy{}
	apply := reference.DirectoryMixedApplyConfiguration{
		Users: scimorganization.DirectoryUserMappingConfig{
			TenantID: edge.scope.TenantID, OrganizationID: edge.scope.OrganizationID,
			ProviderID: sso.ProviderID(edge.scope.ProviderID), ConnectionID: edge.scope.ConnectionID,
			MappingVersion: generation.MappingVersion, Members: members, AllowAdmission: true, AllowWithdrawal: true,
		},
		Groups: &groupMapping, Roles: &roleMapping, Authorization: policy, ApplyAuthorization: policy,
		MaximumMembers: 100, MaximumPerUser: 10,
	}
	bound, worker := bindReferenceDirectoryMixedGraph(t, ctx, selected, deps, configs, apply)
	boundPort, err := bound.Organizations()
	if err != nil {
		t.Fatal(err)
	}
	permission := func(service *reference.OrganizationService, want authorization.Outcome) {
		t.Helper()
		decision, err := service.CheckPermission(ctx, organization.PermissionCheckRequest{
			Authentication: member.auth, OrganizationID: referenceDirectoryOrganization, OrganizationVersion: current("").Version,
			Action: "document.read", ResourceType: "document", ResourceID: "one", CorrelationID: "directory-mixed-check",
		})
		if err != nil || decision.Outcome != want {
			t.Fatal("mixed source role did not control the genuine member permission", decision.Outcome, want, err)
		}
	}
	permission(boundPort, authorization.Deny)
	var childIDs [4]identity.CommandID
	for i := range childIDs {
		childIDs[i] = commandIDForReference(t)
	}
	first, err := sso.NewDirectoryUserAdmissionDelta(childIDs[0], users[0], string(revisions[0]))
	if err != nil {
		t.Fatal(err)
	}
	group, err := sso.NewDirectoryGroupMembershipDelta(childIDs[1], edge.groupID, edge.userID, sso.DirectoryMembershipAdd)
	if err != nil {
		t.Fatal(err)
	}
	roleDelta, err := sso.NewDirectoryGroupMembershipDelta(childIDs[2], roleGroupID, edge.userID, sso.DirectoryMembershipAdd)
	if err != nil {
		t.Fatal(err)
	}
	second, err := sso.NewDirectoryUserAdmissionDelta(childIDs[3], users[1], string(revisions[1]))
	if err != nil {
		t.Fatal(err)
	}
	request := ssopg.DirectoryMixedApplyRequest{
		GenerationID: generation.GenerationID, ProviderID: sso.ProviderID(generation.ProviderID),
		MappingVersion: generation.MappingVersion, PredecessorCheckpoint: predecessor,
		Deltas: []sso.DirectoryDelta{first, group, roleDelta, second},
	}
	type previewState struct {
		generation referenceDirectoryProjection
		durable    string
	}
	observeState := func() previewState {
		t.Helper()
		state := previewState{generation: status()}
		if err := f.pool.Raw().QueryRow(ctx, `SELECT jsonb_build_object(
 'identity_users',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM identity.users r),
 'organizations',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM organization.organizations r),
 'memberships',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM organization.memberships r),
 'user_grants',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM organization.directory_membership_grants r),
 'teams',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM organization.teams r),
 'team_memberships',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM organization.team_memberships r),
 'group_grants',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM organization.directory_team_grants r),
 'roles',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM organization.custom_roles r),
 'bindings',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM organization.team_role_bindings r),
 'role_grants',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM organization.directory_team_role_grants r),
 'audits',(SELECT count(*) FROM audit.records),
 'events',(SELECT count(*) FROM outbox_messages),
 'commands',(SELECT count(*) FROM identity.commands),
 'claims',(SELECT count(*) FROM identity.identity_command_id_claims)
 )::text`).Scan(&state.durable); err != nil {
			t.Fatal("observe organization state and protected effects around Reference mixed inspection", err)
		}
		return state
	}
	assertUnchanged := func(before previewState) {
		t.Helper()
		if after := observeState(); after != before {
			t.Fatal("Reference mixed inspection changed HTTPS Status, organization state, source contributions, or protected effects")
		}
	}
	wantDrift := []ssopg.DirectoryMixedDrift{
		{Kind: ssopg.DirectoryMixedDriftUser, User: ssopg.DirectoryUserDrift{
			Kind:   scimorganization.DirectoryMembershipDriftMissingSourceGrant,
			Source: scimpostgres.DirectoryUserObservation{State: scimpostgres.DirectoryMembershipUserActive, Revision: revisions[0]},
		}},
		{Kind: ssopg.DirectoryMixedDriftGroup, Group: scimorganization.DirectoryMembershipDrift{Kind: scimorganization.DirectoryMembershipDriftMissingSourceGrant}},
		{Kind: ssopg.DirectoryMixedDriftRole, Role: ssopg.DirectoryGroupRoleDrift{Kind: ssopg.DirectoryGroupRoleDriftMissing, Source: scimpostgres.DirectoryGroupEdgePresent}},
		{Kind: ssopg.DirectoryMixedDriftUser, User: ssopg.DirectoryUserDrift{
			Kind:   scimorganization.DirectoryMembershipDriftMissingSourceGrant,
			Source: scimpostgres.DirectoryUserObservation{State: scimpostgres.DirectoryMembershipUserActive, Revision: revisions[1]},
		}},
	}
	beforePreview := observeState()
	if reports, err := worker.ObserveBatchDrift(ctx, request); err != nil || !slices.Equal(reports, wantDrift) {
		t.Fatal("Reference mixed inspection did not preserve exact missing User, Group, role and User classifications", err)
	}
	assertUnchanged(beforePreview)
	permission(boundPort, authorization.Deny)
	for _, user := range users {
		if _, err := repository.ObserveCredentialAuthority(ctx, organization.CredentialAuthorityQuery{
			TenantID: otpTenant, OrganizationID: referenceDirectoryOrganization, ActorID: identity.UserID(user),
		}); !errors.Is(err, organization.ErrForbidden) {
			t.Fatal("mixed inspection admitted a source User or changed its unavailable organization authority", err)
		}
	}
	before := current("").Version
	result, err := worker.Apply(ctx, request)
	if err != nil || len(result.ChildOutcomes) != len(childIDs) || result.Checkpoint == predecessor || result.Checkpoint == ([32]byte{}) {
		t.Fatal("mixed Apply did not settle the interleaved User, Group, role and User children", err)
	}
	wantUsers := [4]identity.UserID{identity.UserID(users[0]), member.user, member.user, identity.UserID(users[1])}
	wantOperations := [4]identity.FeatureOperation{sso.DirectoryUserAdmissionOperation(), sso.DirectoryTeamMembershipOperation(), sso.DirectoryTeamMembershipOperation(), sso.DirectoryUserAdmissionOperation()}
	for i, receipt := range result.ChildOutcomes {
		if receipt.Validate() != nil || receipt.Outcome != identity.CommitOutcomeCommitted || receipt.Binding.CommandID != childIDs[i] ||
			receipt.Binding.UserID != wantUsers[i] || receipt.Binding.OperationID != wantOperations[i].OperationID ||
			receipt.Binding.TenantID != otpTenant || receipt.Binding.ActorKind != authorization.SubjectServiceAccount ||
			receipt.Binding.ActorID != referenceDirectorySCIMActor || receipt.Feature == nil || receipt.Feature.Operation != wantOperations[i] {
			t.Fatal("mixed result reordered or replaced an exact source-account child receipt", i)
		}
	}
	assertEffects := func() {
		t.Helper()
		var memberships, grants, roles, userAudits, groupAudits, userEvents, groupEvents, roleEvents int
		err := f.pool.Raw().QueryRow(ctx, `SELECT
 (SELECT count(*) FROM organization.directory_membership_grants WHERE active),
 (SELECT count(*) FROM organization.directory_team_grants WHERE active),
 (SELECT count(*) FROM organization.directory_team_role_grants),
 (SELECT count(*) FROM audit.records WHERE action=$1 AND outcome=1),
 (SELECT count(*) FROM audit.records WHERE action=$2 AND outcome=1),
 (SELECT count(*) FROM outbox_messages WHERE topic='sso.directory_sync.membership_changed.v1'),
 (SELECT count(*) FROM outbox_messages WHERE topic='sso.directory_sync.team_membership_changed.v1'),
 (SELECT count(*) FROM outbox_messages WHERE topic='sso.directory_sync.team_role_changed.v1')`,
			sso.DirectoryUserAdmissionOperation().OperationID, sso.DirectoryTeamMembershipOperation().OperationID).
			Scan(&memberships, &grants, &roles, &userAudits, &groupAudits, &userEvents, &groupEvents, &roleEvents)
		if err != nil || memberships != 2 || grants != 2 || roles != 1 || userAudits != 2 || groupAudits != 2 || userEvents != 2 || groupEvents != 1 || roleEvents != 1 {
			t.Fatal("mixed Apply or replay omitted or duplicated native contributions, audits or events", memberships, grants, roles, userAudits, groupAudits, userEvents, groupEvents, roleEvents, err)
		}
		if got := current("").Version; got != before+3 {
			t.Fatal("two User admissions and one effective role change did not advance the organization exactly once each", before, got)
		}
		for _, user := range users {
			view := current(identity.UserID(user))
			if view.Actor.UserID != identity.UserID(user) || !view.Actor.Active || view.Actor.Role != organization.RoleMember {
				t.Fatal("mixed User admission did not establish ordinary native organization authority")
			}
		}
		grant, err := repository.ObserveDirectoryTeamMembership(ctx, organizationpg.DirectoryTeamGrantScope{
			TenantID: edge.scope.TenantID, OrganizationID: edge.scope.OrganizationID,
			ProviderID: organization.ID(edge.scope.ProviderID), ConnectionID: organization.ID(edge.scope.ConnectionID),
			GroupID: organization.ID(edge.groupID), TeamID: team, UserID: member.user,
		})
		if err != nil || !grant.Source || grant.Version != 1 {
			t.Fatal("mixed Group child lost the original attributed team grant", err)
		}
		permission(boundPort, authorization.Allow)
		permission(port, authorization.Deny)
	}
	assertEffects()
	if replay, err := worker.Apply(ctx, request); err != nil || !reflect.DeepEqual(result, replay) {
		t.Fatal("same mixed graph did not replay exact ordered receipts and checkpoint", err)
	}
	assertEffects()
	rebound, restarted := bindReferenceDirectoryMixedGraph(t, ctx, selected, deps, configs, apply)
	if replay, err := restarted.Apply(ctx, request); err != nil || !reflect.DeepEqual(result, replay) {
		t.Fatal("freshly reconstructed mixed graph replaced the original result", err)
	}
	restartedPort, err := rebound.Organizations()
	if err != nil {
		t.Fatal(err)
	}
	permission(restartedPort, authorization.Allow)
	assertEffects()
	afterApply := observeState()
	if afterApply.generation.Checkpoint != base64.RawURLEncoding.EncodeToString(result.Checkpoint[:]) ||
		afterApply.generation.ReadCount != 4 || afterApply.generation.AppliedCount != 4 || afterApply.generation.RejectedCount != 0 {
		t.Fatal("ordinary mixed Apply did not advance the HTTPS checkpoint for exactly its four children")
	}
	if stale, err := worker.ObserveBatchDrift(ctx, request); !errors.Is(err, sso.ErrDirectoryReconciliation) || stale != nil {
		t.Fatal("superseded Reference mixed checkpoint disclosed a complete or partial report", err)
	}
	assertUnchanged(afterApply)
	inspection := request
	inspection.PredecessorCheckpoint, inspection.Deltas = result.Checkpoint, slices.Clone(request.Deltas)
	for i, index := range []int{0, 3} {
		observed := observeUser(users[i])
		inspection.Deltas[index], err = sso.NewDirectoryUserAdmissionDelta(childIDs[index], users[i], string(observed.Revision))
		if err != nil {
			t.Fatal("bind settled mixed inspection to the current exact User revision", err)
		}
		wantDrift[index].User.Kind, wantDrift[index].User.Source = scimorganization.DirectoryMembershipDriftInSync, observed
	}
	wantDrift[1].Group.Kind = scimorganization.DirectoryMembershipDriftInSync
	wantDrift[2].Role.Kind = ssopg.DirectoryGroupRoleDriftInSync
	if reports, err := restarted.ObserveBatchDrift(ctx, inspection); err != nil || !slices.Equal(reports, wantDrift) {
		t.Fatal("Reference mixed inspection did not converge all typed children at the exact successor and current User revisions", err)
	}
	assertUnchanged(afterApply)
	permission(restartedPort, authorization.Allow)
	assertEffects()
	return result.Checkpoint
}

func bindReferenceDirectoryMixedGraph(t *testing.T, ctx context.Context, selected reference.StoreConfiguration,
	deps reference.ReferenceDependencies, configs []deliverypg.WorkerConfig, apply reference.DirectoryMixedApplyConfiguration) (reference.FeatureSet, *reference.DirectoryMixedApplyService) {
	t.Helper()
	admin, source := *selected.DirectorySync, *selected.DirectorySync.GroupSource
	source.Mixed = &reference.DirectoryMixedConfiguration{Apply: &apply}
	source.Roles = &reference.DirectoryGroupRoleConfiguration{Apply: &reference.DirectoryGroupRoleApplyConfiguration{
		Mapping: *apply.Roles, Authorization: apply.Authorization, ApplyAuthorization: referenceDirectoryPolicy{},
	}}
	admin.GroupSource = &source
	selected.DirectorySync, selected.HTTPDirectorySync = &admin, nil
	stores, err := reference.ComposeStores(selected, deps)
	if err != nil {
		t.Fatal("compose the explicit mixed graph against the original primary", err)
	}
	t.Cleanup(func() {
		bounded, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := stores.Close(bounded); err != nil {
			t.Error("close the direct mixed graph", err)
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
		t.Fatal("initialize mixed graph without migrating or borrowing an administrator session", err)
	}
	worker, err := features.DirectoryMixedApply()
	if err != nil {
		t.Fatal("obtain the opt-in direct mixed executor", err)
	}
	return features, worker
}
