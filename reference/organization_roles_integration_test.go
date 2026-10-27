//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

func TestReferencePostgresOrganizationRolesHTTPS(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{organization: true, organizationRoles: true, postgresBaseline: true})
}
func TestReferencePostgresOrganizationRolesPopulatedUpgradeHTTPS(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{organization: true, organizationRoles: true, organizationUpgrade: true, postgresBaseline: true})
}

func TestReferencePostgresOrganizationDirectBindingsHTTPS(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{organization: true, organizationRoles: true, organizationBindings: true, postgresBaseline: true})
}

func TestReferencePostgresOrganizationDirectBindingsPopulatedUpgradeHTTPS(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{organization: true, organizationRoles: true, organizationBindings: true, organizationUpgrade: true, postgresBaseline: true})
}

func TestReferencePostgresOrganizationTeamRoleBindingsHTTPS(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{organization: true, organizationRoles: true, organizationTeamBindings: true, postgresBaseline: true})
}

func TestReferencePostgresOrganizationTeamRoleBindingsPopulatedUpgradeHTTPS(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{organization: true, organizationRoles: true, organizationTeamBindings: true, organizationUpgrade: true, postgresBaseline: true})
}

type referenceOrganizationRolesPolicy struct{}

func (referenceOrganizationRolesPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if ctx.Err() != nil {
		return authorization.Decision{}, ctx.Err()
	}
	if string(c.Request.Tenant) == otpTenant && c.PolicyRevision == 9 && c.Request.Subject.Kind == authorization.SubjectUser && (strings.HasPrefix(string(c.Request.Action), "identity.organization.role.") || c.Request.Action == authorization.Action(organization.CheckPermission)) {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
	}
	return (referenceOrganizationTeamsPolicy{}).Decide(ctx, c)
}

func proveReferenceOrganizationRolesSelection(t *testing.T, c reference.StoreConfiguration, d reference.ReferenceDependencies) {
	t.Helper()
	modes := []string{"disabled-native", "empty-catalog", "unknown-team-profile", "no-team-lifecycle"}
	if c.Organization.TeamRoleBindings {
		modes = append(modes, "raw-team-bindings-disabled")
	}
	for _, mode := range modes {
		candidate, org := c, *c.Organization
		candidate.Organization = &org
		switch mode {
		case "disabled-native":
			org.Core.DynamicRoles = organization.DynamicRoleConfig{}
		case "empty-catalog":
			org.Core.DynamicRoles.Catalog = nil
		case "unknown-team-profile":
			org.Core.DynamicRoles.TeamBindingsVersion = 2
		case "no-team-lifecycle":
			org.Core.Teams.LifecycleVersion = 0
		case "raw-team-bindings-disabled":
			org.Core.DynamicRoles.TeamBindingsVersion = 0
		}
		if graph, err := reference.ComposeStores(candidate, d); err == nil {
			bounded, cancel := context.WithTimeout(context.Background(), time.Second)
			_ = graph.Close(bounded)
			cancel()
			t.Fatal("roles accepted missing native contract", mode)
		}
	}
}

// Binding setup uses the existing public raw native owner and the identical
// graph configuration, never SQL-created grants or a test policy engine. This
// selected HTTP profile exposes role CRUD, not binding orchestration endpoints.
func referenceRoleBindingSource(t *testing.T, f liveStores, c reference.StoreConfiguration) *organizationpg.Service {
	t.Helper()
	n := *c.Organization
	e := c.Session.Native.Execution
	validation := c.Session.Native.Validation
	validation.Clock = clock.System{}
	profile := sessionpg.IdentifierAdmissionConfig(e.Profile)
	reader, err := sessionpg.NewSelectedSessionService(f.pool, sessionpg.SelectedSessionServiceConfig{Repository: e.Repository, Admission: sessionpg.SelectedSessionAdmissionConfig{SingleFactor: sessionpg.SingleFactorSessionAdmissionConfig{Verified: &profile}}, Validation: validation})
	if err != nil {
		t.Fatal(err)
	}
	lookup := make(map[uint32]session.DigestKey)
	probe, _ := session.ParseToken("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	for _, key := range validation.LookupKeys {
		digest, err := probe.Digest(key, "validation")
		if err != nil {
			t.Fatal(err)
		}
		lookup[digest.KeyVersion] = key
	}
	repository, err := organizationpg.NewRepository(f.pool, n.Repository)
	if err != nil {
		t.Fatal(err)
	}
	participant, err := organizationpg.NewContributor(repository, organizationpg.ContributorConfig{Session: e.Repository, Profile: profile, LookupKeys: lookup, PolicyID: n.Core.PolicyID, PolicyVersion: n.Core.PolicyVersion, MaximumMembers: n.Core.MaximumMembers, MaximumPerUser: n.Core.MaximumPerUser, MaximumPerTenant: n.Core.MaximumPerTenant, Teams: n.Core.Teams, DynamicRoles: n.Core.DynamicRoles})
	if err != nil {
		t.Fatal(err)
	}
	counters, err := riskpg.NewRepository(n.Counters)
	if err != nil {
		t.Fatal(err)
	}
	domain, err := kernel.NewRepository(f.pool, kernel.Config{MaximumDuration: n.Repository.MaximumDuration})
	if err != nil {
		t.Fatal(err)
	}
	audits, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		t.Fatal(err)
	}
	outbox, err := lifecyclepg.NewContributor()
	if err != nil {
		t.Fatal(err)
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{domain, audits, outbox, counters, participant})
	if err != nil {
		t.Fatal(err)
	}
	query := c.OTP.RequestKeys.Policy
	query.Clock = clock.System{}
	coordinatorConfig := c.OTP.Coordinator
	coordinatorConfig.QueryPolicy = &query
	coordinator, err := kernel.NewCoordinator(f.pool, registry, coordinatorConfig)
	if err != nil {
		t.Fatal(err)
	}
	n.Core.Clock = clock.System{}
	source, err := organizationpg.NewService(participant, organizationpg.ServiceConfig{Core: n.Core, Sessions: reader, Authorization: query.Authorization, Risk: counters, Coordinator: coordinator, Registry: registry})
	if err != nil {
		t.Fatal(err)
	}
	return source
}

func proveReferenceOrganizationRoles(t *testing.T, ctx context.Context, f liveStores, c reference.StoreConfiguration, deps reference.ReferenceDependencies, features reference.FeatureSet, workers reference.WorkerSet, workerConfigs []deliverypg.WorkerConfig, client *http.Client, base, origin string, messages <-chan string, cookies []*http.Cookie, csrf string, fresh func(...string) ([]*http.Cookie, string)) {
	t.Helper()
	sessions, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	owner := organizationHumanFromSession(t, ctx, sessions, cookies, csrf)
	member := registerReferenceOrganizationHuman(t, ctx, client, base, origin, features, workers, messages)
	port, err := features.Organizations()
	if err != nil {
		t.Fatal(err)
	}
	rebuild := func() *reference.OrganizationService {
		t.Helper()
		stores, err := reference.ComposeStores(c, deps)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			bounded, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := stores.Close(bounded); err != nil {
				t.Error(err)
			}
		})
		providers, err := reference.ComposeProviders(stores)
		if err != nil {
			t.Fatal(err)
		}
		runners, err := reference.ComposeWorkers(stores, providers, workerConfigs...)
		if err != nil {
			t.Fatal(err)
		}
		selected, err := reference.ComposeFeatures(stores, providers, runners)
		if err != nil {
			t.Fatal(err)
		}
		if err := selected.Initialize(ctx); err != nil {
			t.Fatal(err)
		}
		out, err := selected.Organizations()
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	newID := func() organization.ID {
		id, err := identity.NewSubjectID()
		if err != nil {
			t.Fatal(err)
		}
		return organization.ID(id)
	}
	created, err := port.Create(ctx, organization.CreateOperationRequest{Authentication: owner.auth, IdempotencyKey: teamCRUDKey(t, "roles-org"), Name: "Role consumer", Slug: "role-consumer", CorrelationID: "roles"}, "127.0.0.1")
	if err != nil || created.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("role organization setup", err)
	}
	org := created.OrganizationID
	added, err := port.AddMember(ctx, organization.AddMemberOperationRequest{Authentication: owner.auth, IdempotencyKey: teamCRUDKey(t, "roles-member"), OrganizationID: org, OrganizationVersion: 1, UserID: member.user, Role: organization.RoleMember, CorrelationID: "roles"}, "127.0.0.1")
	if err != nil || added.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("role member setup", err)
	}
	role, team := newID(), newID()
	call := func(h organizationTestHuman, method, path string, body any, key string) (int, []byte) {
		t.Helper()
		var wire []byte
		if body != nil {
			var err error
			wire, err = json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(wire)
		}
		r, err := http.NewRequestWithContext(ctx, method, base+path, bytes.NewReader(wire))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Authorization", "Bearer "+h.auth.Bearer.Token())
		if body != nil {
			r.Header.Set("Content-Type", "application/json")
		}
		if key != "" {
			r.Header.Set("Idempotency-Key", key)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		out, readErr := io.ReadAll(io.LimitReader(response.Body, 16385))
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || len(out) > 16384 || len(response.Cookies()) != 0 || response.Header.Get("Cache-Control") != "no-store" || bytes.Contains(out, []byte(h.auth.Bearer.Token())) {
			t.Fatal("role response custody/cleanup")
		}
		return response.StatusCode, out
	}
	mutate := func(h organizationTestHuman, op string, body any, key string) (int, organizationhttp.MutationResponse) {
		t.Helper()
		code, wire := call(h, http.MethodPost, "/v1/organization/role/"+op, body, key)
		var out organizationhttp.MutationResponse
		if json.Unmarshal(wire, &out) != nil {
			t.Fatal("role mutation response")
		}
		return code, out
	}
	statement := func(effect string) map[string]string {
		return map[string]string{"permissionID": "document-read", "resourceID": "one", "effect": effect}
	}
	create := map[string]any{"organizationID": org, "roleID": role, "organizationVersion": 2, "name": "Reader", "statements": []any{statement("allow")}}
	if code, out := mutate(member, "create", create, "roles-denied"); code != 403 || out.Committed {
		t.Fatal("member created role", code)
	}
	if _, err := f.pool.Raw().Exec(ctx, `CREATE FUNCTION reference_role_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic role outbox failure'; END $$; CREATE TRIGGER reference_role_fail BEFORE INSERT ON public.identity_outbox_bindings FOR EACH ROW EXECUTE FUNCTION reference_role_fail()`); err != nil {
		t.Fatal(err)
	}
	if code, out := mutate(owner, "create", create, "roles-rollback"); code == 200 || out.Committed || out.CommitOutcome != "not_committed" {
		t.Fatal("role required-effect rollback", code, out.CommitOutcome)
	}
	if _, err := f.pool.Raw().Exec(ctx, `DROP TRIGGER reference_role_fail ON public.identity_outbox_bindings; DROP FUNCTION reference_role_fail()`); err != nil {
		t.Fatal(err)
	}
	if page, err := port.ListDynamicRoles(ctx, organization.DynamicRoleReadRequest{Authentication: owner.auth, OrganizationID: org, Limit: 10, CorrelationID: "roles-rollback"}); err != nil || len(page.DynamicRoles) != 0 || page.Organization.Version != 2 {
		t.Fatal("role rollback retained state", err)
	}
	code, original := mutate(owner, "create", create, "roles-create")
	if code != 200 || !original.Committed || original.BeforeVersion != 2 || original.AfterVersion != 3 || original.MemberID != "" || original.Recovery == nil {
		t.Fatal("HTTP role create", code, original.Error)
	}
	if code, out := mutate(owner, "create", create, "roles-create"); code != 200 || !reflect.DeepEqual(out, original) {
		t.Fatal("original role creation", code)
	}
	source := referenceRoleBindingSource(t, f, c)
	commit := func(p organizationpg.PreparedCommand, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		if out, err := source.Execute(ctx, p); err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("native binding setup", err)
		}
	}
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	assign := organization.AssignDynamicRoleOperationRequest{Authentication: owner.auth, IdempotencyKey: teamCRUDKey(t, "roles-direct"), OrganizationID: org, RoleID: role, UserID: member.user, OrganizationVersion: 3, RoleVersion: 1, OrganizationMemberVersion: 1, CorrelationID: "roles-direct"}
	var assigned, revoked organization.StoreResult
	if c.Organization.DirectRoleBindings {
		assigned, err = port.AssignDynamicRole(ctx, assign, "127.0.0.1")
		if err != nil || assigned.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("native facade assignment", err)
		}
		if out, err := port.AssignDynamicRole(ctx, assign, "127.0.0.1"); err != nil || out.Receipt.Binding != assigned.Receipt.Binding {
			t.Fatal("original assignment retry", err)
		}
	} else {
		commit(source.PrepareAssignDynamicRole(ctx, organization.RoleBindingRequest{Authentication: owner.auth, CommandID: id, OrganizationID: org, RoleID: role, UserID: member.user, OrganizationVersion: 3, RoleVersion: 1, OrganizationMemberVersion: 1, CorrelationID: "roles-direct"}, "127.0.0.1"))
	}
	permission := func(epoch uint64, want authorization.Outcome) {
		t.Helper()
		out, err := port.CheckPermission(ctx, organization.PermissionCheckRequest{Authentication: member.auth, OrganizationID: org, OrganizationVersion: epoch, Action: "document.read", ResourceType: "document", ResourceID: "one", CorrelationID: "roles-check"})
		if err != nil || out.Outcome != want {
			t.Fatal("actual role permission", out.Outcome, err)
		}
		if c.HTTPOrganization.PermissionCheck {
			code, wire := call(member, http.MethodGet, "/v1/organization/permission-check?organizationID="+string(org)+"&organizationVersion="+strconv.FormatUint(epoch, 10)+"&action=document.read&resourceType=document&resourceID=one", nil, "")
			var response organizationhttp.PermissionCheckResponse
			if code != 200 || json.Unmarshal(wire, &response) != nil || response.Decision != want.String() || response.OrganizationVersion != epoch {
				t.Fatal("HTTP effective permission differs from native", code)
			}
		}
	}
	permission(4, authorization.Allow)
	id, err = identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	revoke := organization.RevokeDynamicRoleOperationRequest{Authentication: owner.auth, OrganizationID: org, RoleID: role, UserID: member.user, OrganizationVersion: 4, RoleVersion: 1, OrganizationMemberVersion: 1, BindingVersion: 1, CorrelationID: "roles-direct-revoke"}
	if c.Organization.DirectRoleBindings {
		revoked, err = port.RevokeDynamicRole(ctx, revoke, "127.0.0.1")
		if err != nil || revoked.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("native facade revocation", err)
		}
		if out, err := port.RevokeDynamicRole(ctx, revoke, "127.0.0.1"); err != nil || out.Receipt.Binding != revoked.Receipt.Binding {
			t.Fatal("original revocation retry", err)
		}
		changed := revoke
		changed.BindingVersion++
		if _, err := port.RevokeDynamicRole(ctx, changed, "127.0.0.1"); !errors.Is(err, organization.ErrConflict) {
			t.Fatal("changed original revocation accepted", err)
		}
	} else {
		commit(source.PrepareRevokeDynamicRole(ctx, organization.RoleBindingRequest{Authentication: owner.auth, CommandID: id, OrganizationID: org, RoleID: role, UserID: member.user, OrganizationVersion: 4, RoleVersion: 1, OrganizationMemberVersion: 1, BindingVersion: 1, CorrelationID: "roles-direct-revoke"}, "127.0.0.1"))
	}
	permission(5, authorization.Deny)
	if c.Organization.DirectRoleBindings {
		freshCookies, freshCSRF := fresh()
		human := organizationHumanFromSession(t, ctx, sessions, freshCookies, freshCSRF)
		restored := rebuild()
		assignment, revocation := assign, revoke
		assignment.Authentication, revocation.Authentication = human.auth, human.auth
		if out, err := restored.AssignDynamicRole(ctx, assignment, "127.0.0.1"); err != nil || out.Receipt.Binding.CommandID != assigned.Receipt.Binding.CommandID {
			t.Fatal("fresh reconstructed original assignment", err)
		}
		if out, err := restored.RevokeDynamicRole(ctx, revocation, "127.0.0.1"); err != nil || out.Receipt.Binding.CommandID != revoked.Receipt.Binding.CommandID {
			t.Fatal("fresh reconstructed original revocation", err)
		}
		permission(5, authorization.Deny)
	}
	teamCreated, err := port.CreateTeam(ctx, organization.CreateTeamOperationRequest{Authentication: owner.auth, IdempotencyKey: teamCRUDKey(t, "roles-team"), OrganizationID: org, OrganizationVersion: 5, TeamID: team, Name: "Readers", CorrelationID: "roles-team"}, "127.0.0.1")
	if err != nil || teamCreated.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("role team setup", err)
	}
	bound, err := port.AddTeamMember(ctx, organization.AddTeamMemberOperationRequest{Authentication: owner.auth, IdempotencyKey: teamCRUDKey(t, "roles-team-member"), OrganizationID: org, OrganizationVersion: 6, TeamID: team, TeamVersion: 1, UserID: member.user, OrganizationMemberVersion: 1, CorrelationID: "roles-team"}, "127.0.0.1")
	if err != nil || bound.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("role team member", err)
	}
	id, err = identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	teamAssign := organization.AssignTeamDynamicRoleOperationRequest{Authentication: owner.auth, IdempotencyKey: teamCRUDKey(t, "roles-team-binding"), OrganizationID: org, RoleID: role, TeamID: team, OrganizationVersion: 7, RoleVersion: 1, TeamVersion: 2, CorrelationID: "roles-team-binding"}
	var teamAssigned, teamRevoked organization.StoreResult
	if c.Organization.TeamRoleBindings {
		teamAssigned, err = port.AssignTeamDynamicRole(ctx, teamAssign, "127.0.0.1")
		if err != nil || teamAssigned.Receipt.Outcome != identity.CommitOutcomeCommitted || teamAssigned.Receipt.Binding.UserID != owner.user {
			t.Fatal("guarded actual-human team assignment", err)
		}
	} else {
		commit(source.PrepareAssignTeamDynamicRole(ctx, organization.TeamRoleBindingRequest{Authentication: owner.auth, CommandID: id, OrganizationID: org, RoleID: role, TeamID: team, OrganizationVersion: 7, RoleVersion: 1, TeamVersion: 2, CorrelationID: "roles-team-binding"}, "127.0.0.1"))
	}
	permission(8, authorization.Allow)
	roleEpoch := uint64(8)
	teamRevoke := organization.RevokeTeamDynamicRoleOperationRequest{Authentication: owner.auth, OrganizationID: org, RoleID: role, TeamID: team, OrganizationVersion: 8, RoleVersion: 1, TeamVersion: 3, BindingVersion: 1, CorrelationID: "roles-team-revoke"}
	if c.Organization.TeamRoleBindings {
		teamRevoked, err = port.RevokeTeamDynamicRole(ctx, teamRevoke, "127.0.0.1")
		if err != nil || teamRevoked.Receipt.Outcome != identity.CommitOutcomeCommitted || teamRevoked.Receipt.Binding.UserID != owner.user {
			t.Fatal("guarded actual-human team revocation", err)
		}
		permission(9, authorization.Deny)
		if out, err := port.RevokeTeamDynamicRole(ctx, teamRevoke, "127.0.0.1"); err != nil || out.Receipt.Binding != teamRevoked.Receipt.Binding {
			t.Fatal("original team revocation", err)
		}
		freshCookies, freshCSRF := fresh()
		human := organizationHumanFromSession(t, ctx, sessions, freshCookies, freshCSRF)
		restored := rebuild()
		a, r := teamAssign, teamRevoke
		a.Authentication, r.Authentication = human.auth, human.auth
		if out, err := restored.AssignTeamDynamicRole(ctx, a, "127.0.0.1"); err != nil || out.Receipt.Binding != teamAssigned.Receipt.Binding {
			t.Fatal("fresh reconstructed team assignment", err)
		}
		if out, err := restored.RevokeTeamDynamicRole(ctx, r, "127.0.0.1"); err != nil || out.Receipt.Binding != teamRevoked.Receipt.Binding {
			t.Fatal("fresh reconstructed team revocation", err)
		}
		next := teamAssign
		next.IdempotencyKey = teamCRUDKey(t, "roles-team-reassignment")
		next.OrganizationVersion, next.TeamVersion, next.BindingVersion = 9, 4, 2
		if out, err := port.AssignTeamDynamicRole(ctx, next, "127.0.0.1"); err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("team reassignment", err)
		}
		permission(10, authorization.Allow)
		if _, err := port.RevokeTeamDynamicRole(ctx, teamRevoke, "127.0.0.1"); !errors.Is(err, organization.ErrConflict) {
			t.Fatal("old revoke reached new team binding", err)
		}
		if out, err := port.RemoveMember(ctx, organization.RemoveMemberOperationRequest{Authentication: owner.auth, OrganizationID: org, OrganizationVersion: 10, UserID: member.user, MemberVersion: 1, CorrelationID: "roles-team-remove"}, "127.0.0.1"); err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("team member organization removal", err)
		}
		if _, err := port.CheckPermission(ctx, organization.PermissionCheckRequest{Authentication: member.auth, OrganizationID: org, OrganizationVersion: 11, Action: "document.read", ResourceType: "document", ResourceID: "one", CorrelationID: "roles-team-removed"}); !errors.Is(err, organization.ErrForbidden) {
			t.Fatal("removed member retained inherited permission", err)
		}
		if out, err := port.AddMember(ctx, organization.AddMemberOperationRequest{Authentication: owner.auth, IdempotencyKey: teamCRUDKey(t, "roles-team-readmit"), OrganizationID: org, OrganizationVersion: 11, UserID: member.user, MemberVersion: 2, Role: organization.RoleMember, CorrelationID: "roles-team-readmit"}, "127.0.0.1"); err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("organization readmission", err)
		}
		permission(12, authorization.Deny)
		if out, err := port.AddTeamMember(ctx, organization.AddTeamMemberOperationRequest{Authentication: owner.auth, IdempotencyKey: teamCRUDKey(t, "roles-team-new-admission"), OrganizationID: org, OrganizationVersion: 12, TeamID: team, TeamVersion: 5, UserID: member.user, OrganizationMemberVersion: 3, MembershipVersion: 1, CorrelationID: "roles-team-new-admission"}, "127.0.0.1"); err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("explicit new team admission", err)
		}
		permission(13, authorization.Allow)
		if out, err := port.DeleteTeam(ctx, organization.DeleteTeamOperationRequest{Authentication: owner.auth, OrganizationID: org, OrganizationVersion: 13, TeamID: team, TeamVersion: 6, CorrelationID: "roles-team-terminal"}, "127.0.0.1"); err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("terminal team deletion", err)
		}
		permission(14, authorization.Deny)
		if out, err := port.RevokeTeamDynamicRole(ctx, teamRevoke, "127.0.0.1"); err == nil || out.Receipt.Binding.CommandID != "" {
			t.Fatal("terminal team supplied old revocation authority")
		}
		if _, err := port.CreateTeam(ctx, organization.CreateTeamOperationRequest{Authentication: owner.auth, IdempotencyKey: teamCRUDKey(t, "roles-team-revive"), OrganizationID: org, OrganizationVersion: 14, TeamID: team, Name: "Revived team", CorrelationID: "roles-team-revive"}, "127.0.0.1"); !errors.Is(err, organization.ErrConflict) {
			t.Fatal("terminal team identity revived", err)
		}
		roleEpoch = 14
	}
	update := map[string]any{"organizationID": org, "roleID": role, "organizationVersion": roleEpoch, "roleVersion": 1, "name": "Denied reader", "statements": []any{statement("allow"), statement("deny")}}
	code, replaced := mutate(owner, "update", update, "roles-update")
	if code != 200 || !replaced.Committed || replaced.BeforeVersion != roleEpoch || replaced.AfterVersion != roleEpoch+1 {
		t.Fatal("HTTP role replacement", code, replaced.Error)
	}
	permission(roleEpoch+1, authorization.Deny)
	if _, err := port.CheckPermission(ctx, organization.PermissionCheckRequest{Authentication: member.auth, OrganizationID: org, OrganizationVersion: 8, Action: "document.read", ResourceType: "document", ResourceID: "one", CorrelationID: "roles-stale"}); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("stale policy epoch classification", err)
	}
	for _, op := range []string{"get?organizationID=" + string(org) + "&roleID=" + string(role), "list?organizationID=" + string(org) + "&limit=1"} {
		if code, wire := call(owner, http.MethodGet, "/v1/organization/role/"+op, nil, ""); code != 200 || !bytes.Contains(wire, []byte(`"effect":"deny"`)) || !bytes.Contains(wire, []byte(`"organizationVersion":`+strconv.FormatUint(roleEpoch+1, 10))) {
			t.Fatal("current role read", code)
		}
		if code, _ := call(member, http.MethodGet, "/v1/organization/role/"+op, nil, ""); code != 403 {
			t.Fatal("member read manager role metadata", code)
		}
	}
	remove := map[string]any{"organizationID": org, "roleID": role, "organizationVersion": roleEpoch + 1, "roleVersion": 2}
	code, deleted := mutate(owner, "delete", remove, "")
	if code != 200 || !deleted.Committed || deleted.BeforeVersion != roleEpoch+1 || deleted.AfterVersion != roleEpoch+2 || deleted.Recovery == nil {
		t.Fatal("HTTP terminal role delete", code, deleted.Error)
	}
	if code, out := mutate(owner, "delete", remove, ""); code != 200 || !reflect.DeepEqual(out, deleted) {
		t.Fatal("natural role original recovery", code)
	}
	permission(roleEpoch+2, authorization.Deny)
	if _, err := port.GetDynamicRole(ctx, organization.DynamicRoleReadRequest{Authentication: owner.auth, OrganizationID: org, RoleID: role, CorrelationID: "roles-deleted"}); err == nil || errors.Is(err, organization.ErrInvalidInput) {
		t.Fatal("deleted role readable")
	}
	if _, err := port.CreateDynamicRole(ctx, organization.CreateDynamicRoleOperationRequest{Authentication: owner.auth, IdempotencyKey: teamCRUDKey(t, "roles-revive"), OrganizationID: org, OrganizationVersion: roleEpoch + 2, RoleID: role, Name: "Revived", CorrelationID: "roles-revive"}, "127.0.0.1"); !errors.Is(err, organization.ErrConflict) {
		t.Fatal("retired role identity revived", err)
	}
	currentCookies, currentCSRF := fresh()
	current := organizationHumanFromSession(t, ctx, sessions, currentCookies, currentCSRF)
	restored := rebuild()
	if c.Organization.DirectRoleBindings {
		assign.Authentication, revoke.Authentication = current.auth, current.auth
		if out, err := restored.AssignDynamicRole(ctx, assign, "127.0.0.1"); err != nil || out.Receipt.Binding.CommandID != assigned.Receipt.Binding.CommandID {
			t.Fatal("reconstructed original assignment", err)
		}
		// Native readDynamicRole denies retired roles even for original binding
		// recovery. Verify that terminal-role fence rather than weakening it.
		if out, err := restored.RevokeDynamicRole(ctx, revoke, "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) || out.Receipt.Binding.CommandID != "" {
			t.Fatal("retired role revocation history disclosed", err)
		}
	}
	cr := organization.CreateDynamicRoleOperationRequest{Authentication: current.auth, IdempotencyKey: teamCRUDKey(t, "roles-create"), OrganizationID: org, RoleID: role, OrganizationVersion: 2, Name: "Reader", Statements: []organization.RoleStatement{{PermissionID: "document-read", ResourceID: "one", Effect: authorization.Allow}}, CorrelationID: "roles-reconstruction"}
	if out, err := restored.CreateDynamicRole(ctx, cr, "127.0.0.1"); err != nil || out.Receipt.Binding.CommandID != original.CommandID {
		t.Fatal("reconstructed creation original", err)
	}
	ur := organization.UpdateDynamicRoleOperationRequest{Authentication: current.auth, IdempotencyKey: teamCRUDKey(t, "roles-update"), OrganizationID: org, RoleID: role, OrganizationVersion: roleEpoch, RoleVersion: 1, Name: "Denied reader", Statements: []organization.RoleStatement{{PermissionID: "document-read", ResourceID: "one", Effect: authorization.Allow}, {PermissionID: "document-read", ResourceID: "one", Effect: authorization.Deny}}, CorrelationID: "roles-reconstruction"}
	if out, err := restored.UpdateDynamicRole(ctx, ur, "127.0.0.1"); err != nil || out.Receipt.Binding.CommandID != replaced.CommandID {
		t.Fatal("reconstructed replacement original", err)
	}
	dr := organization.DeleteDynamicRoleOperationRequest{Authentication: current.auth, OrganizationID: org, RoleID: role, OrganizationVersion: roleEpoch + 1, RoleVersion: 2, CorrelationID: "roles-reconstruction"}
	if out, err := restored.DeleteDynamicRole(ctx, dr, "127.0.0.1"); err != nil || out.Receipt.Binding.CommandID != deleted.CommandID {
		t.Fatal("reconstructed deletion original", err)
	}
	proveRegistrationSessionLogout(t, ctx, client, base, origin, current.cookies, current.csrf, current.sessionID, f, features)
	if c.Organization.TeamRoleBindings {
		teamAssign.Authentication, teamRevoke.Authentication = current.auth, current.auth
		if out, err := restored.AssignTeamDynamicRole(ctx, teamAssign, "127.0.0.1"); err == nil || out.Receipt.Binding.CommandID != "" {
			t.Fatal("logged-out team assignment history disclosed")
		}
		if out, err := restored.RevokeTeamDynamicRole(ctx, teamRevoke, "127.0.0.1"); err == nil || out.Receipt.Binding.CommandID != "" {
			t.Fatal("logged-out team revocation history disclosed")
		}
	}
	if c.Organization.DirectRoleBindings {
		if out, err := restored.AssignDynamicRole(ctx, assign, "127.0.0.1"); err == nil || out.Receipt.Binding.CommandID != "" {
			t.Fatal("logged-out assignment history disclosed")
		}
		if out, err := restored.RevokeDynamicRole(ctx, revoke, "127.0.0.1"); err == nil || out.Receipt.Binding.CommandID != "" {
			t.Fatal("logged-out revocation history disclosed")
		}
	}
	if code, out := mutate(current, "delete", remove, ""); code != 403 || out.Committed || out.Recovery != nil {
		t.Fatal("logged-out role history disclosed", code)
	}
	if out, err := restored.DeleteDynamicRole(ctx, dr, "127.0.0.1"); err == nil || out.Receipt.Binding.CommandID != "" {
		t.Fatal("logged-out native role history disclosed")
	}
}
