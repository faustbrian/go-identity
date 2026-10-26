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
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	"github.com/faustbrian/go-identity/reference"
	organization "github.com/faustbrian/go-organization"
)

func TestReferencePostgresOrganizationTeamCRUDHTTPS(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{organization: true, organizationTeams: true, organizationTeamCRUD: true, postgresBaseline: true})
}

func TestReferencePostgresOrganizationTeamCRUDPopulatedUpgradeHTTPS(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{organization: true, organizationTeams: true, organizationTeamCRUD: true, organizationUpgrade: true, postgresBaseline: true})
}

func proveReferenceOrganizationTeamCRUDSelection(t *testing.T, c reference.StoreConfiguration, deps reference.ReferenceDependencies) {
	t.Helper()
	for _, mode := range []string{"missing-teams", "missing-lifecycle", "unknown-lifecycle"} {
		candidate, org := c, *c.Organization
		candidate.Organization = &org
		switch mode {
		case "missing-teams":
			org.Core.Teams = organization.TeamConfig{}
		case "missing-lifecycle":
			org.Core.Teams.LifecycleVersion = 0
		case "unknown-lifecycle":
			org.Core.Teams.LifecycleVersion = 2
		}
		if graph, err := reference.ComposeStores(candidate, deps); err == nil {
			bounded, cancel := context.WithTimeout(context.Background(), time.Second)
			_ = graph.Close(bounded)
			cancel()
			t.Fatal("team CRUD selected without its native policy", mode)
		}
	}
}

// The populated upgrade starts from real membership-only team history, not
// merely an identity-only database. Both the active binding and original
// creation receipt must survive installation of the native lifecycle suffix.
type referenceTeamUpgrade struct {
	request organization.CreateTeamOperationRequest
	created organization.StoreResult
}

func prepareReferenceTeamUpgrade(t *testing.T, ctx context.Context, features reference.FeatureSet, cookies []*http.Cookie, csrf string) referenceTeamUpgrade {
	t.Helper()
	sessions, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	human := organizationHumanFromSession(t, ctx, sessions, cookies, csrf)
	port, err := features.Organizations()
	if err != nil {
		t.Fatal(err)
	}
	org, err := port.Create(ctx, organization.CreateOperationRequest{Authentication: human.auth, IdempotencyKey: teamCRUDKey(t, "team-upgrade-org"), Name: "Installed teams", Slug: "installed-team-history", CorrelationID: "team-upgrade"}, "127.0.0.1")
	if err != nil || org.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("populated organization setup", err)
	}
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	r := organization.CreateTeamOperationRequest{Authentication: human.auth, IdempotencyKey: teamCRUDKey(t, "team-upgrade-create"), OrganizationID: org.OrganizationID, OrganizationVersion: 1, TeamID: organization.ID(id), Name: "Installed team", CorrelationID: "team-upgrade"}
	created, err := port.CreateTeam(ctx, r, "127.0.0.1")
	if err != nil || created.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("populated membership-only team", err)
	}
	bound, err := port.AddTeamMember(ctx, organization.AddTeamMemberOperationRequest{Authentication: human.auth, IdempotencyKey: teamCRUDKey(t, "team-upgrade-bind"), OrganizationID: r.OrganizationID, TeamID: r.TeamID, UserID: human.user, OrganizationVersion: 2, TeamVersion: 1, OrganizationMemberVersion: 1, CorrelationID: "team-upgrade"}, "127.0.0.1")
	if err != nil || bound.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("populated active team binding", err)
	}
	return referenceTeamUpgrade{request: r, created: created}
}

func (u referenceTeamUpgrade) prove(t *testing.T, ctx context.Context, features reference.FeatureSet) {
	t.Helper()
	port, err := features.Organizations()
	if err != nil {
		t.Fatal(err)
	}
	read := organization.TeamReadRequest{Authentication: u.request.Authentication, OrganizationID: u.request.OrganizationID, TeamID: u.request.TeamID, CorrelationID: "team-upgrade-check"}
	view, err := port.GetTeam(ctx, read)
	if err != nil || view.Team.ID != u.request.TeamID || view.Team.Name != u.request.Name || view.Team.Version != 2 || view.Organization.Version != 3 {
		t.Fatal("lifecycle upgrade changed installed team", err)
	}
	read.TeamID, read.Limit = "", 10
	page, err := port.ListMyTeams(ctx, read)
	if err != nil || len(page.Teams) != 1 || page.Teams[0].ID != u.request.TeamID {
		t.Fatal("lifecycle upgrade lost active binding", err)
	}
	original, err := port.CreateTeam(ctx, u.request, "127.0.0.1")
	if err != nil || !reflect.DeepEqual(original, u.created) {
		t.Fatal("lifecycle upgrade rewrote original history", err)
	}
}

func teamCRUDKey(t *testing.T, value string) identity.IdempotencyKey {
	t.Helper()
	k, err := identity.NewIdempotencyKey([]byte(value))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func proveReferenceOrganizationTeamCRUD(t *testing.T, ctx context.Context, f liveStores, c reference.StoreConfiguration, deps reference.ReferenceDependencies, features reference.FeatureSet, workers reference.WorkerSet, workerConfigs []deliverypg.WorkerConfig, client *http.Client, base, origin string, messages <-chan string, cookies []*http.Cookie, csrf string, fresh func(...string) ([]*http.Cookie, string)) {
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
	created, err := port.Create(ctx, organization.CreateOperationRequest{Authentication: owner.auth, IdempotencyKey: teamCRUDKey(t, "crud-org"), Name: "Team lifecycle", Slug: "team-lifecycle", CorrelationID: "team-crud"}, "127.0.0.1")
	if err != nil || created.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("CRUD organization setup", err)
	}
	org := created.OrganizationID
	added, err := port.AddMember(ctx, organization.AddMemberOperationRequest{Authentication: owner.auth, IdempotencyKey: teamCRUDKey(t, "crud-member"), OrganizationID: org, OrganizationVersion: 1, UserID: member.user, Role: organization.RoleMember, CorrelationID: "team-crud"}, "127.0.0.1")
	if err != nil || added.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("CRUD member setup", err)
	}
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	team := organization.ID(id)
	call := func(h organizationTestHuman, method, path string, body any, key string) (int, []byte) {
		t.Helper()
		var wire []byte
		if body != nil {
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
		if readErr != nil || closeErr != nil || len(out) > 16384 || response.Header.Get("Cache-Control") != "no-store" || len(response.Cookies()) != 0 || bytes.Contains(out, []byte(h.auth.Bearer.Token())) {
			t.Fatal("team CRUD response custody/cleanup")
		}
		return response.StatusCode, out
	}
	mutate := func(h organizationTestHuman, operation string, body any, key string) (int, organizationhttp.MutationResponse) {
		t.Helper()
		code, wire := call(h, http.MethodPost, "/v1/organization/team/"+operation, body, key)
		var out organizationhttp.MutationResponse
		if json.Unmarshal(wire, &out) != nil {
			t.Fatal("team CRUD mutation schema")
		}
		return code, out
	}
	create := map[string]any{"organizationID": org, "teamID": team, "organizationVersion": 2, "name": "First name"}
	if code, out := mutate(member, "create", create, "crud-denied"); code != 403 || out.Committed || out.Recovery != nil {
		t.Fatal("nonmanager created team", code)
	}
	if _, err := f.pool.Raw().Exec(ctx, `CREATE FUNCTION reference_team_crud_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic team CRUD outbox failure'; END $$; CREATE TRIGGER reference_team_crud_fail BEFORE INSERT ON public.identity_outbox_bindings FOR EACH ROW EXECUTE FUNCTION reference_team_crud_fail()`); err != nil {
		t.Fatal(err)
	}
	if code, out := mutate(owner, "create", create, "crud-rollback"); code == 200 || out.Committed || out.CommitOutcome != "not_committed" {
		t.Fatal("team creation required-effect rollback", code, out.CommitOutcome)
	}
	if _, err := f.pool.Raw().Exec(ctx, `DROP TRIGGER reference_team_crud_fail ON public.identity_outbox_bindings; DROP FUNCTION reference_team_crud_fail()`); err != nil {
		t.Fatal(err)
	}
	if page, err := port.ListTeams(ctx, organization.TeamReadRequest{Authentication: owner.auth, OrganizationID: org, Limit: 10, CorrelationID: "team-crud-rollback"}); err != nil || len(page.Teams) != 0 || page.Organization.Version != 2 {
		t.Fatal("rolled-back team creation retained state", err)
	}
	code, original := mutate(owner, "create", create, "crud-create")
	if code != 200 || !original.Committed || original.BeforeVersion != 2 || original.AfterVersion != 3 || original.MemberID != "" || original.Recovery == nil {
		t.Fatal("HTTP team create", code, original.Error)
	}
	if code, out := mutate(owner, "create", create, "crud-create"); code != 200 || !reflect.DeepEqual(out, original) {
		t.Fatal("HTTP team creation recovery", code)
	}
	bound, err := port.AddTeamMember(ctx, organization.AddTeamMemberOperationRequest{Authentication: owner.auth, IdempotencyKey: teamCRUDKey(t, "crud-bind"), OrganizationID: org, TeamID: team, UserID: member.user, OrganizationVersion: 3, TeamVersion: 1, OrganizationMemberVersion: 1, CorrelationID: "team-crud"}, "127.0.0.1")
	if err != nil || bound.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("real native member binding", err)
	}
	update := map[string]any{"organizationID": org, "teamID": team, "organizationVersion": 4, "teamVersion": 2, "name": "Renamed team"}
	if code, out := mutate(member, "update", update, "crud-denied-rename"); code != 403 || out.Committed || out.Recovery != nil {
		t.Fatal("nonmanager renamed team", code)
	}
	stale := map[string]any{"organizationID": org, "teamID": team, "organizationVersion": 4, "teamVersion": 1, "name": "Wrong version"}
	if code, out := mutate(owner, "update", stale, "crud-stale"); code != 409 || out.Committed {
		t.Fatal("stale team version renamed team", code)
	}
	code, renamed := mutate(owner, "update", update, "crud-rename")
	if code != 200 || !renamed.Committed || renamed.BeforeVersion != 4 || renamed.AfterVersion != 5 || renamed.MemberID != "" {
		t.Fatal("HTTP team rename", code, renamed.Error)
	}
	for _, who := range []struct {
		human organizationTestHuman
		route string
	}{{owner, "list"}, {member, "list-mine"}} {
		code, wire := call(who.human, http.MethodGet, "/v1/organization/team/"+who.route+"?organizationID="+string(org)+"&limit=1", nil, "")
		var page organizationhttp.TeamListResponse
		if code != 200 || json.Unmarshal(wire, &page) != nil || len(page.Teams) != 1 || page.Teams[0].ID != team || page.Teams[0].Name != "Renamed team" || page.Teams[0].Version != 3 || page.OrganizationVersion != 5 {
			t.Fatal("team rename projection/binding preservation", who.route, code)
		}
	}
	if code, _ := call(member, http.MethodGet, "/v1/organization/team/list?organizationID="+string(org)+"&limit=1", nil, ""); code != 403 {
		t.Fatal("nonmanager listed all teams", code)
	}
	remove := map[string]any{"organizationID": org, "teamID": team, "organizationVersion": 5, "teamVersion": 3}
	if code, out := mutate(member, "delete", remove, ""); code != 403 || out.Committed || out.Recovery != nil {
		t.Fatal("nonmanager deleted team", code)
	}
	code, deleted := mutate(owner, "delete", remove, "")
	if code != 200 || !deleted.Committed || deleted.BeforeVersion != 5 || deleted.AfterVersion != 6 || deleted.Recovery == nil || deleted.MemberID != "" {
		t.Fatal("HTTP terminal team deletion", code, deleted.Error)
	}
	if code, out := mutate(owner, "delete", remove, ""); code != 200 || !reflect.DeepEqual(out, deleted) {
		t.Fatal("natural team deletion recovery", code)
	}
	read := organization.TeamReadRequest{Authentication: owner.auth, OrganizationID: org, TeamID: team, CorrelationID: "team-crud"}
	if _, err := port.GetTeam(ctx, read); err == nil {
		t.Fatal("deleted team remained readable")
	}
	if page, err := port.ListMyTeams(ctx, organization.TeamReadRequest{Authentication: member.auth, OrganizationID: org, Limit: 10, CorrelationID: "team-crud"}); err != nil || len(page.Teams) != 0 {
		t.Fatal("terminal deletion retained active binding", err)
	}
	if _, err := port.CreateTeam(ctx, organization.CreateTeamOperationRequest{Authentication: owner.auth, IdempotencyKey: teamCRUDKey(t, "crud-reuse"), OrganizationID: org, OrganizationVersion: 6, TeamID: team, Name: "Revived", CorrelationID: "team-crud"}, "127.0.0.1"); !errors.Is(err, organization.ErrConflict) {
		t.Fatal("retired team ID reused", err)
	}
	currentCookies, currentCSRF := fresh()
	current := organizationHumanFromSession(t, ctx, sessions, currentCookies, currentCSRF)
	rebuilt, err := reference.ComposeStores(c, deps)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		bounded, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := rebuilt.Close(bounded); err != nil {
			t.Error(err)
		}
	})
	providers, err := reference.ComposeProviders(rebuilt)
	if err != nil {
		t.Fatal(err)
	}
	runners, err := reference.ComposeWorkers(rebuilt, providers, workerConfigs...)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := reference.ComposeFeatures(rebuilt, providers, runners)
	if err != nil {
		t.Fatal(err)
	}
	if err := selected.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	restored, err := selected.Organizations()
	if err != nil {
		t.Fatal(err)
	}
	u := organization.UpdateTeamOperationRequest{Authentication: current.auth, IdempotencyKey: teamCRUDKey(t, "crud-rename"), OrganizationID: org, TeamID: team, OrganizationVersion: 4, TeamVersion: 2, Name: "Renamed team", CorrelationID: "team-crud-reconstructed"}
	foreign := u
	foreign.Authentication.TenantID = "unconfigured-tenant"
	if out, err := restored.UpdateTeam(ctx, foreign, "127.0.0.1"); err == nil || out.Receipt.Binding.CommandID != "" {
		t.Fatal("team history crossed configured tenant boundary")
	}
	originalRename, err := restored.UpdateTeam(ctx, u, "127.0.0.1")
	if err != nil || originalRename.Receipt.Binding.CommandID != renamed.CommandID || originalRename.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("fresh reconstructed rename history", err)
	}
	d := organization.DeleteTeamOperationRequest{Authentication: current.auth, OrganizationID: org, TeamID: team, OrganizationVersion: 5, TeamVersion: 3, CorrelationID: "team-crud-reconstructed"}
	if out, err := restored.DeleteTeam(ctx, d, "127.0.0.1"); err != nil || out.Receipt.Binding.CommandID != deleted.CommandID || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("fresh reconstructed deletion history", err)
	}
	if code, out := mutate(current, "delete", remove, ""); code != 200 || !reflect.DeepEqual(out, deleted) {
		t.Fatal("fresh-session HTTP deletion history", code)
	}
	proveRegistrationSessionLogout(t, ctx, client, base, origin, current.cookies, current.csrf, current.sessionID, f, features)
	if code, out := mutate(current, "delete", remove, ""); code != 403 || out.Committed || out.Recovery != nil {
		t.Fatal("logged-out team history disclosed", code)
	}
	if out, err := restored.DeleteTeam(ctx, d, "127.0.0.1"); err == nil || out.Receipt.Binding.CommandID != "" {
		t.Fatal("logged-out native team history disclosed")
	}
	if err := rebuilt.Close(ctx); err != nil {
		t.Fatal(err)
	}
	var unavailable identity.UnavailableError
	if _, err := restored.UpdateTeam(ctx, u, "127.0.0.1"); !errors.As(err, &unavailable) {
		t.Fatal("closed team lifecycle handle reached owner", err)
	}
}
