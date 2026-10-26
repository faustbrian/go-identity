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
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	"github.com/faustbrian/go-identity/reference"
	organization "github.com/faustbrian/go-organization"
)

func TestReferencePostgresOrganizationTeamsHTTPS(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{organization: true, organizationTeams: true, postgresBaseline: true})
}
func TestReferencePostgresOrganizationTeamsPopulatedUpgradeHTTPS(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{organization: true, organizationTeams: true, organizationUpgrade: true, postgresBaseline: true})
}

type referenceOrganizationTeamsPolicy struct{}

func proveReferenceOrganizationTeamsSelection(t *testing.T, c reference.StoreConfiguration, deps reference.ReferenceDependencies) {
	t.Helper()
	for _, mode := range []string{"no-native-teams", "no-limit", "no-version", "unknown-lifecycle"} {
		candidate, org := c, *c.Organization
		candidate.Organization = &org
		switch mode {
		case "no-native-teams":
			org.Core.Teams = organization.TeamConfig{}
		case "no-limit":
			org.Core.Teams.MaximumMembers = 0
		case "no-version":
			org.Core.Teams.Version = 0
		case "unknown-lifecycle":
			org.Core.Teams.LifecycleVersion = 2
		}
		if graph, err := reference.ComposeStores(candidate, deps); err == nil {
			bounded, stop := context.WithTimeout(context.Background(), time.Second)
			_ = graph.Close(bounded)
			stop()
			t.Fatal("invalid team selection accepted", mode)
		}
	}
}

func (referenceOrganizationTeamsPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	if string(c.Request.Tenant) == otpTenant && c.PolicyRevision == 9 && c.Request.Subject.Kind == authorization.SubjectUser && strings.HasPrefix(string(c.Request.Action), "identity.organization.team.") {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
	}
	return (referenceOrganizationPolicy{}).Decide(ctx, c)
}

// Real signup, captured verification, password sessions and protected native
// owners are retained. The only delivery seam is the existing captured sender.
func proveReferenceOrganizationTeams(t *testing.T, ctx context.Context, f liveStores, c reference.StoreConfiguration, deps reference.ReferenceDependencies, features reference.FeatureSet, workers reference.WorkerSet, workerConfigs []deliverypg.WorkerConfig, client *http.Client, base, origin string, messages <-chan string, cookies []*http.Cookie, csrf string, fresh func(...string) ([]*http.Cookie, string)) {
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
	key := func(value string) identity.IdempotencyKey {
		k, err := identity.NewIdempotencyKey([]byte(value))
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	created, err := port.Create(ctx, organization.CreateOperationRequest{Authentication: owner.auth, IdempotencyKey: key("teams-create-org"), Name: "Team organization", Slug: "reference-teams", CorrelationID: "teams-setup"}, "127.0.0.1")
	if err != nil || created.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("real team organization", err)
	}
	org := created.OrganizationID
	admitted, err := port.AddMember(ctx, organization.AddMemberOperationRequest{Authentication: owner.auth, IdempotencyKey: key("teams-org-member"), OrganizationID: org, OrganizationVersion: 1, UserID: member.user, Role: organization.RoleMember, CorrelationID: "teams-setup"}, "127.0.0.1")
	if err != nil || admitted.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("real team organization admission", err)
	}
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	team := organization.ID(id)
	teamCreated, err := port.CreateTeam(ctx, organization.CreateTeamOperationRequest{Authentication: owner.auth, IdempotencyKey: key("teams-create-team"), OrganizationID: org, OrganizationVersion: 2, TeamID: team, Name: "Consumer team", CorrelationID: "teams-setup"}, "127.0.0.1")
	if err != nil || teamCreated.Receipt.Outcome != identity.CommitOutcomeCommitted || teamCreated.Receipt.Feature.AfterVersion != 3 {
		t.Fatal("guarded native team setup", err)
	}
	call := func(h organizationTestHuman, method, path string, value any, requestKey string) (int, []byte) {
		t.Helper()
		var wire []byte
		if value != nil {
			wire, err = json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(wire)
		}
		r, err := http.NewRequestWithContext(ctx, method, base+path, bytes.NewReader(wire))
		if err != nil {
			t.Fatal(err)
		}
		if value != nil {
			r.Header.Set("Content-Type", "application/json")
		}
		r.Header.Set("Authorization", "Bearer "+h.auth.Bearer.Token())
		if requestKey != "" {
			r.Header.Set("Idempotency-Key", requestKey)
		}
		res, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		out, readErr := io.ReadAll(io.LimitReader(res.Body, 16385))
		closeErr := res.Body.Close()
		if readErr != nil || closeErr != nil || len(out) > 16384 || res.Header.Get("Cache-Control") != "no-store" || len(res.Cookies()) != 0 || bytes.Contains(out, []byte(h.auth.Bearer.Token())) {
			t.Fatal("team response cleanup/custody")
		}
		return res.StatusCode, out
	}
	listMine := func(h organizationTestHuman, count, want int) {
		t.Helper()
		code, wire := call(h, http.MethodGet, "/v1/organization/team/list-mine?organizationID="+string(org)+"&limit=1", nil, "")
		var page organizationhttp.TeamListResponse
		if code != want || want == 200 && (json.Unmarshal(wire, &page) != nil || len(page.Teams) != count || count == 1 && (page.Teams[0].ID != team || page.Teams[0].Name != "Consumer team")) {
			t.Fatal("current subject team page", code, want)
		}
	}
	mutate := func(h organizationTestHuman, path string, body map[string]any, requestKey string) (int, organizationhttp.MutationResponse) {
		t.Helper()
		code, wire := call(h, http.MethodPost, path, body, requestKey)
		var out organizationhttp.MutationResponse
		if json.Unmarshal(wire, &out) != nil {
			t.Fatal("malformed team mutation response")
		}
		return code, out
	}
	add := map[string]any{"organizationID": org, "teamID": team, "userID": member.user, "organizationVersion": 3, "teamVersion": 1, "organizationMemberVersion": 1, "membershipVersion": 0}
	listMine(member, 0, 200)
	if code, out := mutate(member, "/v1/organization/team/member-add", add, "team-nonmanager"); code != 403 || out.Committed || out.Recovery != nil {
		t.Fatal("nonmanager admitted team member", code)
	}
	if _, err := f.pool.Raw().Exec(ctx, `CREATE FUNCTION reference_team_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic team outbox failure'; END $$; CREATE TRIGGER reference_team_fail BEFORE INSERT ON public.identity_outbox_bindings FOR EACH ROW EXECUTE FUNCTION reference_team_fail()`); err != nil {
		t.Fatal(err)
	}
	if code, out := mutate(owner, "/v1/organization/team/member-add", add, "team-rollback"); code == 200 || out.Committed || out.CommitOutcome != "not_committed" {
		t.Fatal("team required-effect rollback", code, out.CommitOutcome)
	}
	if _, err := f.pool.Raw().Exec(ctx, `DROP TRIGGER reference_team_fail ON public.identity_outbox_bindings; DROP FUNCTION reference_team_fail()`); err != nil {
		t.Fatal(err)
	}
	listMine(member, 0, 200)
	code, original := mutate(owner, "/v1/organization/team/member-add", add, "team-first-add")
	if code != 200 || !original.Committed || original.BeforeVersion != 3 || original.AfterVersion != 4 || original.Recovery == nil {
		t.Fatal("real HTTP team admission", code, original.Error)
	}
	if code, again := mutate(owner, "/v1/organization/team/member-add", add, "team-first-add"); code != 200 || !reflect.DeepEqual(again, original) {
		t.Fatal("team original-key recovery", code, again.Error)
	}
	listMine(member, 1, 200)
	memberPath := "/v1/organization/team/member-list?organizationID=" + string(org) + "&teamID=" + string(team) + "&limit=1"
	code, wire := call(member, http.MethodGet, memberPath, nil, "")
	var page organizationhttp.TeamMemberListResponse
	if code != 200 || json.Unmarshal(wire, &page) != nil || len(page.Members) != 1 || page.Members[0].UserID != member.user || page.Members[0].Version != 1 || page.Members[0].OrganizationMemberVersion != 1 || page.TeamVersion != 2 || page.OrganizationVersion != 4 {
		t.Fatal("real current team membership page", code)
	}
	remove := map[string]any{"organizationID": org, "teamID": team, "userID": member.user, "organizationVersion": 4, "teamVersion": 2, "organizationMemberVersion": 1, "membershipVersion": 1}
	code, removed := mutate(owner, "/v1/organization/team/member-remove", remove, "")
	if code != 200 || !removed.Committed || removed.BeforeVersion != 4 || removed.AfterVersion != 5 || removed.Recovery == nil {
		t.Fatal("real HTTP team removal", code, removed.Error)
	}
	if code, again := mutate(owner, "/v1/organization/team/member-remove", remove, ""); code != 200 || !reflect.DeepEqual(again, removed) {
		t.Fatal("natural removal changed original history", code)
	}
	listMine(member, 0, 200)
	if code, _ := call(member, http.MethodGet, memberPath, nil, ""); code != 403 {
		t.Fatal("removed binding retained team read", code)
	}
	left, err := port.RemoveMember(ctx, organization.RemoveMemberOperationRequest{Authentication: owner.auth, OrganizationID: org, OrganizationVersion: 5, UserID: member.user, MemberVersion: 1, CorrelationID: "teams-remove-org-member"}, "127.0.0.1")
	if err != nil || left.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("organization departure", err)
	}
	readmitted, err := port.AddMember(ctx, organization.AddMemberOperationRequest{Authentication: owner.auth, IdempotencyKey: key("teams-readmit"), OrganizationID: org, OrganizationVersion: 6, UserID: member.user, MemberVersion: 2, Role: organization.RoleMember, CorrelationID: "teams-readmit"}, "127.0.0.1")
	if err != nil || readmitted.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("organization readmission", err)
	}
	listMine(member, 0, 200)
	if code, out := mutate(owner, "/v1/organization/team/member-remove", remove, ""); code == 200 || out.Committed {
		t.Fatal("old removal crossed readmission", code)
	}
	add["organizationVersion"], add["teamVersion"], add["organizationMemberVersion"], add["membershipVersion"] = 7, 3, 3, 2
	code, readmission := mutate(owner, "/v1/organization/team/member-add", add, "team-new-admission")
	if code != 200 || !readmission.Committed || readmission.BeforeVersion != 7 || readmission.AfterVersion != 8 {
		t.Fatal("explicit new team admission", code, readmission.Error)
	}
	listMine(member, 1, 200)
	currentCookies, currentCSRF := fresh()
	current := organizationHumanFromSession(t, ctx, sessions, currentCookies, currentCSRF)
	rebuilt, err := reference.ComposeStores(c, deps)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		bounded, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := rebuilt.Close(bounded); err != nil {
			t.Error(err)
		}
	})
	providers, err := reference.ComposeProviders(rebuilt)
	if err != nil {
		t.Fatal(err)
	}
	rebuiltWorkers, err := reference.ComposeWorkers(rebuilt, providers, workerConfigs...)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := reference.ComposeFeatures(rebuilt, providers, rebuiltWorkers)
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
	r := organization.AddTeamMemberOperationRequest{Authentication: current.auth, IdempotencyKey: key("team-new-admission"), OrganizationID: org, TeamID: team, UserID: member.user, OrganizationVersion: 7, TeamVersion: 3, OrganizationMemberVersion: 3, MembershipVersion: 2, CorrelationID: "teams-reconstructed"}
	if out, err := restored.AddTeamMember(ctx, r, "127.0.0.1"); err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted || out.Receipt.Binding.CommandID != readmission.CommandID {
		t.Fatal("fresh-session reconstructed team history", err)
	}
	if code, out := mutate(current, "/v1/organization/team/member-add", add, "team-new-admission"); code != 200 || !reflect.DeepEqual(out, readmission) {
		t.Fatal("fresh-session HTTP team history", code)
	}
	foreign := r
	foreign.Authentication.TenantID = "unconfigured-tenant"
	if out, err := restored.AddTeamMember(ctx, foreign, "127.0.0.1"); err == nil || out.Receipt.Binding.CommandID != "" {
		t.Fatal("team operation crossed graph tenant boundary")
	}
	proveRegistrationSessionLogout(t, ctx, client, base, origin, current.cookies, current.csrf, current.sessionID, f, features)
	if code, out := mutate(current, "/v1/organization/team/member-add", add, "team-new-admission"); code != 403 || out.Committed || out.Recovery != nil {
		t.Fatal("logged-out manager recovered team history", code)
	}
	if out, err := restored.AddTeamMember(ctx, r, "127.0.0.1"); err == nil || out.Receipt.Binding.CommandID != "" {
		t.Fatal("logged-out manager recovered native team history")
	}
	if err := rebuilt.Close(ctx); err != nil {
		t.Fatal(err)
	}
	var unavailable identity.UnavailableError
	if _, err := restored.AddTeamMember(ctx, r, "127.0.0.1"); !errors.As(err, &unavailable) {
		t.Fatal("retained closed team handle reached owner", err)
	}
}
