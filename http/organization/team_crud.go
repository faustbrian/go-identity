package organizationhttp

import (
	"context"

	organization "github.com/faustbrian/go-organization"
)

// TeamCreator owns original-key creation of an empty team with the requested
// canonical ID, exact organization epoch and name. Current manager/session,
// team-write/query policy, quotas and atomic effects remain native decisions.
// Matching retries recover original history; calls honor ctx and concurrency.
type TeamCreator interface {
	CreateTeam(context.Context, organization.CreateTeamOperationRequest, string) (organization.StoreResult, error)
}

// TeamUpdater owns original-key bounded-name replacement at exact native
// organization/team epochs. It preserves bindings and current authority;
// unknown outcomes never authorize reexecution. Calls honor ctx/concurrency.
type TeamUpdater interface {
	UpdateTeam(context.Context, organization.UpdateTeamOperationRequest, string) (organization.StoreResult, error)
}

// TeamDeleter owns naturally repeated exact-version terminal team deletion.
// Only actual original effects and receipts establish prior success; missing
// rows do not. Retired IDs and bindings never revive. Calls honor ctx and
// concurrent requests, retaining current manager/action/query/session authority.
type TeamDeleter interface {
	DeleteTeam(context.Context, organization.DeleteTeamOperationRequest, string) (organization.StoreResult, error)
}

// TeamLister owns current manager-only bounded team pages, actual team-read
// policy and primary/scoped-authority fences. Failures disclose no partial page.
// Calls honor ctx/concurrency; returned epochs never grant mutation authority.
type TeamLister interface {
	ListTeams(context.Context, organization.TeamReadRequest) (organization.View, error)
}

func teamCRUDMutation(op organization.Operation) bool {
	return op == organization.CreateTeam || op == organization.UpdateTeam || op == organization.DeleteTeam
}
func teamCRUDKeyed(op organization.Operation) bool {
	return op == organization.CreateTeam || op == organization.UpdateTeam
}
func (in *requestInput) createTeam() organization.CreateTeamOperationRequest {
	return organization.CreateTeamOperationRequest{Authentication: in.auth, IdempotencyKey: in.key, OrganizationID: in.org, TeamID: in.team, OrganizationVersion: in.orgVersion, Name: in.name, CorrelationID: in.correlation}
}
func (in *requestInput) updateTeam() organization.UpdateTeamOperationRequest {
	return organization.UpdateTeamOperationRequest{Authentication: in.auth, IdempotencyKey: in.key, OrganizationID: in.org, TeamID: in.team, OrganizationVersion: in.orgVersion, TeamVersion: in.teamVersion, Name: in.name, CorrelationID: in.correlation}
}
func (in *requestInput) deleteTeam() organization.DeleteTeamOperationRequest {
	return organization.DeleteTeamOperationRequest{Authentication: in.auth, OrganizationID: in.org, TeamID: in.team, OrganizationVersion: in.orgVersion, TeamVersion: in.teamVersion, CorrelationID: in.correlation}
}
