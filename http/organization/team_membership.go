package organizationhttp

import (
	"context"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	organization "github.com/faustbrian/go-organization"
)

// TeamMemberAdder owns exact original-key team admission, current manager and
// organization membership authority, and atomic native effects. Matching retries
// recover only original history. Calls honor ctx and concurrent requests.
type TeamMemberAdder interface {
	AddTeamMember(context.Context, organization.AddTeamMemberOperationRequest, string) (organization.StoreResult, error)
}

// TeamMemberRemover owns naturally repeated exact-binding removal. Absent rows
// cannot establish success, and readmission never revives old bindings. Current
// native action/query authority remains mandatory. Calls honor ctx/concurrency.
type TeamMemberRemover interface {
	RemoveTeamMember(context.Context, organization.RemoveTeamMemberOperationRequest, string) (organization.StoreResult, error)
}

// MyTeamLister returns current exact-admission teams for the authenticated human,
// never a caller-selected subject or a cached grant. Calls honor ctx/concurrency.
type MyTeamLister interface {
	ListMyTeams(context.Context, organization.TeamReadRequest) (organization.View, error)
}

// TeamMemberLister owns current team/member authorization and bounded primary
// pagination, including organization readmission fencing. Calls honor ctx and
// concurrency; failure must disclose no partial page.
type TeamMemberLister interface {
	ListTeamMembers(context.Context, organization.TeamReadRequest) (organization.View, error)
}

// TeamView is safe team metadata, not a reusable authorization decision.
type TeamView struct {
	ID      organization.ID `json:"id"`
	Name    string          `json:"name"`
	Version uint64          `json:"version"`
}

// TeamListResponse is a current subject's bounded team page. The organization
// epoch is observed native state, not a lease. Cursor is an exclusive locator.
type TeamListResponse struct {
	OrganizationVersion uint64     `json:"organizationVersion"`
	Teams               []TeamView `json:"teams"`
	NextCursor          string     `json:"nextCursor,omitempty"`
}

// TeamMemberView binds a live team membership to its exact organization
// admission. A later readmission cannot reuse this version as authority.
type TeamMemberView struct {
	UserID                    identity.UserID `json:"userID"`
	Version                   uint64          `json:"version"`
	OrganizationMemberVersion uint64          `json:"organizationMemberVersion"`
}

// TeamMemberListResponse exposes a bounded current page and exact native epochs
// for subsequent compare-and-swap requests. It grants no mutation authority.
type TeamMemberListResponse struct {
	OrganizationVersion uint64           `json:"organizationVersion"`
	TeamVersion         uint64           `json:"teamVersion"`
	Members             []TeamMemberView `json:"members"`
	NextCursor          string           `json:"nextCursor,omitempty"`
}

func teamMembershipMutation(op organization.Operation) bool {
	return op == organization.AddTeamMember || op == organization.RemoveTeamMember
}
func teamMembershipRead(op organization.Operation) bool {
	return op == organization.ListMyTeams || op == organization.ListTeamMembers
}
func (in *requestInput) teamAdd() organization.AddTeamMemberOperationRequest {
	return organization.AddTeamMemberOperationRequest{Authentication: in.auth, IdempotencyKey: in.key, OrganizationID: in.org, TeamID: in.team, UserID: in.user, OrganizationVersion: in.orgVersion, TeamVersion: in.teamVersion, OrganizationMemberVersion: in.orgMemberVersion, MembershipVersion: in.memberVersion, CorrelationID: in.correlation}
}
func (in *requestInput) teamRemove() organization.RemoveTeamMemberOperationRequest {
	return organization.RemoveTeamMemberOperationRequest{Authentication: in.auth, OrganizationID: in.org, TeamID: in.team, UserID: in.user, OrganizationVersion: in.orgVersion, TeamVersion: in.teamVersion, OrganizationMemberVersion: in.orgMemberVersion, MembershipVersion: in.memberVersion, CorrelationID: in.correlation}
}
func (in *requestInput) teamRead() organization.TeamReadRequest {
	return organization.TeamReadRequest{Authentication: in.auth, OrganizationID: in.org, TeamID: in.team, Cursor: in.teamCursor, Limit: in.limit, CorrelationID: in.correlation}
}
func decodeTeamQuery(in *requestInput, q url.Values) error {
	for key, values := range q {
		if len(values) != 1 || key != "organizationID" && key != "limit" && key != "cursor" && (in.op != organization.ListTeamMembers || key != "teamID") {
			return identityhttp.ErrInvalidInput
		}
	}
	in.org = organization.ID(q.Get("organizationID"))
	if !boundedID(string(in.org)) || len(q["limit"]) != 1 {
		return identityhttp.ErrInvalidInput
	}
	limit := q.Get("limit")
	n, err := strconv.ParseUint(limit, 10, 32)
	if err != nil || n < 1 || n > 100 || strconv.FormatUint(n, 10) != limit {
		return identityhttp.ErrInvalidInput
	}
	in.limit = uint32(n)
	if values, present := q["cursor"]; present {
		if !boundedID(values[0]) {
			return identityhttp.ErrInvalidInput
		}
		in.teamCursor = values[0]
	}
	if in.op == organization.ListTeamMembers {
		in.team = organization.ID(q.Get("teamID"))
		if !boundedID(string(in.team)) {
			return identityhttp.ErrInvalidInput
		}
	}
	return nil
}
func validTeamReadView(in *requestInput, v organization.View) bool {
	return v.Organization.ID == in.org && v.Organization.TenantID == in.auth.TenantID && v.Organization.Active && v.Organization.Version > 0 && v.Actor.OrganizationID == in.org && v.Actor.TenantID == in.auth.TenantID && v.Actor.UserID == in.actor && validMember(v.Actor)
}
func validTeamMetadata(in *requestInput, team organization.Team) bool {
	if team.OrganizationID != in.org || team.TenantID != in.auth.TenantID || !boundedID(string(team.ID)) || team.Version == 0 || len(team.Name) == 0 || len(team.Name) > 256 || !utf8.ValidString(team.Name) || strings.TrimSpace(team.Name) != team.Name {
		return false
	}
	// Match the native boundedText name contract before exporting its snapshot.
	for _, r := range team.Name {
		if r < ' ' || r == 127 {
			return false
		}
	}
	return true
}
func myTeamsResponse(in *requestInput, v organization.View) (TeamListResponse, error) {
	var zero TeamListResponse
	if !validTeamReadView(in, v) || len(v.Teams) > int(in.limit) {
		return zero, identityhttp.ErrUnavailable
	}
	out := TeamListResponse{OrganizationVersion: v.Organization.Version, Teams: make([]TeamView, len(v.Teams)), NextCursor: v.NextTeamCursor}
	for i, team := range v.Teams {
		if !validTeamMetadata(in, team) || string(team.ID) <= in.teamCursor || i > 0 && v.Teams[i-1].ID >= team.ID {
			return zero, identityhttp.ErrUnavailable
		}
		out.Teams[i] = TeamView{ID: team.ID, Name: team.Name, Version: team.Version}
	}
	if out.NextCursor != "" && (len(v.Teams) != int(in.limit) || len(v.Teams) == 0 || out.NextCursor != string(v.Teams[len(v.Teams)-1].ID)) {
		return zero, identityhttp.ErrUnavailable
	}
	return out, nil
}
func teamMembersResponse(in *requestInput, v organization.View) (TeamMemberListResponse, error) {
	var zero TeamMemberListResponse
	if !validTeamReadView(in, v) || !validTeamMetadata(in, v.Team) || v.Team.ID != in.team || len(v.TeamMembers) > int(in.limit) {
		return zero, identityhttp.ErrUnavailable
	}
	out := TeamMemberListResponse{OrganizationVersion: v.Organization.Version, TeamVersion: v.Team.Version, Members: make([]TeamMemberView, len(v.TeamMembers)), NextCursor: v.NextTeamCursor}
	for i, m := range v.TeamMembers {
		if !m.Active || m.TeamID != in.team || m.OrganizationID != in.org || m.TenantID != in.auth.TenantID || !boundedID(string(m.UserID)) || m.Version == 0 || m.OrganizationMemberVersion == 0 || string(m.UserID) <= in.teamCursor || i > 0 && v.TeamMembers[i-1].UserID >= m.UserID {
			return zero, identityhttp.ErrUnavailable
		}
		out.Members[i] = TeamMemberView{UserID: m.UserID, Version: m.Version, OrganizationMemberVersion: m.OrganizationMemberVersion}
	}
	if out.NextCursor != "" && (len(v.TeamMembers) != int(in.limit) || len(v.TeamMembers) == 0 || out.NextCursor != string(v.TeamMembers[len(v.TeamMembers)-1].UserID)) {
		return zero, identityhttp.ErrUnavailable
	}
	return out, nil
}
