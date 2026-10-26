package organizationhttp

import (
	"errors"
	"unicode/utf8"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	organization "github.com/faustbrian/go-organization"
)

// CommandScope is explicit safe original-command correlation, never permission
// to disclose or execute. Persist it for direct current-authorized recovery;
// no separate HTTP recovery endpoint is selected by this finite feature.
type CommandScope struct {
	CommandID     identity.CommandID        `json:"commandID"`
	TenantID      identity.TenantID         `json:"tenantID"`
	UserID        identity.UserID           `json:"userID"`
	ActorID       identity.ActorID          `json:"actorID"`
	ActorKind     authorization.SubjectKind `json:"actorKind"`
	OperationID   string                    `json:"operationID"`
	RecordID      string                    `json:"recordID"`
	PolicyID      string                    `json:"policyID"`
	PolicyVersion uint64                    `json:"policyVersion"`
	SchemaID      string                    `json:"schemaID"`
	SchemaVersion uint32                    `json:"schemaVersion"`
	CorrelationID string                    `json:"correlationID"`
}

// MutationResponse retains the native outcome even alongside an error. Only an
// actual validated committed receipt sets Committed. Unknown never means safe
// retry execution; keep the original request key/input or direct recovery scope.
type MutationResponse struct {
	Committed      bool               `json:"committed"`
	CommitOutcome  string             `json:"commitOutcome"`
	CommandID      identity.CommandID `json:"commandID,omitempty"`
	OrganizationID organization.ID    `json:"organizationID,omitempty"`
	MemberID       identity.UserID    `json:"memberID,omitempty"`
	BeforeVersion  uint64             `json:"beforeVersion,omitempty"`
	AfterVersion   uint64             `json:"afterVersion,omitempty"`
	Recovery       *CommandScope      `json:"recovery,omitempty"`
	Error          string             `json:"error,omitempty"`
}

// OrganizationView discloses selected organization metadata, no authority vector.
type OrganizationView struct {
	ID      organization.ID `json:"id"`
	Name    string          `json:"name"`
	Slug    string          `json:"slug"`
	Version uint64          `json:"version"`
}

// MemberView contains current safe membership metadata, never reusable authority.
type MemberView struct {
	UserID  identity.UserID   `json:"userID"`
	Role    organization.Role `json:"role"`
	Version uint64            `json:"version"`
}

// ReadResponse is the explicit authorized get/page projection. A list always
// returns Members (including an empty array) and an exclusive optional cursor.
type ReadResponse struct {
	Organization OrganizationView `json:"organization"`
	Membership   MemberView       `json:"membership"`
	Members      *[]MemberView    `json:"members,omitempty"`
	NextCursor   identity.UserID  `json:"nextCursor,omitempty"`
}

func mutationResponse(in *requestInput, result organization.StoreResult, err error) (int, MutationResponse) {
	out := MutationResponse{CommitOutcome: "none"}
	status := 200
	if err != nil {
		status, out.Error = domainFailure(err)
	}
	r := result.Receipt
	b := r.Binding
	if b == (identity.CommandBinding{}) {
		if err == nil {
			status, out.Error = 503, "unavailable"
		}
		return status, out
	}
	target := in.user
	if in.op == organization.Create || in.op == organization.Update || in.op == organization.InvitationCancel || in.op == organization.InvitationReject {
		target = in.actor
	}
	if in.op == organization.InvitationResend {
		// The recipient is fixed by the exact native invitation, not a new
		// transport selector. Validate its native receipt without inventing one.
		target = result.MemberID
	}
	validRecord := result.OrganizationID == organization.ID(b.RecordID) && (in.op == organization.Create || organization.ID(b.RecordID) == in.org)
	if in.op == organization.InvitationSend {
		validRecord = boundedID(string(result.InvitationID)) && result.InvitationID == organization.ID(b.RecordID) && result.OrganizationID == in.org
	}
	if in.op == organization.InvitationAccept {
		validRecord = result.InvitationID == in.invitationID && b.RecordID == string(in.invitationID) && result.OrganizationID == in.org && b.CommandID == in.commandID && b.CorrelationID == in.correlation
	}
	if in.op == organization.InvitationResend || in.op == organization.InvitationCancel || in.op == organization.InvitationReject {
		validRecord = result.InvitationID == in.invitationID && b.RecordID == string(in.invitationID) && result.OrganizationID == in.org
	}
	if b.ValidateFor(in.op.Descriptor()) != nil || b.TenantID != in.auth.TenantID || b.ActorKind != authorization.SubjectUser || b.ActorID != identity.ActorID(in.actor) || b.UserID != target || result.MemberID != b.UserID || !validRecord {
		return 503, MutationResponse{CommitOutcome: "none", Error: "unavailable"}
	}
	out.CommandID, out.OrganizationID, out.MemberID = b.CommandID, result.OrganizationID, result.MemberID
	if in.op == organization.InvitationSend || in.op == organization.InvitationResend || in.op == organization.InvitationCancel || in.op == organization.InvitationReject {
		out.MemberID = "" // These invitation transitions do not create membership.
	}
	out.Recovery = &CommandScope{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID, PolicyID: b.PolicyID, PolicyVersion: b.PolicyVersion, SchemaID: b.SchemaID, SchemaVersion: b.SchemaVersion, CorrelationID: b.CorrelationID}
	if r.Outcome == identity.CommitOutcomeInvalid {
		if err == nil {
			status, out.Error = 503, "unavailable"
		}
		return status, out
	}
	if r.Validate() != nil || r.Feature == nil || r.Feature.Operation != in.op.Descriptor() {
		out.CommitOutcome, out.Error = "unknown", "unavailable"
		return 503, out
	}
	expectedBefore := in.orgVersion
	if in.op == organization.Create || in.op == organization.InvitationSend {
		expectedBefore = 0
	}
	if in.op == organization.InvitationAccept || in.op == organization.InvitationResend || in.op == organization.InvitationCancel || in.op == organization.InvitationReject {
		expectedBefore = in.invitationVersion
	}
	if r.Outcome == identity.CommitOutcomeCommitted && (r.Feature.BeforeVersion != expectedBefore || r.Feature.AfterVersion != expectedBefore+1) {
		out.CommitOutcome, out.Error = "unknown", "unavailable"
		return 503, out
	}
	switch r.Outcome {
	case identity.CommitOutcomeCommitted:
		out.CommitOutcome, out.Committed = "committed", true
		out.BeforeVersion, out.AfterVersion = r.Feature.BeforeVersion, r.Feature.AfterVersion
	case identity.CommitOutcomeNotCommitted:
		out.CommitOutcome = "not_committed"
		if err == nil {
			status, out.Error = 503, "unavailable"
		}
	case identity.CommitOutcomeUnknown:
		out.CommitOutcome = "unknown"
		status, out.Error = 503, "unavailable"
	case identity.CommitOutcomeConflict:
		out.CommitOutcome = "conflict"
		status, out.Error = 409, "conflict"
	case identity.CommitOutcomeInProgress:
		out.CommitOutcome = "in_progress"
		status, out.Error = 409, "in_progress"
	default:
		return 503, MutationResponse{CommitOutcome: "none", Error: "unavailable"}
	}
	return status, out
}
func domainFailure(err error) (int, string) {
	switch {
	case errors.Is(err, organization.ErrInvalidInput):
		return 400, "invalid_request"
	case errors.Is(err, organization.ErrForbidden):
		return 403, "forbidden"
	case errors.Is(err, organization.ErrLastOwner):
		return 409, "last_owner"
	case errors.Is(err, organization.ErrConflict):
		return 409, "conflict"
	case errors.Is(err, organization.ErrLimit):
		return 409, "limit_exceeded"
	default:
		return 503, "unavailable"
	}
}
func readResponse(in *requestInput, v organization.View) (ReadResponse, error) {
	var out ReadResponse
	if v.Organization.TenantID != in.auth.TenantID || v.Organization.ID != in.org || !v.Organization.Active || v.Organization.Version == 0 || len(v.Organization.Name) == 0 || len(v.Organization.Name) > 256 || !utf8.ValidString(v.Organization.Name) || len(v.Organization.Slug) == 0 || len(v.Organization.Slug) > 63 || !utf8.ValidString(v.Organization.Slug) || v.Actor.TenantID != in.auth.TenantID || v.Actor.OrganizationID != in.org || v.Actor.UserID != in.actor || !validMember(v.Actor) {
		return out, identityhttp.ErrUnavailable
	}
	out.Organization = OrganizationView{ID: v.Organization.ID, Name: v.Organization.Name, Slug: v.Organization.Slug, Version: v.Organization.Version}
	out.Membership = MemberView{UserID: v.Actor.UserID, Role: v.Actor.Role, Version: v.Actor.Version}
	if in.op == organization.ListMembers {
		if len(v.Members) > int(in.limit) || v.NextCursor != "" && !boundedID(string(v.NextCursor)) {
			return ReadResponse{}, identityhttp.ErrUnavailable
		}
		members := make([]MemberView, len(v.Members))
		previous := in.cursor
		for i, m := range v.Members {
			if !validMember(m) || m.TenantID != in.auth.TenantID || m.OrganizationID != in.org || string(m.UserID) <= string(previous) {
				return ReadResponse{}, identityhttp.ErrUnavailable
			}
			previous = m.UserID
			members[i] = MemberView{UserID: m.UserID, Role: m.Role, Version: m.Version}
		}
		if v.NextCursor != "" && (len(members) == 0 || v.NextCursor != previous) {
			return ReadResponse{}, identityhttp.ErrUnavailable
		}
		out.Members, out.NextCursor = &members, v.NextCursor
	}
	return out, nil
}
func validMember(m organization.Member) bool {
	return m.Active && m.Version > 0 && m.Role.Valid() && boundedID(string(m.UserID))
}
