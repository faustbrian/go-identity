package organizationhttp

import organization "github.com/faustbrian/go-organization"

// InvitationRejectResponse projects validated original recipient-rejection
// metadata, not current membership or delivery. State is present only for a
// successful committed terminal transition; recovery metadata grants no authority.
type InvitationRejectResponse struct {
	MutationResponse
	InvitationID organization.ID `json:"invitationID,omitempty"`
	State        string          `json:"state,omitempty"`
}

func invitationRejectResponse(in *requestInput, result organization.StoreResult, err error) (int, InvitationRejectResponse) {
	status, base := mutationResponse(in, result, err)
	out := InvitationRejectResponse{MutationResponse: base}
	if base.CommandID != "" {
		out.InvitationID = result.InvitationID
	}
	if status == 200 && base.Committed {
		out.State = "rejected"
	}
	return status, out
}
