package organizationhttp

import organization "github.com/faustbrian/go-organization"

// InvitationCancelResponse projects only validated original cancellation
// metadata. State describes the committed terminal transition, not a current
// recipient or membership read. Errors/unknown outcomes expose no successful
// state; safe recovery correlation is not execution or disclosure authority.
type InvitationCancelResponse struct {
	MutationResponse
	InvitationID organization.ID `json:"invitationID,omitempty"`
	State        string          `json:"state,omitempty"`
}

func invitationCancelResponse(in *requestInput, result organization.StoreResult, err error) (int, InvitationCancelResponse) {
	status, base := mutationResponse(in, result, err)
	out := InvitationCancelResponse{MutationResponse: base}
	if base.CommandID != "" {
		out.InvitationID = result.InvitationID
	}
	if status == 200 && base.Committed {
		out.State = "cancelled"
	}
	return status, out
}
