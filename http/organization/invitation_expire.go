package organizationhttp

import organization "github.com/faustbrian/go-organization"

// InvitationExpireResponse projects validated original expiry correlation.
// State describes the committed terminal transition, not a current invitation,
// recipient, membership or delivery read. Errors and unknown outcomes expose no
// successful terminal state; correlation grants no execution/disclosure right.
type InvitationExpireResponse struct {
	MutationResponse
	InvitationID organization.ID `json:"invitationID,omitempty"`
	State        string          `json:"state,omitempty"`
}

func invitationExpireResponse(in *requestInput, result organization.StoreResult, err error) (int, InvitationExpireResponse) {
	status, base := mutationResponse(in, result, err)
	out := InvitationExpireResponse{MutationResponse: base}
	if base.CommandID != "" {
		out.InvitationID = result.InvitationID
	}
	if status == 200 && base.Committed {
		out.State = "expired"
	}
	return status, out
}
