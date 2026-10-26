package organizationhttp

import organization "github.com/faustbrian/go-organization"

// InvitationResendResponse retains the exact original native command outcome
// independently of its authorized original delivery observation. No invitation
// proof, delivery effect ID, recipient address or latest invitation is exported.
// Queued/accepted are not confirmed delivery; unknown never permits redispatch.
type InvitationResendResponse struct {
	MutationResponse
	InvitationID  organization.ID `json:"invitationID,omitempty"`
	DeliveryState string          `json:"deliveryState,omitempty"`
}

func invitationResendResponse(in *requestInput, result organization.InvitationResendOperationResult, err error) (int, InvitationResendResponse) {
	status, base := mutationResponse(in, result.StoreResult, err)
	out := InvitationResendResponse{MutationResponse: base}
	if base.CommandID == "" {
		return status, out
	}
	out.InvitationID = result.InvitationID
	if status != 200 || !base.Committed {
		return status, out
	}
	state := deliveryStateName(result.DeliveryState)
	if state == "" {
		out.Error = "unavailable"
		return 503, out
	}
	out.DeliveryState = state
	return status, out
}
