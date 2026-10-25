package organizationhttp

import (
	"context"

	"github.com/faustbrian/go-identity/delivery"
	organization "github.com/faustbrian/go-organization"
)

// InvitationSendResponse retains the original native command outcome separately
// from current owner-authorized invitation and delivery observations. A failed
// current projection never implies rollback of an already committed send.
// Neither queued nor accepted means confirmed delivery. No proof, address,
// provider reference, delivery effect identity or credential is exported.
type InvitationSendResponse struct {
	MutationResponse
	InvitationID  organization.ID `json:"invitationID,omitempty"`
	Invitation    *InvitationView `json:"invitation,omitempty"`
	DeliveryState string          `json:"deliveryState,omitempty"`
}

func invitationSendResponse(ctx context.Context, c Config, in *requestInput, result organization.StoreResult, err error) (status int, out InvitationSendResponse) {
	status, base := mutationResponse(in, result, err)
	out = InvitationSendResponse{MutationResponse: base}
	if base.CommandID == "" {
		return status, out
	}
	out.InvitationID = result.InvitationID
	if status != 200 || !base.Committed {
		return status, out
	}
	defer func() {
		if recover() != nil {
			status, out.Error = 503, "unavailable"
			out.Invitation, out.DeliveryState = nil, ""
		}
	}()
	// The transaction receipt proves queue commitment, not a current invitation
	// view or provider delivery. Read those through their actual owner; failure
	// must not rewrite the original committed outcome into an apparent rollback.
	current, err := c.Invitations.Get(ctx, organization.InvitationReadRequest{Authentication: in.auth, OrganizationID: in.org, ID: result.InvitationID, CorrelationID: in.correlation})
	if err != nil {
		status, out.Error = domainFailure(err)
		return status, out
	}
	view, err := invitationView(&invitationInput{auth: in.auth, actor: in.actor, org: in.org, id: result.InvitationID}, current.Invitation, false)
	state := deliveryStateName(current.State)
	if err != nil || current.Invitation.RecipientUserID != in.user || current.Invitation.RecipientIdentifierID != in.recipientIdentifier || current.Invitation.CreatedBy != in.actor || !boundedID(string(current.EffectID)) || state == "" {
		out.Error = "unavailable"
		return 503, out
	}
	out.Invitation, out.DeliveryState = &view, state
	return status, out
}

func deliveryStateName(state delivery.DeliveryState) string {
	switch state {
	case delivery.StateQueued:
		return "queued"
	case delivery.StateAttempting:
		return "attempting"
	case delivery.StateAccepted:
		return "accepted"
	case delivery.StateDelivered:
		return "delivered"
	case delivery.StateRejected:
		return "rejected"
	case delivery.StateBounced:
		return "bounced"
	case delivery.StateCancelled:
		return "cancelled"
	case delivery.StateOutcomeUnknown:
		return "unknown"
	case delivery.StateRetryWait:
		return "retry_wait"
	case delivery.StateExpired:
		return "expired"
	case delivery.StateExhausted:
		return "exhausted"
	case delivery.StateSuperseded:
		return "superseded"
	case delivery.StateTransientFailure:
		return "transient_failure"
	}
	return ""
}
