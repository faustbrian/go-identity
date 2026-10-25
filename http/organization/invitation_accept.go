package organizationhttp

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	organization "github.com/faustbrian/go-organization"
)

// InvitationAcceptResponse is the original acceptance receipt, not a fresh
// membership observation or credential. Recovery requires this safe binding,
// OrganizationID and current authenticated native access. There is no separate
// HTTP recovery route; re-posting a consumed proof is not recovery.
type InvitationAcceptResponse struct {
	MutationResponse
	InvitationID organization.ID `json:"invitationID,omitempty"`
}

func decodeAcceptance(in *requestInput, body map[string]json.RawMessage, limits capability.Limits) error {
	names := []string{"commandID", "organizationID", "invitationID", "organizationVersion", "invitationVersion", "token"}
	if len(body) != len(names) {
		return identityhttp.ErrInvalidInput
	}
	for _, name := range names {
		if value, ok := body[name]; !ok || string(value) == "null" {
			return identityhttp.ErrInvalidInput
		}
	}
	decode := func(name string, target any) bool { return json.Unmarshal(body[name], target) == nil }
	var token string
	if !decode("commandID", &in.commandID) || !decode("organizationID", &in.org) || !decode("invitationID", &in.invitationID) || !decode("organizationVersion", &in.orgVersion) || !decode("invitationVersion", &in.invitationVersion) || !decode("token", &token) {
		return identityhttp.ErrInvalidInput
	}
	proof, err := capability.ParseProof(token, limits)
	if err != nil {
		return identityhttp.ErrInvalidInput
	}
	in.proof = proof
	return nil
}

func (in *requestInput) accept() organization.InvitationAcceptRequest {
	return organization.InvitationAcceptRequest{Authentication: in.auth, CommandID: in.commandID, ID: in.invitationID, OrganizationID: in.org, OrganizationVersion: in.orgVersion, InvitationVersion: in.invitationVersion, Proof: in.proof, CorrelationID: in.correlation}
}

func admitInvitationAccept(ctx context.Context, c Config, in *requestInput, source organization.InvitationAcceptAdmission) error {
	b := source.Binding
	if ctx == nil || ctx.Err() != nil || in.observed.ValidateAt(c.Now()) != nil || source.Validate() != nil || source.OrganizationID != in.org || b.CommandID != in.commandID || b.TenantID != in.auth.TenantID || b.UserID != in.actor || b.ActorKind != authorization.SubjectUser || b.ActorID != identity.ActorID(in.actor) || b.RecordID != string(in.invitationID) || b.CorrelationID != in.correlation {
		return identityhttp.ErrUnavailable
	}
	out, err := c.SecretRate.AdmitOriginalCommand(ctx, in.facts, identityhttp.OriginalCommandSecretRateRequest{OperationID: string(organization.InvitationAccept), UserID: in.actor, CommandID: in.commandID, ChallengeID: source.ChallengeID, ChallengeLifetime: source.ChallengeLifetime})
	if errors.Is(err, identityhttp.ErrRateLimited) {
		return requestFailure{status: 429, code: "rate_limited", retry: out.RetryAfter}
	}
	if err != nil || !out.Allowed || ctx.Err() != nil || in.observed.ValidateAt(c.Now()) != nil {
		return identityhttp.ErrUnavailable
	}
	return nil
}

func invitationAcceptResponse(in *requestInput, result organization.StoreResult, err error) (int, InvitationAcceptResponse) {
	status, base := mutationResponse(in, result, err)
	out := InvitationAcceptResponse{MutationResponse: base}
	if base.CommandID != "" {
		out.InvitationID = result.InvitationID
	}
	return status, out
}
