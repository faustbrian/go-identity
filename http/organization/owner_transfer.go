package organizationhttp

import (
	"context"
	"errors"

	auth "github.com/faustbrian/go-authentication/v2"
	organization "github.com/faustbrian/go-organization"
)

// Authentication ProofID/audience are22..128/1..128 visible ASCII bytes,
// respectively (go-authentication/v2 Proof and ReauthenticationProof). They are
// original-owner identifiers, not a transport-invented bearer-token grammar.
func canonicalProofText(value string, min, max int) bool {
	if len(value) < min || len(value) > max {
		return false
	}
	for _, b := range []byte(value) {
		if b < 33 || b > 126 {
			return false
		}
	}
	return true
}

func (in *requestInput) ownerTransfer(p auth.ReauthenticationProof) organization.OwnerTransferOperationRequest {
	return organization.OwnerTransferOperationRequest{Authentication: in.auth, IdempotencyKey: in.key, OrganizationID: in.org, TargetUserID: in.user, OrganizationVersion: in.orgVersion, SourceVersion: in.sourceVersion, TargetVersion: in.memberVersion, Proof: p, CorrelationID: in.correlation}
}

func dispatchOwnerTransfer(ctx context.Context, c Config, in *requestInput) (organization.StoreResult, error) {
	var zero organization.StoreResult
	r, err := c.OwnerTransferProofs.Reauthentication(ctx, in.transferProofID)
	if ctx.Err() != nil || in.observed.ValidateAt(c.Now()) != nil {
		return zero, organization.ErrUnavailable
	}
	if errors.Is(err, auth.ErrInvalidProof) {
		return zero, organization.ErrForbidden
	}
	if err != nil {
		return zero, organization.ErrUnavailable
	}
	p := r.Proof
	if p.Proof.ID != in.transferProofID || p.Proof.Tenant != string(in.auth.TenantID) || p.Proof.Subject != string(in.actor) || p.Action != string(organization.OwnerTransfer) || p.Proof.Audience != c.OwnerTransferAudience {
		return zero, organization.ErrForbidden
	}
	request := in.ownerTransfer(p)
	if request.Validate() != nil {
		return zero, organization.ErrForbidden
	}
	// Historical keyed classification may use the retained expired proof and a
	// fresh current session. Binding this projection to today's session or clock
	// would reject native original recovery; the native owner authenticates and
	// consumes the original fresh proof only when admitting new work.
	return c.OwnerTransferer.OwnerTransfer(ctx, request, in.facts.ClientIP().String())
}
