package organizationhttp

import (
	"context"
	"errors"

	auth "github.com/faustbrian/go-authentication/v2"
	organization "github.com/faustbrian/go-organization"
)

func lifecycleOperation(op organization.Operation) bool {
	return op == organization.Archive || op == organization.Restore
}

func dispatchLifecycle(ctx context.Context, c Config, in *requestInput) (organization.StoreResult, error) {
	var zero organization.StoreResult
	r, err := c.LifecycleProofs.Reauthentication(ctx, in.transferProofID)
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
	if p.Proof.ID != in.transferProofID || p.Proof.Tenant != string(in.auth.TenantID) || p.Proof.Subject != string(in.actor) || p.Action != string(in.op) || p.Proof.Audience != c.LifecycleAudience {
		return zero, organization.ErrForbidden
	}
	request := organization.LifecycleOperationRequest{Authentication: in.auth, IdempotencyKey: in.key, OrganizationID: in.org, OrganizationVersion: in.orgVersion, Reason: in.lifecycleReason, Proof: p, CorrelationID: in.correlation}
	if request.Validate() != nil {
		return zero, organization.ErrForbidden
	}
	// Original-key recovery may use an expired original record and a new current
	// session. Only the native owner authenticates/consumes a fresh action proof
	// for new execution; transport must not renew it or bind history to today.
	if in.op == organization.Archive {
		return c.Archiver.Archive(ctx, request, in.facts.ClientIP().String())
	}
	return c.Restorer.Restore(ctx, request, in.facts.ClientIP().String())
}
