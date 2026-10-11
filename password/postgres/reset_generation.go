package passwordpostgres

import (
	"context"
	"time"

	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
)

// Only the native preparation journal's acknowledged original generation may
// call this. Original scope and consumption must come from durable issuer
// provenance, not caller projections. Signature verification still belongs to
// the configured capability engine; counted admission precedes that work and
// the real HIBP collection precedes hashing. This neither reserves nor consumes.
// The caller encrypts the generated output in that same journal, restores it
// without regeneration and fences current account/identifier/factor authority
// with material, one-use, session and lifecycle effects in the sole Work.
func (r *Repository) generateResetCommand(ctx context.Context, input identity.Command, c password.HashPreparationConfig, admission risk.AuthenticationAdmission, verifier capability.Service, profile password.ResetProfile, original password.ResetGrantSpec, grant capability.Grant, consumption kernel.CapabilityPlan) (command identity.Command, facts []risk.Signal, err error) {
	caller := ctx
	defer func() {
		if recover() != nil {
			err = password.ErrPasswordWork
		}
		if caller != nil && caller.Err() != nil {
			err = caller.Err()
		}
		if err != nil {
			command, facts = identity.Command{}, nil
		}
	}()
	spec, metadata := input.PasswordResetInputFeature()
	candidate, proof, custody := input.PasswordResetInputCustody()
	if ctx == nil || r == nil || r.policy.Algorithm() == "" || !metadata || !custody || verifier == nil || c.Now == nil || c.Timeout <= 0 || c.Timeout > 10*time.Second || original.FactorVersion == 0 {
		return command, nil, password.ErrPasswordWork
	}
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer func() {
		// Observe actual deadline/cancellation before releasing the derived
		// context; our own cleanup is not a failed generation.
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		cancel()
	}()
	if err := ctx.Err(); err != nil {
		return command, nil, err
	}
	intent, err := passwordResetIntent(spec)
	if err != nil {
		return command, nil, err
	}
	scope := admission.Prepared().Scope
	if scope.Operation != risk.Action(spec.Binding.OperationID) || scope.Tenant != string(spec.Binding.TenantID) || scope.Attempt != string(spec.Binding.CommandID) || admission.Check(ctx) != nil || admission.CheckAt(ctx, c.Now()) != nil {
		return command, nil, password.ErrPasswordWork
	}
	if err := passwordResetOriginalIntent(intent, profile, original, grant, consumption, c.Now()); err != nil {
		return command, nil, err
	}
	// A verified grant from another proof must not authorize this input, even
	// when its user/resource match. Borrow and reverify the actual original
	// owner; do not export or terminally transfer bearer bytes to compare them.
	audiences := grant.Payload().Audiences
	if len(audiences) != 1 {
		return command, nil, identity.ForbiddenError{}
	}
	verified, err := verifier.Verify(ctx, proof, "identity.password.reset-complete", audiences[0])
	if err != nil || verified.EnvelopeDigest() != grant.EnvelopeDigest() {
		return command, nil, identity.ForbiddenError{}
	}
	hash, facts, err := r.prepareResetHash(ctx, c, admission, scope, candidate)
	if err != nil {
		return command, nil, err
	}
	command, err = identity.NewFeaturePasswordResetCommand(spec, hash.String(), proof)
	if err != nil {
		return command, nil, password.ErrPasswordWork
	}
	// Hash/provider latency cannot renew the grant, original risk facts or the
	// signed predecessors. Generated material must use the selected owner policy.
	if _, _, err := passwordResetOriginalMaterial(command, r.policy, profile, original, verified, consumption, c.Now()); err != nil {
		return command, nil, err
	}
	if err := admission.Check(ctx); err != nil {
		return command, nil, password.ErrPasswordWork
	}
	return command, facts, nil
}
