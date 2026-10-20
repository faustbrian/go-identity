package postgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
)

// FeatureInputAdmissionContributor supplies the exact registered native
// feature's current original-input checks before another participant compares
// or charges a credential. The coordinator invokes it in its existing Work,
// never through a caller clearance callback or an OTP-handle conversion.
// FeatureScope identifies this synchronous owner; Apply-only command identity
// remains unavailable. Admission must perform only bounded owned primary reads
// and locks, not writes, generation, external IO, freshness renewal or retention.
// Errors/panics poison the complete provisional transaction. Implementations
// must support independent concurrent calls and immutable original input.
type FeatureInputAdmissionContributor interface {
	FeatureExecutionContributor
	AdmitFeaturePreparation(context.Context, Work, identity.Command) error
}

func otpFeatureInputAdmissionRequired(p CommandPlan) bool {
	return p.OTP != nil && p.Feature != nil && (p.Feature.Operation.Owner == "identity/mfa" || otpEmailMutationOperation(p.Feature.Operation) || p.Feature.Operation == phoneVerificationOperation() || p.Feature.Operation == phoneChangeOperation())
}

// Existing OTP signin/check profiles retain their owner-specific admission.
// OTP-backed MFA must authenticate its distinct parent/factor/CSRF owners before
// a wrong attempt debit as well as before consuming reservation.
func (c *Coordinator) admitOTPFeatureInput(ctx context.Context, w Work, command identity.Command, p *admittedKernelPlan) error {
	if p == nil {
		return invalidPlan()
	}
	if !otpFeatureInputAdmissionRequired(p.snapshot()) {
		return nil
	}
	return c.invokeFeatureInputAdmission(ctx, w, command, p)
}

func (c *Coordinator) invokeFeatureInputAdmission(ctx context.Context, w Work, command identity.Command, p *admittedKernelPlan) (err error) {
	if err = w.usable(); err != nil {
		return err
	}
	if ctx == nil || c == nil || c.registry == nil || p == nil || p.belongsTo(c.registry) != nil || p.feature == nil || w.state.registry != p.registry || w.state.binding != p.binding || w.state.feature == nil || *w.state.feature != *p.feature || w.state.featureInvocation != nil || w.state.featureApplying || w.state.rows != nil {
		return w.fail(w.state.ctx, invalidWork())
	}
	if err = ctx.Err(); err != nil {
		return w.fail(ctx, err)
	}
	// Use the same closed selector as plan admission: sealed password variants
	// deliberately refuse the legacy generic accessor without losing metadata.
	spec, ok := commandFeature(command)
	entry, selectErr := c.registry.selectFeatureOperation(*p.feature)
	phase, owned := entry.contributor.(FeatureInputAdmissionContributor)
	if !ok || selectErr != nil || !owned || spec.Binding != p.binding || spec.Operation != p.feature.Operation {
		return w.fail(ctx, invalidWork())
	}
	w.state.featureInvocation = phase
	w.state.featurePreparationCommand = &command
	w.state.featurePreparationPlan = p
	defer func() {
		w.state.featureInvocation = nil
		w.state.featurePreparationCommand = nil
		w.state.featurePreparationPlan = nil
		if recover() != nil {
			err = w.fail(ctx, identity.UnavailableError{})
		}
	}()
	if err = admitResetInputCredential(ctx, w, command, p); err != nil {
		return w.fail(ctx, err)
	}
	if err = phase.AdmitFeaturePreparation(ctx, w, command); err != nil {
		switch err.(type) {
		case identity.ForbiddenError:
			err = identity.ForbiddenError{}
		case identity.ConflictError:
			err = identity.ConflictError{}
		case OAuthReauthenticationRequiredError:
			err = OAuthReauthenticationRequiredError{}
		default:
			err = identity.UnavailableError{}
		}
		return w.fail(ctx, err)
	}
	if w.state.rows != nil {
		return w.fail(ctx, invalidWork())
	}
	return w.usable()
}
