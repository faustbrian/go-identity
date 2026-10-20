package postgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
)

// Raw reset preparation must reject a stale, disabled-state-mismatched or
// expired predecessor before provider/password work. Reuse the kernel's exact
// reset fence in this short admission transaction; its invocation state dies
// with Work and final execution independently reacquires every lock. This does
// not consume the capability, stage material or mutate any domain row.
func admitResetInputCredential(ctx context.Context, w Work, command identity.Command, plan *admittedKernelPlan) error {
	spec, input := command.PasswordResetInputFeature()
	if !input {
		spec, input = command.PhonePasswordResetInputFeature()
	}
	if !input {
		return nil
	}
	if plan == nil || plan.feature == nil || !credentialResetSelected(plan.feature.Operation) || spec.Operation != plan.feature.Operation || spec.Binding != plan.binding {
		return w.fail(ctx, invalidCredentialReset())
	}
	i, err := decodeCredentialReset(spec)
	if err != nil {
		return w.fail(ctx, err)
	}
	for _, entry := range plan.contributors {
		if entry.descriptor.Owner == "identity/postgres" {
			repo, _ := entry.contributor.(*Repository)
			return lockCredentialReplacement(ctx, w, repo, i.Replacement, &i)
		}
	}
	return w.fail(ctx, invalidCredentialReset())
}

func prepareCredentialReset(ctx context.Context, w Work, command identity.Command) error {
	plan := w.state.execution.reservation.plan
	var repo *Repository
	var native CredentialResetContributor
	for _, e := range plan.contributors {
		if e.descriptor.Owner == "identity/postgres" {
			repo, _ = e.contributor.(*Repository)
		}
		if e.descriptor == plan.feature.Contributor {
			native, _ = e.contributor.(CredentialResetContributor)
		}
	}
	if repo == nil || native == nil || w.state.resetIntent != nil {
		return w.fail(ctx, invalidCredentialReset())
	}
	i, err := credentialResetCommand(native, command, plan.snapshot())
	if err != nil {
		return w.fail(ctx, err)
	}
	return lockCredentialReplacement(ctx, w, repo, i.Replacement, &i)
}

func (c *Coordinator) finalizeCredentialReset(w Work) error {
	if w.state.resetIntent == nil {
		return nil
	}
	if !w.state.resetApplied || w.state.resetFinalized || w.state.featureReceipt == nil {
		return w.fail(w.state.ctx, invalidCredentialReset())
	}
	if err := c.runCapabilityExecution(w.state.ctx, w, true); err != nil {
		return err
	}
	w.state.resetFinalized = true
	return nil
}
