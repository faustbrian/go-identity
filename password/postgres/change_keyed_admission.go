package passwordpostgres

import (
	"context"
	"slices"
	"time"

	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
)

var _ kernel.FeatureAdmissionPreparationContributor = (*keyedPasswordChangePhase)(nil)

// Original provider observations are immutable invocation custody, not a new
// permission, replay store or authority. Check performs only local policy/time
// evaluation; the kernel invokes it again at final transaction/commit boundaries.
type keyedPasswordChangeAdmission struct {
	owner   *keyedPasswordChangePhase
	command identity.Command
	facts   []risk.Signal
}

func (a *keyedPasswordChangeAdmission) Check(ctx context.Context) error {
	if a == nil || a.owner == nil || ctx == nil {
		return password.ErrPasswordWork
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	p := a.owner
	phase, original, record, err := p.invocation(p.input(), slices.Clone(a.facts), identity.Command{})
	if err != nil {
		return err
	}
	// A clock callback supplied by the caller must not run under SQL locks.
	// The primary-owned phase independently checks the same original instants.
	now := time.Now().UTC()
	use := p.service.proofUse(p.request(), now)
	if record.Proof.Validate(use) != nil {
		return identity.ForbiddenError{}
	}
	if _, err := original.Lifetime(now); err != nil {
		return identity.ForbiddenError{}
	}
	scope := phase.scope
	scope.Now = now
	decision, err := p.service.native.assessChangeProviders(ctx, scope, a.facts)
	if err != nil || decision.Action != risk.Allow {
		return identity.ForbiddenError{}
	}
	until := minPasswordChangeExpiry(record.Proof.Proof.ExpiresAt, record.Proof.Proof.IssuedAt.Add(p.service.native.c.MaximumAge))
	for _, fact := range a.facts {
		until = minPasswordChangeExpiry(until, fact.ExpiresAt)
	}
	if p.arm == nil {
		return password.ErrPasswordWork
	}
	return p.arm(until)
}

func (a *keyedPasswordChangeAdmission) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	if err := a.Check(ctx); err != nil {
		return nil, err
	}
	return a.owner.generateWithFacts(ctx, a.command, generation, a.facts)
}

func (p *keyedPasswordChangePhase) PrepareFeatureAdmission(ctx context.Context, original identity.Command) (kernel.FeaturePreparationAdmission, error) {
	if p == nil || p.input == nil || p.request == nil || ctx == nil {
		return nil, password.ErrPasswordWork
	}
	input := p.input()
	scope := risk.Context{Tenant: string(input.Binding.TenantID), Operation: risk.Action(replacementOperation().OperationID), Attempt: string(input.Binding.CommandID), Now: p.service.native.source.c.Verifier.Now().UTC()}
	ctx, stop := context.WithTimeout(ctx, p.service.native.c.Screening.Timeout)
	defer stop()
	request := p.request()
	facts, err := p.service.native.collectChange(ctx, input.Binding, request.Proof, scope, request.Password)
	if err != nil || len(facts) == 0 || len(facts) > 32 || ctx.Err() != nil {
		return nil, readerFailure(ctx)
	}
	a := &keyedPasswordChangeAdmission{owner: p, command: original, facts: slices.Clone(facts)}
	if err := a.Check(ctx); err != nil {
		return nil, err
	}
	return a, nil
}

func (p *keyedPasswordChangePhase) RestoreFeatureAdmission(ctx context.Context, original identity.Command, generation uint64, wire []byte) (kernel.FeaturePreparationAdmission, error) {
	// Only local keyring AEAD runs here; cloud/network key providers are not
	// selectable in this profile. Original observations are never recollected.
	if _, _, err := p.RestoreFeaturePreparation(ctx, original, generation, wire); err != nil {
		return nil, err
	}
	retained := p.retained()
	a := &keyedPasswordChangeAdmission{owner: p, command: original, facts: slices.Clone(retained.output.Facts)}
	if err := a.Check(ctx); err != nil {
		return nil, err
	}
	return a, nil
}
