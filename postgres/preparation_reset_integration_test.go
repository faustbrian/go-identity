//go:build integration

package postgres

import (
	"bytes"
	"context"

	identity "github.com/faustbrian/go-identity"
)

// Scheduling/custody fixture only: these admissions are not genuine risk or
// HIBP decisions, and the existing reset fixture owns synthetic material.
// Real kernel SQL must nevertheless enforce atomic consumption and rollback.
type preparedResetPhase struct {
	*resetNativePhase
	original, generated identity.Command
	plan                CommandPlan
	deny                bool
	generations         int
}

func (p *preparedResetPhase) ValidateFeatureCommand(c identity.Command, plan CommandPlan) error {
	return p.resetNativePhase.ValidateFeatureCommand(c, plan)
}

func (p *preparedResetPhase) ValidateFeaturePreparation(c identity.Command, plan CommandPlan) error {
	if c != p.original || !resetAuthenticationPreparation(plan) {
		return invalidPreparation()
	}
	_, proof, ok := c.PasswordResetInputCustody()
	if !ok || proof.ValidateBounds(32, 4096) != nil {
		return invalidPreparation()
	}
	return nil
}

func (p *preparedResetPhase) AdmitFeaturePreparation(ctx context.Context, w Work, c identity.Command) error {
	s, ok := c.PasswordResetInputFeature()
	b, _, _, err := w.FeatureScope(p)
	if err != nil || !ok || c != p.original || b != s.Binding {
		return invalidWork()
	}
	_, err = w.DatabaseTime(ctx)
	return err
}

func (*preparedResetPhase) GenerateFeaturePreparation(context.Context, identity.Command, uint64) ([]byte, error) {
	return nil, invalidPreparation()
}

func (p *preparedResetPhase) RestoreFeaturePreparation(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identity.Command, CommandPlan, error) {
	q, err := prepareClaim(c, [32]byte{1})
	if err != nil || c != p.original || generation == 0 || ctx.Err() != nil {
		return identity.Command{}, CommandPlan{}, invalidPreparation()
	}
	digest := claimFingerprint([32]byte{1}, q.canonical)
	if !bytes.Equal(wire, digest[:]) {
		return identity.Command{}, CommandPlan{}, invalidPreparation()
	}
	return p.generated, p.plan, nil
}

func (p *preparedResetPhase) PrepareFeatureAdmission(ctx context.Context, c identity.Command) (FeaturePreparationAdmission, error) {
	if c != p.original || ctx.Err() != nil {
		return nil, invalidPreparation()
	}
	return preparedResetAdmission{p}, nil
}

func (p *preparedResetPhase) RestoreFeatureAdmission(ctx context.Context, c identity.Command, generation uint64, wire []byte) (FeaturePreparationAdmission, error) {
	if _, _, err := p.RestoreFeaturePreparation(ctx, c, generation, wire); err != nil {
		return nil, err
	}
	return preparedResetAdmission{p}, nil
}

func (p *preparedResetPhase) CheckFeatureCommit(ctx context.Context, w Work, c identity.Command) error {
	if _, _, _, err := w.FeatureScope(p); err != nil {
		return err
	}
	if p.failCommit {
		return identity.UnavailableError{}
	}
	return p.checkProof(ctx, c)
}

type preparedResetAdmission struct{ owner *preparedResetPhase }

func (a preparedResetAdmission) Check(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if a.owner.deny {
		return identity.ForbiddenError{}
	}
	return nil
}

func (a preparedResetAdmission) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	if err := a.Check(ctx); err != nil || generation == 0 {
		return nil, invalidPreparation()
	}
	q, err := prepareClaim(a.owner.original, [32]byte{1})
	if err != nil {
		return nil, err
	}
	a.owner.generations++
	digest := claimFingerprint([32]byte{1}, q.canonical)
	return bytes.Clone(digest[:]), nil
}
