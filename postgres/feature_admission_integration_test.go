//go:build integration

package postgres

import (
	"context"
	identity "github.com/faustbrian/go-identity"
)

// These sources exercise kernel scheduling/custody, not real risk decisions.
type gatedPreparedFeaturePhase struct {
	*preparedFeaturePhase
	prepare func(context.Context, identity.Command) (FeaturePreparationAdmission, error)
	restore func(context.Context, identity.Command, uint64, []byte) (FeaturePreparationAdmission, error)
}

func (p *gatedPreparedFeaturePhase) PrepareFeatureAdmission(ctx context.Context, c identity.Command) (FeaturePreparationAdmission, error) {
	return p.prepare(ctx, c)
}
func (p *gatedPreparedFeaturePhase) RestoreFeatureAdmission(ctx context.Context, c identity.Command, g uint64, wire []byte) (FeaturePreparationAdmission, error) {
	return p.restore(ctx, c, g, wire)
}

type testPreparationAdmission struct {
	phase    *preparedFeaturePhase
	original identity.Command
	check    func(context.Context) error
}

func (a *testPreparationAdmission) Check(ctx context.Context) error {
	if a.check != nil {
		return a.check(ctx)
	}
	return ctx.Err()
}
func (a *testPreparationAdmission) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	return a.phase.GenerateFeaturePreparation(ctx, a.original, generation)
}
