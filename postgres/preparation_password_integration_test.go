//go:build integration

package postgres

import (
	"bytes"
	"context"

	identity "github.com/faustbrian/go-identity"
)

// Synthetic native custody exercises generated-command selection and the real
// replacement transaction, not encryption, hashing or proof authentication.
// The production password adapter must supply its authenticated retained codec.
type preparedReplacementPhase struct {
	*replacementNativePhase
	generated, restored int
	command             identity.Command
	plan                CommandPlan
}

func (p *preparedReplacementPhase) ValidateFeaturePreparation(c identity.Command, plan CommandPlan) error {
	return p.ValidateFeatureCommand(c, plan)
}

func (p *preparedReplacementPhase) AdmitFeaturePreparation(ctx context.Context, w Work, c identity.Command) error {
	s, ok := c.Feature()
	b, _, _, err := w.FeatureScope(p)
	if err != nil || !ok || b != s.Binding {
		return invalidWork()
	}
	_, err = w.DatabaseTime(ctx)
	return err
}

func (p *preparedReplacementPhase) GenerateFeaturePreparation(ctx context.Context, original identity.Command, _ uint64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	q, err := prepareClaim(original, [32]byte{1})
	if err != nil {
		return nil, err
	}
	p.generated++
	fingerprint := claimFingerprint([32]byte{1}, q.canonical)
	return bytes.Clone(fingerprint[:]), nil
}

func (p *preparedReplacementPhase) RestoreFeaturePreparation(ctx context.Context, original identity.Command, generation uint64, wire []byte) (identity.Command, CommandPlan, error) {
	q, err := prepareClaim(original, [32]byte{1})
	if err != nil || generation == 0 || ctx.Err() != nil {
		return identity.Command{}, CommandPlan{}, invalidPreparation()
	}
	fingerprint := claimFingerprint([32]byte{1}, q.canonical)
	if !bytes.Equal(wire, fingerprint[:]) {
		return identity.Command{}, CommandPlan{}, invalidPreparation()
	}
	p.restored++
	return p.command, p.plan, nil
}

func (p *preparedReplacementPhase) ApplyFeature(ctx context.Context, w Work, c identity.Command) (identity.FeatureReceipt, error) {
	want, err := prepareClaim(p.command, [32]byte{1})
	got, actualErr := prepareClaim(c, [32]byte{1})
	if err != nil || actualErr != nil || !bytes.Equal(want.canonical, got.canonical) {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	if wire, generation, err := w.FeaturePreparationOutput(p); err != nil || len(wire) != 32 || generation != 1 {
		return identity.FeatureReceipt{}, invalidPreparation()
	}
	return p.replacementNativePhase.ApplyFeature(ctx, w, c)
}
