package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func TestPreparedFeatureRecoveryRejectsInvalidComposition(t *testing.T) {
	for _, c := range []*Coordinator{nil, {}, {maximumDuration: time.Minute + 1}} {
		if got, err := c.RecoverPreparedFeatureCommand(context.Background(), identity.RecoveryQuery{}, requestKeyUnitCaller(RequestKeyScope{}), FeatureRegistration{}, nil); err == nil || got.Binding.CommandID != "" {
			t.Fatal("invalid mapped recovery composition admitted")
		}
	}
}

func TestRequestKeyRecoveryDecoderCancellationAndRedaction(t *testing.T) {
	original := featureCodecSpec().Binding
	for _, fail := range []bool{false, true} {
		owner := &requestPreparationParticipant{restore: func(context.Context, RequestKeyPreparationBinding, []byte) (identity.CommandBinding, error) {
			if fail {
				panic("private decoder diagnostic")
			}
			return original, errors.New("private decoder diagnostic")
		}}
		b, err := restoreRequestKey(context.Background(), owner, RequestKeyPreparationBinding{}, nil)
		var unavailable identity.UnavailableError
		if b != (identity.CommandBinding{}) || !errors.As(err, &unavailable) || err.Error() == "private decoder diagnostic" {
			t.Fatal("native decoder failure exported scope/diagnostics")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	owner := &requestPreparationParticipant{restore: func(context.Context, RequestKeyPreparationBinding, []byte) (identity.CommandBinding, error) {
		cancel()
		return original, nil
	}}
	b, err := restoreRequestKey(ctx, owner, RequestKeyPreparationBinding{}, nil)
	if b != (identity.CommandBinding{}) || !errors.Is(err, context.Canceled) {
		t.Fatal("late cancelled decoder exported original scope")
	}
	owner.restore = func(context.Context, RequestKeyPreparationBinding, []byte) (identity.CommandBinding, error) {
		t.Fatal("cancelled callback invoked")
		return original, nil
	}
	if b, err := restoreRequestKey(ctx, owner, RequestKeyPreparationBinding{}, nil); b != (identity.CommandBinding{}) || !errors.Is(err, context.Canceled) {
		t.Fatal("early cancellation lost")
	}
}
