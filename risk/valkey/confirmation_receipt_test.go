package valkey

import (
	"context"
	"testing"

	"github.com/faustbrian/go-identity/risk"
)

func TestOwnedNativeConfirmationReturnsExactAcknowledgement(t *testing.T) {
	f := newConfirmationFixture(t, 1)
	owner, ok := any(f.owner).(interface {
		confirmed(context.Context, risk.VelocityLease, risk.VelocityClosure, risk.VelocityPublication, risk.VelocityConfirmation) (risk.VelocityNativeConfirmation, error)
	})
	if !ok {
		t.Fatal("native confirmed IO cannot return owned acknowledgement")
	}
	ack, err := owner.confirmed(context.Background(), f.lease, f.closure, f.publication, f.confirmation)
	if err != nil {
		t.Fatal(err)
	}
	v, _ := f.native.Verifier()
	if got, err := v.NativeConfirmation(f.lease, f.closure, f.publication, f.confirmation, ack); err != nil || got != f.binding {
		t.Fatal("native receipt lost original confirmed cut", err)
	}
}

func TestOwnedNativeConfirmationNeverAcknowledgesLostAuthority(t *testing.T) {
	for _, mode := range []int32{1, 2, 3, 4, 5, 6, 7, 8} {
		f := newConfirmationFixture(t, 1)
		owner, ok := any(f.owner).(interface {
			confirmed(context.Context, risk.VelocityLease, risk.VelocityClosure, risk.VelocityPublication, risk.VelocityConfirmation) (risk.VelocityNativeConfirmation, error)
		})
		if !ok {
			t.Fatal("native acknowledgement path missing")
		}
		f.mode.Store(mode)
		if got, err := owner.confirmed(context.Background(), f.lease, f.closure, f.publication, f.confirmation); err == nil || got != (risk.VelocityNativeConfirmation{}) {
			t.Fatal("failed native/primary confirmation exposed custody", mode, err)
		}
	}
}
