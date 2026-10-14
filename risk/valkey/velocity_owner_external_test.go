package valkey_test

import (
	"context"
	"errors"
	"testing"

	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/risk/valkey"
)

// Consumer access does not expose a native issuer, executor or internal binder.
func TestExternalVelocityOwnerFailsClosedWithoutConfiguration(t *testing.T) {
	if _, err := valkey.NewCredential("", nil); !errors.Is(err, risk.ErrInvalidPolicy) {
		t.Fatal("invalid external credential accepted", err)
	}
	owner, err := valkey.NewVelocityRecovery(valkey.VelocityRecoveryConfig{})
	if !errors.Is(err, risk.ErrInvalidPolicy) {
		t.Fatal("zero external configuration accepted", err)
	}
	if _, _, err := owner.PrimaryAuthorities(); !errors.Is(err, risk.ErrInvalidVelocityRecovery) {
		t.Fatal("failed construction exposed capabilities", err)
	}
	if err := owner.Close(context.Background()); !errors.Is(err, risk.ErrInvalidVelocityRecovery) {
		t.Fatal("failed construction appeared live", err)
	}
}
