package postgres

import (
	"github.com/faustbrian/go-identity/mfa"
	"testing"
)

func TestActiveTOTPPrimaryRequiresNativeSessionAndSynchronizerOwners(t *testing.T) {
	if source, err := NewPasswordActiveTOTPPrimarySource(nil, PasswordActiveTOTPPrimaryConfig{}); err == nil || source != nil {
		t.Fatal("active factor accepted absent primary and synchronizer owners")
	}
}

func TestRegenerationPrimaryRejectsAbsentCurrentSessionBeforePreparation(t *testing.T) {
	for _, source := range []*PasswordActiveTOTPPrimarySource{nil, {}} {
		primary, current, err := source.PrepareRegeneration(t.Context(), mfa.RecoveryRegenerateRequest{})
		if err == nil || primary != nil || current.Authenticated {
			t.Fatal("unowned regeneration primary returned session custody")
		}
	}
}
