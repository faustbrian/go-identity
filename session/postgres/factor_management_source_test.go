package postgres

import (
	"testing"

	"github.com/faustbrian/go-identity/mfa"
)

func TestFactorUpdatePrimaryAndSessionEffectsRequireRealOwners(t *testing.T) {
	if effects, err := NewMFAFactorUpdateSessionEffect(Config{}, IdentifierAdmissionConfig{}); err == nil || effects != nil {
		t.Fatal("unconfigured factor management acquired session effects")
	}
	for _, source := range []*PasswordActiveTOTPPrimarySource{nil, {}} {
		primary, observed, err := source.PrepareFactorUpdate(t.Context(), mfa.FactorUpdateRequest{}, "")
		if err == nil || primary != nil || observed.Authenticated {
			t.Fatal("missing native primary granted factor-update custody")
		}
		if primary, err := source.RestoreFactorUpdate(t.Context(), mfa.FactorUpdateRequest{}, "", nil); err == nil || primary != nil {
			t.Fatal("missing native primary restored factor-update custody")
		}
	}
}
