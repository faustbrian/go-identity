package mfapostgres

import (
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-identity/session"
)

func TestEmailChangeFactorRequiresSelectedNativeIssuer(t *testing.T) {
	for _, stepup := range []*TOTPActiveStepUpService{nil, {}, {state: func() *activeStepUpState { return &activeStepUpState{} }}} {
		if source, err := NewEmailChangeFactorSource(stepup); err == nil || source != nil {
			t.Fatal("unselected native issuer supplied email factor authority")
		}
	}
	for _, source := range []*EmailChangeFactorSource{nil, {}} {
		proof, err := source.Prepare(t.Context(), auth.ReauthenticationProof{}, auth.ReauthenticationUse{}, session.Session{})
		if err == nil {
			t.Fatal("missing native custody supplied email factor authority")
		}
		if _, err := proof.Original(); err == nil {
			t.Fatal("failed preparation disclosed original factor evidence")
		}
	}
}
