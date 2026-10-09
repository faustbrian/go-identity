package passwordpostgres

import (
	"context"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func TestPasswordChangeRejectsUnconfiguredAuthority(t *testing.T) {
	for _, source := range []*ReauthenticationService{nil, {}} {
		if service, err := NewPasswordChangeService(source, PasswordChangeConfig{}); err == nil || service != nil {
			t.Fatal("unconfigured source admitted password change")
		}
	}
	for _, service := range []*PasswordChangeService{nil, {}} {
		result, err := service.Change(context.Background(), PasswordChangeRequest{})
		if err == nil || result.Outcome == identity.CommitOutcomeCommitted || result.CredentialVersion != 0 {
			t.Fatal("zero service reported a protected mutation")
		}
	}
}
