package passwordpostgres

import (
	"context"
	"testing"

	identity "github.com/faustbrian/go-identity"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
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

// Config normalization governs the actual native mutation; zero retains strict
// revoke-all behavior, while explicit choices freeze one bounded whole set.
func TestPasswordChangeSessionPolicy(t *testing.T) {
	for _, c := range []PasswordChangeConfig{{}, {SessionDisposition: sessionpg.PasswordChangePreserveSessions, MaximumSessions: 16}, {SessionDisposition: sessionpg.PasswordChangeRevokeOtherSessions, MaximumSessions: 1}, {SessionDisposition: sessionpg.PasswordChangeRevokeAllSessions, MaximumSessions: 100000}} {
		got, err := passwordChangeSessionPolicy(c)
		if err != nil || got.SessionDisposition == 0 || got.MaximumSessions == 0 {
			t.Fatal("valid bounded session policy rejected", err)
		}
		if c.SessionDisposition == 0 && (got.SessionDisposition != sessionpg.PasswordChangeRevokeAllSessions || got.MaximumSessions != 100000) {
			t.Fatal("default weakened strict invalidation")
		}
	}
	for _, c := range []PasswordChangeConfig{{SessionDisposition: 255}, {MaximumSessions: 100001}} {
		if _, err := passwordChangeSessionPolicy(c); err == nil {
			t.Fatal("invalid whole-set policy accepted")
		}
	}
}
