package mfapostgres

import (
	"bytes"
	"context"
	"testing"

	auth "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	primitive "github.com/faustbrian/go-password"
)

func TestPendingTOTPActivationCannotUseUnregisteredWork(t *testing.T) {
	if err := activatePendingTOTP(context.Background(), kernel.Work{}, nil, identity.Command{}, PendingTOTPMetadata{}, 0, 0, nil, primitive.Secret{}, auth.OneTimeCode{}, mfa.TOTPVerifier{}, 0); err == nil {
		t.Fatal("unregistered work activated a factor")
	}
}

func TestConfirmationScopeSeparatesOriginalAccountFactorCommandAndKey(t *testing.T) {
	m := PendingTOTPMetadata{TenantID: "tenant", UserID: "user", FactorID: "factor"}
	base, err := enrollmentConfirmationScope(m, "command", 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*PendingTOTPMetadata){
		func(m *PendingTOTPMetadata) { m.TenantID = "tenant2" },
		func(m *PendingTOTPMetadata) { m.UserID = "user2" },
		func(m *PendingTOTPMetadata) { m.FactorID = "factor2" },
	} {
		candidate := m
		change(&candidate)
		scope, err := enrollmentConfirmationScope(candidate, "command", 1)
		if err != nil || bytes.Equal(scope, base) {
			t.Fatal("confirmation scope aliases another owner")
		}
	}
	for _, scope := range []struct {
		command identity.CommandID
		version uint32
	}{{"command2", 1}, {"command", 2}} {
		wire, err := enrollmentConfirmationScope(m, scope.command, scope.version)
		if err != nil || bytes.Equal(wire, base) {
			t.Fatal("confirmation scope aliases another command or key")
		}
	}
	if _, err := enrollmentConfirmationScope(m, "command", 0); err == nil {
		t.Fatal("unversioned confirmation key accepted")
	}
}
