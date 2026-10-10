package passwordpostgres

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// SU02/09: zero composition never becomes an execution or recovery fallback.
func TestSignupServiceRejectsUnownedComposition(t *testing.T) {
	if service, err := NewSignupService(nil, SignupConfig{}, nil); err == nil || service != nil {
		t.Fatal("zero composition accepted")
	}
	for _, service := range []*SignupService{nil, {}} {
		for _, ctx := range []context.Context{nil, context.Background()} {
			if _, err := service.Signup(ctx, password.SignupRequest{}); err == nil {
				t.Fatal("zero signup accepted")
			}
			if _, err := service.RecoverSignup(ctx, password.SignupRecoveryRequest{}); err == nil {
				t.Fatal("zero recovery accepted")
			}
		}
	}
	for _, p := range []*signupPhase{nil, {}} {
		if status, err := p.RecoverParticipant(context.Background(), kernel.RecoveryWork{}); err == nil || status != kernel.RecoveryUnknown {
			t.Fatal("zero recovery participant guessed rollback")
		}
	}
}

func TestSignupCompositionDiagnosticsRejectExport(t *testing.T) {
	for _, value := range []any{SignupConfig{IntentKey: [32]byte{1}}, SignupDeliveryConfig{ScopeKey: [32]byte{2}}, SignupService{}} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
			text := fmt.Sprintf(verb, value)
			if text != "passwordpostgres.SignupConfig(redacted)" && text != "passwordpostgres.SignupDeliveryConfig(redacted)" && text != "passwordpostgres.SignupService(redacted)" {
				t.Fatal("private configuration disclosed")
			}
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("configuration JSON allowed")
		}
	}
}
