package risk

import (
	"context"
	"testing"
)

func TestVerificationSigninUsesCountedAuthenticationPolicy(t *testing.T) {
	p := testPolicy(t)
	a, err := p.Admit("identity.email.verification-signin")
	if err != nil || a.Profile.Class != Authentication || a.Profile.Phase != BeforeCredential {
		t.Fatal("post-verification signin lacks Authentication policy", err)
	}
	for _, action := range []Action{"identity.email.verification-confirm", "identity.email.change-confirm"} {
		a, err := p.Admit(action)
		if err != nil || a.Profile.Class != CredentialMutation {
			t.Fatal("verification-only policy changed", err)
		}
	}
	scope := testContext()
	scope.Operation = "identity.email.verification-signin"
	signal := testSignal(scope, "status", SignalDeny)
	assessment, err := p.Assess(context.Background(), scope, []Signal{signal, testSignal(scope, "captcha", SignalClean)})
	if err != nil || assessment.Decision.Action != Deny {
		t.Fatal("current risk denial did not stop post-verification signin", err)
	}
}
