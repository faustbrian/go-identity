package risk

import "testing"

func TestTOTPURIRevealConsumesProtectedCredentialMutationBudget(t *testing.T) {
	admitted, err := testPolicy(t).Admit("identity.mfa.totp-uri")
	if err != nil || admitted.Profile.Class != CredentialMutation || admitted.Profile.Phase != ReserveWithCommand {
		t.Fatal("state-mutating URI reveal lacks protected credential budget")
	}
}
