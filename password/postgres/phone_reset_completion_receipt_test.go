package passwordpostgres

import (
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func TestPhoneResetCompletionReceiptPreservesExactProfile(t *testing.T) {
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	result := identity.CommandResult{Outcome: identity.CommitOutcomeCommitted, Feature: &identity.FeatureReceipt{Operation: phonePasswordResetOperation(), BeforeVersion: 1, AfterVersion: 2}}
	out, err := phoneResetCompleteReceipt(id, result, nil)
	if err != nil || out.CommandID != id || out.Outcome != identity.CommitOutcomeCommitted || out.CredentialVersion != 2 || !out.SessionsRevoked {
		t.Fatal("committed phone receipt was discarded", err)
	}
	if _, err := resetCompleteReceipt(id, result, nil); err == nil {
		t.Fatal("email reset accepted phone history")
	}
	email := result
	email.Feature = &identity.FeatureReceipt{Operation: resetOperation(), BeforeVersion: 1, AfterVersion: 2}
	legacy, err := resetCompleteReceipt(id, email, nil)
	if err != nil || legacy != out {
		t.Fatal("existing email-reset projection changed", err)
	}
	for _, operation := range []identity.FeatureOperation{resetOperation(), {Owner: "identity/phone", OperationID: "identity.phone.password-reset-request"}, {}} {
		result.Feature.Operation = operation
		if _, err := phoneResetCompleteReceipt(id, result, nil); err == nil {
			t.Fatal("phone reset accepted another profile")
		}
	}
	result.Feature = nil
	if _, err := phoneResetCompleteReceipt(id, result, nil); err == nil {
		t.Fatal("phone reset accepted missing committed receipt")
	}
}
