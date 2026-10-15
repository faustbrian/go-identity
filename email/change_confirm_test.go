package email_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
)

func TestEmailChangeConfirmationAndRecoveryKeepExactAction(t *testing.T) {
	original := confirmationRequest(t)
	r := email.ChangeConfirmRequest(original)
	if r.Validate() == nil {
		t.Fatal("verification-only caller selected primary change")
	}
	r.Caller = original.Caller.Clone()
	r.Caller.Request.Action = "identity.email.change-confirm"
	if r.Validate() != nil || email.VerificationConfirmRequest(r).Validate() == nil {
		t.Fatal("typed confirmation actions were aliased")
	}
	q := identity.RecoveryQuery{CommandID: r.CommandID, TenantID: r.TenantID, UserID: "user", ActorID: identity.ActorID(r.Caller.Request.Subject.ID), ActorKind: r.Caller.Request.Subject.Kind, OperationID: "identity.email.change-confirm", RecordID: "candidate"}
	recovery, err := email.NewChangeRecovery(q)
	if err != nil {
		t.Fatal(err)
	}
	q.OperationID = "identity.email.verification-confirm"
	if _, err := email.NewChangeRecovery(q); err == nil {
		t.Fatal("change recovery borrowed verification history")
	}
	bindings, err := recovery.Bindings()
	if err != nil || bindings.OperationID != "identity.email.change-confirm" {
		t.Fatal("original operation changed")
	}
	if _, err := email.NewVerificationRecovery(bindings); err == nil {
		t.Fatal("change became ordinary verification recovery")
	}
	request := email.ChangeRecoveryRequest{Recovery: recovery, Caller: r.Caller}
	if request.Validate() != nil {
		t.Fatal("exact trusted original recovery denied")
	}
	foreign := request
	foreign.Caller = request.Caller.Clone()
	foreign.Caller.Request.Subject.ID = authorization.SubjectID("foreign")
	if foreign.Validate() == nil {
		t.Fatal("foreign actor disclosed original recovery")
	}
	result := email.ChangeConfirmResult{Outcome: identity.CommitOutcomeCommitted, Recovery: recovery, Replayed: true}
	if result.Validate() != nil || (email.ChangeRecoveryResult{Outcome: identity.CommitOutcomeNotCommitted, Recovery: recovery}).Validate() != nil {
		t.Fatal("observed metadata-only outcomes denied")
	}
	if (email.ChangeConfirmResult{}).Validate() == nil || (email.ChangeRecoveryResult{}).Validate() == nil {
		t.Fatal("zero outcome treated as observed")
	}
	for _, value := range []any{r, recovery, request, result, email.ChangeRecoveryResult{Outcome: identity.CommitOutcomeUnknown, Recovery: recovery}} {
		if text := fmt.Sprintf("%#v", value); strings.Contains(text, "confirmation-service") || strings.Contains(text, "app.example.test") || !strings.Contains(text, "redacted") {
			t.Fatal("change diagnostics exposed private intent")
		}
		jsonOwner := value.(interface{ MarshalJSON() ([]byte, error) })
		if _, err := jsonOwner.MarshalJSON(); err == nil {
			t.Fatal("change correlation implicitly exported")
		}
	}
}
