package phone_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/phone"
)

func TestPhoneUpdateRecoveryRetainsOriginalCodeFreeScope(t *testing.T) {
	submission := verificationRequest(t)
	caller := submission.Caller.Clone()
	caller.Request.Action = "identity.phone.update.recover"
	caller.Request.Subject.Groups = []authorization.SubjectID{"original"}
	spec := phone.UpdateRecoveryRequestSpec{TenantID: submission.TenantID, UserID: submission.UserID, Caller: caller, Flow: submission.Flow, Recovery: phoneRecovery(t, submission), CSRFToken: submission.CSRFToken}
	request, err := phone.NewUpdateRecoveryRequest(spec)
	if err != nil {
		t.Fatal(err)
	}
	spec.Caller.Request.Subject.Groups[0] = "changed"
	got, err := request.Bindings()
	if err != nil || got.Caller.Request.Subject.Groups[0] != "original" {
		t.Fatal("historical custody aliased caller", err)
	}
	for name, alter := range map[string]func(*phone.UpdateRecoveryRequestSpec){
		"tenant":            func(r *phone.UpdateRecoveryRequestSpec) { r.TenantID = "foreign" },
		"user":              func(r *phone.UpdateRecoveryRequestSpec) { r.UserID = "foreign" },
		"enrollment-action": func(r *phone.UpdateRecoveryRequestSpec) { r.Caller.Request.Action = "identity.phone.verify.recover" },
		"execute-action":    func(r *phone.UpdateRecoveryRequestSpec) { r.Caller.Request.Action = "identity.phone.update" },
		"missing-flow":      func(r *phone.UpdateRecoveryRequestSpec) { r.Flow = otp.SendFlow{} },
		"missing-original":  func(r *phone.UpdateRecoveryRequestSpec) { r.Recovery = phone.VerificationRecovery{} },
	} {
		t.Run(name, func(t *testing.T) {
			r := got
			r.Caller = got.Caller.Clone()
			alter(&r)
			if _, err := phone.NewUpdateRecoveryRequest(r); err == nil {
				t.Fatal("substituted history admitted")
			}
		})
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if strings.Contains(fmt.Sprintf(format, struct{ private any }{request}), string(submission.SendCommandID)) {
			t.Fatal("historical correlation leaked in nested diagnostics")
		}
	}
	if _, err := json.Marshal(request); err == nil {
		t.Fatal("implicit history export allowed")
	}
}

func TestPhoneUpdateResultCorrelatesOriginalAttempt(t *testing.T) {
	submission := verificationRequest(t)
	recovery := phoneRecovery(t, submission)
	original, err := recovery.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	b := identity.CommandBinding{CommandID: original.Attempt.CommandID, TenantID: submission.TenantID, UserID: submission.UserID, ActorID: identity.ActorID(submission.UserID), ActorKind: authorization.SubjectUser, RecordID: "original-phone", OperationID: "identity.phone.update", SchemaID: "identity.phone.update.native-v1", SchemaVersion: 1, PolicyID: "phone-change", PolicyVersion: 1, CorrelationID: string(original.Attempt.CommandID)}
	op := identity.FeatureOperation{Owner: "identity/phone", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	r := phone.UpdateResult{Result: identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeUnknown, Feature: &identity.FeatureReceipt{Operation: op}}, Recovery: recovery}
	if err := r.Validate(); err != nil {
		t.Fatal("original ambiguous result discarded", err)
	}
	r.Result.Binding.CommandID = submission.SendCommandID
	if err := r.Validate(); err == nil {
		t.Fatal("send substituted for original consuming attempt")
	}
	if err := (phone.UpdateResult{}).Validate(); err == nil {
		t.Fatal("zero completion result accepted")
	}
}
