package postgres

import (
	"context"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func TestManagedEmailPreparationRejectsZeroComposition(t *testing.T) {
	for _, c := range []*Coordinator{nil, {}} {
		for _, ctx := range []context.Context{nil, context.Background()} {
			binding, wire, generation, err := c.QueryManagedEmailPreparation(ctx, identity.RecoveryQuery{}, authorization.DecisionContext{}, FeatureRegistration{}, nil)
			if err == nil || binding != (identity.CommandBinding{}) || wire != nil || generation != 0 {
				t.Fatal("invalid management composition disclosed intent")
			}
		}
	}
}

func TestManagedEmailOriginHasClosedConfirmationMapping(t *testing.T) {
	for _, request := range []string{"identity.email.verification-send", "identity.email.change-request"} {
		confirm := "identity.email.verification-confirm"
		if request == "identity.email.change-request" {
			confirm = "identity.email.change-confirm"
		}
		feature := FeatureRegistration{Contributor: ContributorDescriptor{Owner: "identity/email/postgres", ContractID: "identity.email", Version: 1}, Operation: identity.FeatureOperation{Owner: "identity/email", OperationID: request, SchemaID: request + ".native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}}
		if !managedEmailOriginOperation(feature, confirm) {
			t.Fatal("original request lost its confirmation action")
		}
		for _, mutate := range []func(*FeatureRegistration){
			func(f *FeatureRegistration) { f.Contributor.Owner = "identity/password/postgres" },
			func(f *FeatureRegistration) { f.Contributor.ContractID = "identity.password" },
			func(f *FeatureRegistration) { f.Contributor.Version++ },
			func(f *FeatureRegistration) { f.Operation.Owner = "identity/password" },
			func(f *FeatureRegistration) { f.Operation.OperationID = "identity.password.signup" },
			func(f *FeatureRegistration) { f.Operation.SchemaID = request + ".other" },
			func(f *FeatureRegistration) { f.Operation.SchemaVersion++ },
			func(f *FeatureRegistration) { f.Operation.SubjectRequirement = identity.FeatureSubjectAnonymousFlow },
			func(f *FeatureRegistration) { f.Operation.RecordRequirement = 0 },
		} {
			other := feature
			mutate(&other)
			if managedEmailOriginOperation(other, confirm) {
				t.Fatal("foreign operation acquired management-origin disclosure")
			}
		}
		for _, other := range []string{"", request, "identity.password.signup", "identity.email.address-remove"} {
			if managedEmailOriginOperation(feature, other) {
				t.Fatal("unrelated action acquired original output")
			}
		}
	}
}

func TestOTPChangeOriginCannotSelectGenericPendingVerification(t *testing.T) {
	change := FeatureRegistration{Contributor: ContributorDescriptor{Owner: "identity/email/postgres", ContractID: "identity.email", Version: 1}, Operation: identity.FeatureOperation{Owner: "identity/email", OperationID: "identity.email.change-request", SchemaID: "identity.email.change-request.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}}
	verification := change
	verification.Operation.OperationID = "identity.email.verification-send"
	verification.Operation.SchemaID = "identity.email.verification-send.native-v1"
	for _, action := range []string{"identity.otp.email-change-request", "identity.otp.email-change-confirm", "identity.otp.email-change-confirm.recover"} {
		if !managedEmailOriginOperation(change, action) {
			t.Fatal("OTP change cannot read its actual committed change origin")
		}
		if managedEmailOriginOperation(verification, action) {
			t.Fatal("ordinary pending verification became replacement authority")
		}
		resend := verification
		resend.Operation = emailResendOperation()
		if managedEmailOriginOperation(resend, action) {
			t.Fatal("resend origin became replacement authority")
		}
	}
	for _, action := range []string{"identity.otp.send", "identity.otp.email-verify", "identity.otp.signin", "identity.otp.email-change-request.recover"} {
		if managedEmailOriginOperation(change, action) {
			t.Fatal("unselected OTP action disclosed change custody")
		}
	}
}
