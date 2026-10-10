package postgres

import (
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
)

type verificationCounterPreparer interface {
	PrepareVerificationCommandCounters(identity.Command, risk.Subject, string, time.Time) (identity.Command, kernel.CommandCounterPlan, error)
}

func TestNativeVerificationCounterPreparation(t *testing.T) {
	r, err := NewRepository(protectedConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	owner, ok := any(r).(verificationCounterPreparer)
	if !ok {
		t.Fatal("native sessionless verification counter preparation is missing")
	}
	s, _ := protectedCommand(t, "verification-tenant").Feature()
	s.Operation = identity.FeatureOperation{Owner: "identity/email", OperationID: "identity.email.verification-confirm", SchemaID: "identity.email.verification-confirm.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	s.Binding.OperationID, s.Binding.SchemaID = s.Operation.OperationID, s.Operation.SchemaID
	original, err := identity.NewFeatureCommand(s)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Truncate(time.Microsecond)
	subject := risk.Subject{User: "subject", Network: "2001:db8::1"}
	mapped, plan, err := owner.PrepareVerificationCommandCounters(original, subject, "original-grant", at)
	if err != nil || r.ValidateCommandCounters(mapped, plan) != nil {
		t.Fatal("native proof-bound projection cannot restore", err)
	}
	if r.ValidateCommandCounters(original, plan) == nil {
		t.Fatal("unprepared command admitted")
	}
	if _, _, err := r.PrepareCommandCounters(original, subject, at); err == nil {
		t.Fatal("normal session profile widened")
	}
	if _, _, err := owner.PrepareVerificationCommandCounters(mapped, subject, "original-grant", at); err == nil {
		t.Fatal("counter fields were admitted twice")
	}
	metadata, _ := mapped.Feature()
	for n := range metadata.Fields {
		if metadata.Fields[n].Name == "counter.capability" {
			metadata.Fields[n].Value.Text = "foreign-grant"
		}
	}
	changed, err := identity.NewFeatureCommand(metadata)
	if err != nil || r.ValidateCommandCounters(changed, plan) == nil {
		t.Fatal("foreign grant preserved the original projection", err)
	}
	wrong := subject
	wrong.User = "foreign"
	if _, _, err := owner.PrepareVerificationCommandCounters(original, wrong, "original-grant", at); err == nil {
		t.Fatal("foreign signed subject admitted")
	}
}
