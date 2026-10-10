package postgres

import (
	"context"
	"fmt"
	"math"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func passwordUpgradeIntentFixture() PasswordHashUpgradeIntent {
	c := replacementIntentFixture().Credential
	return PasswordHashUpgradeIntent{Admission: CredentialAdmission{Credential: c, UserAuthorityVersion: 19, IdentifierAuthorityVersion: 17, CredentialAuthorityVersion: 13}, ExpectedUserVersion: 11}
}

func passwordUpgradeSpecFixture(t *testing.T, intent PasswordHashUpgradeIntent) identity.FeatureCommandSpec {
	t.Helper()
	s := featureCodecSpec()
	s.Operation = identity.FeatureOperation{Owner: "identity/password", OperationID: "identity.password.signin", SchemaID: "password-signin", SchemaVersion: 1, SubjectRequirement: identity.FeatureSubjectAnonymousFlow, RecordRequirement: identity.FeatureRecordOmitted}
	s.Binding.TenantID, s.Binding.UserID, s.Binding.AnonymousFlowID, s.Binding.RecordID = intent.Admission.Credential.TenantID, "", "original-flow", ""
	s.Binding.OperationID, s.Binding.SchemaID = s.Operation.OperationID, s.Operation.SchemaID
	var err error
	s.Fields, err = PasswordHashUpgradeFields(intent)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPasswordHashUpgradeBindsIndependentFullWidthPredecessors(t *testing.T) {
	for _, v := range []uint64{1, 1<<53 + 1, 1 << 63, math.MaxUint64 - 1} {
		intent := passwordUpgradeIntentFixture()
		intent.ExpectedUserVersion = v
		spec := passwordUpgradeSpecFixture(t, intent)
		got, err := decodePasswordHashUpgrade(spec)
		if err != nil || got != intent {
			t.Fatal("original upgrade predecessors lost", err)
		}
		if fmt.Sprintf("%#v", intent) != "postgres.PasswordHashUpgradeIntent(redacted)" {
			t.Fatal("upgrade metadata exposed")
		}
	}
}

func TestPasswordHashUpgradeRejectsForeignOrExhaustedIntent(t *testing.T) {
	for _, mutate := range []func(*PasswordHashUpgradeIntent){
		func(s *PasswordHashUpgradeIntent) { s.ExpectedUserVersion = 0 },
		func(s *PasswordHashUpgradeIntent) { s.ExpectedUserVersion = math.MaxUint64 },
		func(s *PasswordHashUpgradeIntent) { s.Admission.Credential.Version = math.MaxUint64 },
		func(s *PasswordHashUpgradeIntent) { s.Admission.CredentialAuthorityVersion = math.MaxUint64 },
		func(s *PasswordHashUpgradeIntent) { s.Admission.UserAuthorityVersion = 0 },
		func(s *PasswordHashUpgradeIntent) { s.Admission.IdentifierAuthorityVersion = 0 },
		func(s *PasswordHashUpgradeIntent) { s.Admission.Credential.Owner = "identity/oauth" },
		func(s *PasswordHashUpgradeIntent) { s.Admission.Credential.Kind = identity.CredentialPasskey },
	} {
		intent := passwordUpgradeIntentFixture()
		mutate(&intent)
		if fields, err := PasswordHashUpgradeFields(intent); err == nil || fields != nil {
			t.Fatal("unsafe upgrade projected")
		}
	}
	for _, mutate := range []func(*identity.FeatureCommandSpec){
		func(s *identity.FeatureCommandSpec) { s.Binding.TenantID = "foreign" },
		func(s *identity.FeatureCommandSpec) { s.Binding.UserID = "foreign" },
		func(s *identity.FeatureCommandSpec) { s.Operation.OperationID = "identity.password.change" },
		func(s *identity.FeatureCommandSpec) { s.Fields = s.Fields[:1] },
		func(s *identity.FeatureCommandSpec) { s.Fields = append(s.Fields, s.Fields[0]) },
		func(s *identity.FeatureCommandSpec) { s.Fields[0].Value.Bool = true },
	} {
		s := passwordUpgradeSpecFixture(t, passwordUpgradeIntentFixture())
		mutate(&s)
		if got, err := decodePasswordHashUpgrade(s); err == nil || got != (PasswordHashUpgradeIntent{}) {
			t.Fatal("unbound upgrade accepted")
		}
	}
}

func TestPasswordHashUpgradeRejectsUnownedWork(t *testing.T) {
	w := Work{}
	if err := w.PreparePasswordHashUpgrade(context.Background(), nil, identity.Command{}, RecipientRecord{}); err == nil {
		t.Fatal("zero work reserved upgrade")
	}
	if r, err := w.ApplyPasswordHashUpgrade(context.Background(), nil, identity.Command{}); err == nil || r != (PasswordHashUpgradeReceipt{}) {
		t.Fatal("zero work applied upgrade")
	}
	if r, a, err := w.PasswordHashUpgradeSuccessor(nil); err == nil || r != (RecipientRecord{}) || a != (CredentialAdmission{}) {
		t.Fatal("zero work disclosed successor")
	}
}
