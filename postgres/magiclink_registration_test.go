package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func magicLinkRegistrationIntentFixture() MagicLinkRegistrationIntent {
	p := registrationIntentFixture()
	return MagicLinkRegistrationIntent{Creation: p.Creation, Identifier: p.Identifier, ComparisonProfile: p.ComparisonProfile, EmailPossessionPolicyVersion: 3}
}

type magicLinkRegistrationMappingPhase struct {
	MagicLinkConsumptionContributor
	intent MagicLinkRegistrationIntent
}

func (p magicLinkRegistrationMappingPhase) ValidateMagicLinkConsumption(identity.Command, CapabilityPlan) error {
	return nil
}
func (p magicLinkRegistrationMappingPhase) MagicLinkRegistration(identity.Command) (MagicLinkRegistrationIntent, error) {
	return p.intent, nil
}

func TestMagicLinkRegistrationNativeMappingCannotRetargetPlan(t *testing.T) {
	b, plan := magicLinkConsumptionPlanFixture(t)
	intent := magicLinkRegistrationIntentFixture()
	intent.Creation.Binding = b
	intent.Creation.Binding.OperationID, intent.Creation.Binding.AnonymousFlowID, intent.Creation.Binding.UserID, intent.Creation.Binding.SchemaID = "identity.user.create", "", "prospective-user", "fields"
	intent.Identifier.UserID = intent.Creation.Binding.UserID
	digest, err := MagicLinkRegistrationDigest(intent)
	if err != nil {
		t.Fatal(err)
	}
	plan.MagicLinkRegistration = &MagicLinkRegistrationPlan{UserID: intent.Creation.Binding.UserID, IdentifierID: string(intent.Identifier.ID), CreationDigest: digest, EmailPossessionPolicyVersion: 3, CreationEventIndex: 1}
	fields, err := MagicLinkRegistrationFields(intent)
	if err != nil {
		t.Fatal(err)
	}
	command := featureCodecCommand(t, identity.FeatureCommandSpec{Binding: b, Operation: magicLinkConsumeOperation(), Fields: fields})
	owner := magicLinkRegistrationMappingPhase{intent: intent}
	if err := validateMagicLinkConsumption(owner, command, plan); err != nil {
		t.Fatal("native mapping denied", err)
	}
	owner.intent.EmailPossessionPolicyVersion++
	if err := validateMagicLinkConsumption(owner, command, plan); err == nil {
		t.Fatal("changed mailbox policy admitted before SQL")
	}
	owner.intent = intent
	owner.intent.Identifier.CanonicalValue = "other@example.test"
	if err := validateMagicLinkConsumption(owner, command, plan); err == nil {
		t.Fatal("changed prospective mailbox admitted")
	}
}

func TestMagicLinkRegistrationCustodyAndDiagnosticsDeny(t *testing.T) {
	for _, value := range []any{magicLinkRegistrationIntentFixture(), MagicLinkRegistrationDomainConfig{ComparisonProfile: "private-profile", RetainedIdentifierKeys: map[uint32][32]byte{1: {1}}}, MagicLinkRegistrationDomain{comparison: "private-profile"}} {
		if text := fmt.Sprintf("%+v", value); strings.Contains(text, "synthetic@example.test") || strings.Contains(text, "private-profile") {
			t.Fatal("creation diagnostics disclosed metadata")
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("registration custody serialized")
		}
	}
	if got, err := (*MagicLinkRegistrationDomain)(nil).Apply(context.Background(), Work{}, nil, identity.Command{}); err == nil || got != (identity.User{}) {
		t.Fatal("zero Work obtained creation")
	}
	if got, err := (Work{}).StagedMagicLinkRegistrationLifecycle(); err == nil || got != (StagedLifecycle{}) {
		t.Fatal("zero Work obtained lifecycle")
	}
}

func TestMagicLinkRegistrationFieldsBindPasswordlessCreation(t *testing.T) {
	encode := func(s MagicLinkRegistrationIntent) []byte {
		t.Helper()
		fields, err := MagicLinkRegistrationFields(s)
		if err != nil || len(fields) != 10 {
			t.Fatal("passwordless creation unavailable", err)
		}
		for _, f := range fields {
			if f.Name == "registration.credential" {
				t.Fatal("invented password credential")
			}
		}
		mapped, err := encodeFeature(identity.FeatureCommandSpec{Fields: fields}, [32]byte{1})
		if err != nil {
			t.Fatal(err)
		}
		return cborMap(mapped)
	}
	s := magicLinkRegistrationIntentFixture()
	original := encode(s)
	for _, change := range []func(*MagicLinkRegistrationIntent){
		func(s *MagicLinkRegistrationIntent) {
			s.Creation.Binding.UserID = "other"
			s.Identifier.UserID = "other"
		},
		func(s *MagicLinkRegistrationIntent) { s.Creation.Binding.SchemaID = "other" },
		func(s *MagicLinkRegistrationIntent) { s.Creation.Binding.SchemaVersion++ },
		func(s *MagicLinkRegistrationIntent) { s.Creation.Attributes[0].Value.Scalar.String = "changed" },
		func(s *MagicLinkRegistrationIntent) { s.Identifier.ID = "other" },
		func(s *MagicLinkRegistrationIntent) { s.Identifier.CanonicalValue = "other@example.test" },
		func(s *MagicLinkRegistrationIntent) { s.Identifier.DisplayValue = "Other@example.test" },
		func(s *MagicLinkRegistrationIntent) { s.ComparisonProfile = "email-v2" },
		func(s *MagicLinkRegistrationIntent) { s.EmailPossessionPolicyVersion++ },
	} {
		changed := magicLinkRegistrationIntentFixture()
		change(&changed)
		if bytes.Equal(original, encode(changed)) {
			t.Fatal("creation retargeting not bound")
		}
	}
	for _, change := range []func(*MagicLinkRegistrationIntent){
		func(s *MagicLinkRegistrationIntent) { s.Identifier.Verified = true },
		func(s *MagicLinkRegistrationIntent) { s.Identifier.Primary = true },
		func(s *MagicLinkRegistrationIntent) { s.Identifier.Version++ },
		func(s *MagicLinkRegistrationIntent) { s.Identifier.Kind = identity.IdentifierPhone },
		func(s *MagicLinkRegistrationIntent) { s.Identifier.UserID = "other" },
		func(s *MagicLinkRegistrationIntent) { s.EmailPossessionPolicyVersion = 0 },
		func(s *MagicLinkRegistrationIntent) { s.ComparisonProfile = "" },
		func(s *MagicLinkRegistrationIntent) { s.Creation.Status = identity.StatusSuspended },
	} {
		changed := magicLinkRegistrationIntentFixture()
		change(&changed)
		if fields, err := MagicLinkRegistrationFields(changed); err == nil || fields != nil {
			t.Fatal("caller-supplied creation authority admitted")
		}
	}
}
