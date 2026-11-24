package postgres

import (
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
)

const directoryStartTestResource = "sso-directory-v1:59846f63082f79a6ff53aa7c80f5b280d6003afa40dd9ff74ffcce492b7098d3"

func directoryStartCounterCommand(t *testing.T) identity.Command {
	t.Helper()
	s, _ := protectedCommand(t, "directory-tenant").Feature()
	s.Operation = identity.FeatureOperation{Owner: "sso", OperationID: "identity.sso.directory-sync-start", SchemaID: "sso-directory-sync-start-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	s.Binding.OperationID, s.Binding.SchemaID = s.Operation.OperationID, s.Operation.SchemaID
	s.Binding.RecordID = string(s.Binding.CommandID)
	s.Fields = []identity.FeatureField{textField("directory.organization-id", "organization"), textField("directory.source-id", "source"), textField("directory.provider-id", "provider")}
	c, err := identity.NewFeatureCommand(s)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNativeDirectorySyncStartCountersRetainStableResource(t *testing.T) {
	r, err := NewRepository(protectedConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Truncate(time.Microsecond)
	subject := risk.Subject{Actor: "subject", Resource: directoryStartTestResource, Network: "2001:db8::1"}
	original := directoryStartCounterCommand(t)
	mapped, plan, err := r.PrepareCommandCounters(original, subject, at)
	if err != nil || r.ValidateCommandCounters(mapped, plan) != nil {
		t.Fatal("exact start cannot prepare and restore stable-resource counters", err)
	}
	restored, err := r.restoreCounter(mapped, plan)
	if err != nil || restored.subject.Resource != directoryStartTestResource || restored.validateAt(at) != nil || restored.validateAt(at.Add(15*time.Minute)) == nil {
		t.Fatal("start did not retain original stable resource or exclusive expiry", err)
	}
	before, _ := original.Feature()
	after, _ := mapped.Feature()
	if before.Binding != after.Binding {
		t.Fatal("counter preparation changed the generation or original command binding")
	}
	other := directoryStartCounterCommand(t)
	second, secondPlan, err := r.PrepareCommandCounters(other, subject, at)
	if err != nil {
		t.Fatal(err)
	}
	otherRestored, err := r.restoreCounter(second, secondPlan)
	if err != nil || plan == secondPlan || restored.current.Targets[2].Keys[0] != otherRestored.current.Targets[2].Keys[0] {
		t.Fatal("distinct command generations did not share the resource bucket and retain distinct intent", err)
	}
	changeField := func(name string, value identity.FeatureValue) func(*identity.FeatureCommandSpec) {
		return func(s *identity.FeatureCommandSpec) {
			for i := range s.Fields {
				if s.Fields[i].Name == name {
					s.Fields[i].Value = value
					return
				}
			}
			t.Fatal("fixture field missing", name)
		}
	}
	for _, mutate := range []func(*identity.FeatureCommandSpec){
		func(s *identity.FeatureCommandSpec) { s.Binding.CommandID = "AgICAgICAgICAgICAgICAg" },
		func(s *identity.FeatureCommandSpec) { s.Binding.TenantID = "foreign-tenant" },
		func(s *identity.FeatureCommandSpec) { s.Binding.ActorID = "foreign-admin" },
		func(s *identity.FeatureCommandSpec) { s.Operation.Owner = "identity/sso" },
		func(s *identity.FeatureCommandSpec) {
			s.Operation.SchemaID = "other-start-v1"
			s.Binding.SchemaID = s.Operation.SchemaID
		},
		func(s *identity.FeatureCommandSpec) {
			s.Operation.SchemaVersion = 2
			s.Binding.SchemaVersion = 2
		},
		func(s *identity.FeatureCommandSpec) { s.Binding.ActorKind = authorization.SubjectServiceAccount },
		changeField("directory.organization-id", identity.FeatureValue{Kind: identity.FeatureText, Text: "other-organization"}),
		changeField("directory.source-id", identity.FeatureValue{Kind: identity.FeatureText, Text: "other-source"}),
		changeField("directory.provider-id", identity.FeatureValue{Kind: identity.FeatureText, Text: "other-provider"}),
		changeField("directory.source-id", identity.FeatureValue{Kind: identity.FeatureBool}),
		changeField("counter.network", identity.FeatureValue{Kind: identity.FeatureText, Text: "2001:db8::2"}),
		func(s *identity.FeatureCommandSpec) { s.Fields = s.Fields[1:] },
	} {
		s, _ := mapped.Feature()
		mutate(&s)
		bad, err := identity.NewFeatureCommand(s)
		if err == nil && r.ValidateCommandCounters(bad, plan) == nil {
			t.Fatal("changed start scope restored original protected counters")
		}
	}
	for _, mutate := range []func(*identity.FeatureCommandSpec){
		func(s *identity.FeatureCommandSpec) { s.Operation.Owner = "identity/sso" },
		func(s *identity.FeatureCommandSpec) {
			s.Operation.SchemaID = "other-start-v1"
			s.Binding.SchemaID = s.Operation.SchemaID
		},
		func(s *identity.FeatureCommandSpec) {
			s.Operation.SchemaVersion = 2
			s.Binding.SchemaVersion = 2
		},
		func(s *identity.FeatureCommandSpec) {
			s.Operation.RecordRequirement = identity.FeatureRecordOmitted
			s.Binding.RecordID = ""
		},
		func(s *identity.FeatureCommandSpec) {
			s.Operation.SubjectRequirement = identity.FeatureSubjectAnonymousFlow
			s.Binding.UserID, s.Binding.AnonymousFlowID = "", "anonymous-flow"
		},
		func(s *identity.FeatureCommandSpec) { s.Binding.ActorKind = authorization.SubjectServiceAccount },
		func(s *identity.FeatureCommandSpec) { s.Binding.ActorID = "other-user" },
		changeField("directory.organization-id", identity.FeatureValue{Kind: identity.FeatureText}),
		changeField("directory.source-id", identity.FeatureValue{Kind: identity.FeatureText}),
		changeField("directory.provider-id", identity.FeatureValue{Kind: identity.FeatureText}),
		func(s *identity.FeatureCommandSpec) { s.Fields = s.Fields[1:] },
	} {
		s, _ := original.Feature()
		mutate(&s)
		bad, err := identity.NewFeatureCommand(s)
		if err == nil {
			for _, resource := range []string{directoryStartTestResource, s.Binding.RecordID} {
				badSubject := subject
				badSubject.Actor, badSubject.Resource = string(s.Binding.ActorID), resource
				if _, _, err := r.PrepareCommandCounters(bad, badSubject, at); err == nil {
					t.Fatal("non-exact profile prepared directory start counters")
				}
			}
		}
	}
	for _, resource := range []string{"", before.Binding.RecordID, "another-resource"} {
		badSubject := subject
		badSubject.Resource = resource
		if _, _, err := r.PrepareCommandCounters(original, badSubject, at); err == nil {
			t.Fatal("start accepted randomized generation or caller-selected resource")
		}
	}
}
