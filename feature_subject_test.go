package identity_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
)

func anonymousFeatureSpec() identity.FeatureCommandSpec {
	return identity.FeatureCommandSpec{
		Operation: identity.FeatureOperation{Owner: "identity/risk", OperationID: "identity.risk.captcha", SchemaID: "captcha-anonymous-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow},
		Binding:   identity.CommandBinding{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", TenantID: "tenant", AnonymousFlowID: "anonymous-flow", ActorID: "verified-service", ActorKind: authorization.SubjectServiceAccount, OperationID: "identity.risk.captcha", PolicyID: "policy", PolicyVersion: 1, SchemaID: "captcha-anonymous-v1", SchemaVersion: 1, CorrelationID: "correlation", RecordID: "evidence-command"},
	}
}

func TestFeatureAnonymousSubjectIsExplicitAndNeverAUser(t *testing.T) {
	s := anonymousFeatureSpec()
	c, err := identity.NewFeatureCommand(s)
	if err != nil {
		t.Fatal("explicit anonymous subject rejected", err)
	}
	got, ok := c.Feature()
	if !ok || got.Binding.UserID != "" || got.Binding.AnonymousFlowID != "anonymous-flow" || got.Binding.ActorID != "verified-service" || got.Operation.SubjectRequirement != identity.FeatureSubjectAnonymousFlow {
		t.Fatal("anonymous scope confused with user or actor")
	}
	s.Binding.AnonymousFlowID = "changed"
	again, _ := c.Feature()
	if again.Binding.AnonymousFlowID != "anonymous-flow" {
		t.Fatal("command did not freeze anonymous scope")
	}
	for _, mutate := range []func(*identity.FeatureCommandSpec){
		func(s *identity.FeatureCommandSpec) { s.Binding.UserID = "user" },
		func(s *identity.FeatureCommandSpec) { s.Binding.AnonymousFlowID = "" },
		func(s *identity.FeatureCommandSpec) { s.Binding.AnonymousFlowID = strings.Repeat("x", 129) },
		func(s *identity.FeatureCommandSpec) { s.Binding.AnonymousFlowID = "bad flow" },
		func(s *identity.FeatureCommandSpec) { s.Binding.ActorID = "" },
		func(s *identity.FeatureCommandSpec) { s.Binding.ActorKind = "anonymous" },
		func(s *identity.FeatureCommandSpec) { s.Operation.SubjectRequirement = 255 },
		func(s *identity.FeatureCommandSpec) { s.Operation.SubjectRequirement = identity.FeatureSubjectUser },
	} {
		changed := anonymousFeatureSpec()
		mutate(&changed)
		if _, err := identity.NewFeatureCommand(changed); err == nil {
			t.Fatal("mixed, missing or invalid scope accepted")
		}
	}
}

func TestFeatureUserSubjectAndKernelRemainClosed(t *testing.T) {
	s := anonymousFeatureSpec()
	s.Operation.SubjectRequirement = identity.FeatureSubjectUser
	s.Binding.UserID, s.Binding.AnonymousFlowID = "user", ""
	if _, err := identity.NewFeatureCommand(s); err != nil {
		t.Fatal("legacy user feature rejected", err)
	}
	s.Binding.AnonymousFlowID = "anonymous-flow"
	if _, err := identity.NewFeatureCommand(s); err == nil {
		t.Fatal("user schema admitted anonymous target")
	}
	b := s.Binding
	b.OperationID, b.RecordID = "identity.user.create", ""
	if _, err := identity.NewUserCreationCommand(identity.CreateUserCommand{Binding: b, Status: identity.StatusActive}); err == nil {
		t.Fatal("kernel ignored anonymous scope")
	}
	s.Binding.AnonymousFlowID = ""
	binding, err := json.Marshal(s.Binding)
	if err != nil || strings.Contains(string(binding), "AnonymousFlowID") {
		t.Fatal("legacy serialized binding changed shape", err)
	}
	operation, err := json.Marshal(s.Operation)
	if err != nil || strings.Contains(string(operation), "SubjectRequirement") {
		t.Fatal("legacy serialized descriptor changed shape", err)
	}
}
