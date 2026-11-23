package postgres

import (
	"context"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

type samlLogoutStartParticipant struct{ scopeFeatureParticipant }

func (*samlLogoutStartParticipant) Descriptor() ContributorDescriptor {
	return SSOSAMLLogoutStartDescriptor()
}

func TestSSOSAMLLogoutStartScopeFencesOriginalSession(t *testing.T) {
	ctx := context.Background()
	owner := &samlLogoutStartParticipant{}
	op := SSOSAMLLogoutStartOperation()
	binding := featureCodecSpec().Binding
	binding.OperationID, binding.SchemaID, binding.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	binding.ActorKind, binding.ActorID = authorization.SubjectUser, identity.ActorID(binding.UserID)
	registration := FeatureRegistration{Operation: op, Contributor: owner.Descriptor()}
	lifecycle := LifecyclePlan{EventType: "session.revoked.v1", BeforeVersion: 3, AfterVersion: 4}
	newWork := func() Work {
		f := registration
		return Work{state: &workState{ctx: ctx, binding: binding, feature: &f,
			featureInvocation: owner, subjectType: "session", lifecycle: &workLifecycle{plan: lifecycle}}}
	}
	check := func(w Work) error {
		return w.RequireSSOSAMLLogoutStartScope(ctx, owner, binding.TenantID, binding.UserID, binding.RecordID, 3)
	}
	if err := check(newWork()); err != nil {
		t.Fatal("canonical SAML logout start denied", err)
	}
	for _, tc := range []struct {
		name string
		edit func(*workState)
	}{
		{"different invocation", func(s *workState) { s.featureInvocation = &samlLogoutStartParticipant{} }},
		{"OIDC owner and operation", func(s *workState) {
			s.feature = &FeatureRegistration{Operation: SSOOIDCLogoutOperation(), Contributor: SSOOIDCLogoutDescriptor()}
			s.binding.OperationID, s.binding.SchemaID = s.feature.Operation.OperationID, s.feature.Operation.SchemaID
		}},
		{"alternate contributor", func(s *workState) { s.feature.Contributor.ContractID = "sso.saml-other" }},
		{"preparation", func(s *workState) { s.featurePreparationPlan = &admittedKernelPlan{} }},
		{"tenant", func(s *workState) { s.binding.TenantID = "different-tenant" }},
		{"user", func(s *workState) { s.binding.UserID = "different-user" }},
		{"actor", func(s *workState) { s.binding.ActorID = "different-user" }},
		{"service actor", func(s *workState) { s.binding.ActorKind = authorization.SubjectServiceAccount }},
		{"session", func(s *workState) { s.binding.RecordID = "different-session" }},
		{"session family", func(s *workState) { s.subjectType = "session_family" }},
		{"event", func(s *workState) { s.lifecycle.plan.EventType = "session.created.v1" }},
		{"event index", func(s *workState) { s.lifecycle.plan.EventIndex = 1 }},
		{"version", func(s *workState) { s.lifecycle.plan.BeforeVersion = 2 }},
		{"successor", func(s *workState) { s.lifecycle.plan.AfterVersion = 5 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWork()
			tc.edit(w.state)
			if err := check(w); err == nil || w.usable() == nil {
				t.Fatal("altered SAML logout scope must deny and poison Work")
			}
		})
	}
}

func TestSSOSAMLLogoutStartRegistrySelectsOnlyNativeOwner(t *testing.T) {
	op, descriptor := SSOSAMLLogoutStartOperation(), SSOSAMLLogoutStartDescriptor()
	if op != (identity.FeatureOperation{Owner: "sso/saml", OperationID: "identity.sso.saml-logout-start",
		SchemaID: "sso-enterprise-saml-logout-start-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}) ||
		descriptor != (ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.saml-logout-start", Version: 1}) {
		t.Fatal("SAML logout start changed its exact contract")
	}
	owner := &featureRegistryContributor{descriptor: descriptor, operations: []identity.FeatureOperation{op}}
	registry, err := NewContributorRegistry([]Contributor{owner})
	if err != nil {
		t.Fatal("canonical SAML logout start registration denied", err)
	}
	registration := FeatureRegistration{Operation: op, Contributor: descriptor}
	if entry, err := registry.selectFeatureOperation(registration); err != nil || entry.contributor != owner {
		t.Fatal("canonical SAML logout start did not select its registered owner", err)
	}
	for _, changed := range []FeatureRegistration{
		{Operation: op, Contributor: SSOOIDCLogoutDescriptor()},
		{Operation: SSOOIDCLogoutOperation(), Contributor: descriptor},
		{Operation: op, Contributor: ContributorDescriptor{Owner: "sso/saml", ContractID: descriptor.ContractID, Version: 1}},
		{Operation: identity.FeatureOperation{Owner: descriptor.Owner, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1,
			RecordRequirement: identity.FeatureRecordRequired}, Contributor: descriptor},
	} {
		input := &featureRegistryContributor{descriptor: changed.Contributor, operations: []identity.FeatureOperation{changed.Operation}}
		if accepted, err := NewContributorRegistry([]Contributor{input}); err == nil || accepted != nil {
			t.Fatal("altered SAML logout registered through an owner fallback")
		}
		if _, err := registry.selectFeatureOperation(changed); err == nil {
			t.Fatal("altered SAML logout selected from the frozen registry")
		}
	}
}
