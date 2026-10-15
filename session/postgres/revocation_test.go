package postgres

import (
	"context"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func revokeBinding() identity.CommandBinding {
	op := session.RevokeFamilyOperation()
	return identity.CommandBinding{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", TenantID: "tenant-a", UserID: "user-a", ActorID: "user-a", ActorKind: authorization.SubjectUser, OperationID: op.OperationID, RecordID: "family-a", PolicyID: "session-policy", PolicyVersion: 1, SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, CorrelationID: "correlation-a"}
}

func TestNativeFamilyRevocationMappingRejectsIncompleteIntent(t *testing.T) {
	native, err := session.NewRevokeFamilyCommand(revokeBinding(), 7)
	if err != nil {
		t.Fatal(err)
	}
	mapped, err := MapCommand(native)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := mapped.Feature()
	if s.Operation != session.RevokeFamilyOperation() || s.Binding != revokeBinding() || len(s.Fields) != 1 || s.Fields[0].Name != "expected.version" || s.Fields[0].Value.Uint64 != 7 {
		t.Fatal("native intent not exhaustive")
	}
	if _, err := MapCommand(session.SessionCommand{}); err == nil {
		t.Fatal("zero mapped")
	}
	repo := &Repository{schema: "session_store"}
	p := identitypostgres.CommandPlan{Feature: &identitypostgres.FeatureRegistration{Contributor: repo.Descriptor(), Operation: s.Operation}, SubjectType: "session_family", Lifecycle: &identitypostgres.LifecyclePlan{EventType: "session_family.revoked.v1", BeforeVersion: 7, AfterVersion: 8}, Audits: []identitypostgres.AuditPlan{{EventType: "identity.session.revoke", RetentionClass: "standard", Required: true, RequiredRecordCount: 1, SchemaVersion: 1}}}
	if err := repo.ValidateFeatureCommand(mapped, p); err != nil {
		t.Fatal("native plan rejected", err)
	}
	for _, mutate := range []func(*identity.FeatureCommandSpec){
		func(s *identity.FeatureCommandSpec) { s.Fields = nil },
		func(s *identity.FeatureCommandSpec) { s.Fields[0].Name = "expected.other" },
		func(s *identity.FeatureCommandSpec) {
			s.Fields[0].Value = identity.FeatureValue{Kind: identity.FeatureUint64}
		},
		func(s *identity.FeatureCommandSpec) { s.Fields[0].Value.Uint64 = ^uint64(0) },
		func(s *identity.FeatureCommandSpec) {
			s.Fields = append(s.Fields, identity.FeatureField{Name: "unknown", Value: identity.FeatureValue{Kind: identity.FeatureBool}})
		},
	} {
		bad, _ := mapped.Feature()
		mutate(&bad)
		c, e := identity.NewFeatureCommand(bad)
		if e == nil && repo.ValidateFeatureCommand(c, p) == nil {
			t.Fatal("incomplete/substituted native intent admitted")
		}
	}
	for _, mutate := range []func(*identitypostgres.CommandPlan){
		func(p *identitypostgres.CommandPlan) { p.SubjectType = "session" },
		func(p *identitypostgres.CommandPlan) { p.Audits[0].EventType = "identity.session.create" },
		func(p *identitypostgres.CommandPlan) { p.Audits[0].RetentionClass = "" },
		func(p *identitypostgres.CommandPlan) { p.Lifecycle.AfterVersion++ },
		func(p *identitypostgres.CommandPlan) { p.Lifecycle.EventType = "session.revoked.v1" },
		func(p *identitypostgres.CommandPlan) { p.Audits = nil },
	} {
		bad := p
		l := *p.Lifecycle
		bad.Lifecycle = &l
		bad.Audits = append([]identitypostgres.AuditPlan(nil), p.Audits...)
		mutate(&bad)
		if repo.ValidateFeatureCommand(mapped, bad) == nil {
			t.Fatal("security effect omitted/substituted")
		}
	}
	if _, err := repo.Apply(context.Background(), identitypostgres.Work{}, native); err == nil {
		t.Fatal("zero Work mutated")
	}
	if _, err := repo.RecoverParticipant(context.Background(), identitypostgres.RecoveryWork{}); err == nil {
		t.Fatal("zero recovery admitted")
	}
}
