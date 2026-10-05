package postgres

import (
	"context"
	"testing"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func TestSingleRevocationMappingRetainsCompleteOriginalRecord(t *testing.T) {
	record, _, profile := identifierSessionFixture(t)
	spec, _ := record.Bindings()
	b := revokeBinding()
	op := session.RevokeOneOperation()
	b.OperationID, b.SchemaID, b.RecordID = op.OperationID, op.SchemaID, spec.SessionID
	native, err := session.NewRevokeOneCommand(b, record)
	if err != nil {
		t.Fatal(err)
	}
	mapped, err := MapCommand(native)
	if err != nil {
		t.Fatal("one-session transition missing", err)
	}
	restored, err := nativeRevokeOne(mapped)
	if err != nil {
		t.Fatal(err)
	}
	projection, ok := restored.RevokeOne()
	got, _ := projection.Session.Bindings()
	gotAuthority, _ := got.Authority.Bindings()
	wantAuthority, _ := spec.Authority.Bindings()
	gotRemember, _ := got.Remember.Bindings()
	wantRemember, _ := spec.Remember.Bindings()
	if gotAuthority != wantAuthority || gotRemember != wantRemember {
		t.Fatal("authority or policy altered")
	}
	got.Authority, got.Remember = spec.Authority, spec.Remember
	if !ok || projection.Binding != b || got != spec {
		t.Fatal("original target or vector lost")
	}
	repo := &Repository{schema: "session_store", issueAdmission: (*IssueAdmissionConfig)(&profile)}
	plan := kernel.CommandPlan{Feature: &kernel.FeatureRegistration{Contributor: repo.Descriptor(), Operation: op}, SubjectType: "session", Lifecycle: &kernel.LifecyclePlan{EventType: "session.revoked.v1", BeforeVersion: spec.Version, AfterVersion: spec.Version + 1}, Audits: []kernel.AuditPlan{{EventType: "identity.session.revoke", SchemaVersion: 1, Required: true, RequiredRecordCount: 1, RetentionClass: "standard"}}}
	if err := repo.ValidateFeatureCommand(mapped, plan); err != nil {
		t.Fatal("complete one-session plan denied", err)
	}
	for _, change := range []func(*kernel.CommandPlan){
		func(p *kernel.CommandPlan) { p.SubjectType = "session_family" },
		func(p *kernel.CommandPlan) { p.Lifecycle.EventType = "session_family.revoked.v1" },
		func(p *kernel.CommandPlan) { p.Lifecycle.AfterVersion++ },
		func(p *kernel.CommandPlan) { p.Audits = nil },
		func(p *kernel.CommandPlan) { p.Audits[0].EventType = "identity.session.create" },
	} {
		bad := plan
		lifecycle := *plan.Lifecycle
		bad.Lifecycle = &lifecycle
		bad.Audits = append([]kernel.AuditPlan(nil), plan.Audits...)
		change(&bad)
		if repo.ValidateFeatureCommand(mapped, bad) == nil {
			t.Fatal("misdeclared effect admitted")
		}
	}
	for _, change := range []func(*identity.FeatureCommandSpec){
		func(p *identity.FeatureCommandSpec) { p.Fields = p.Fields[1:] },
		func(p *identity.FeatureCommandSpec) {
			p.Fields = append(p.Fields, identity.FeatureField{Name: "unknown", Value: identity.FeatureValue{Kind: identity.FeatureBool}})
		},
		func(p *identity.FeatureCommandSpec) { p.Operation = session.RevokeFamilyOperation() },
	} {
		bad, _ := mapped.Feature()
		change(&bad)
		altered, err := identity.NewFeatureCommand(bad)
		if err == nil && repo.ValidateFeatureCommand(altered, plan) == nil {
			t.Fatal("incomplete native schema admitted")
		}
	}
	if (&Repository{schema: "session_store"}).ValidateFeatureCommand(mapped, plan) == nil {
		t.Fatal("unconfigured owner admitted")
	}
	if _, err := repo.Apply(context.Background(), kernel.Work{}, native); err == nil {
		t.Fatal("unowned Work admitted")
	}
}
