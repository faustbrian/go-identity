package mfapostgres

import (
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func anonymousUpgradeFactorFixture(t *testing.T, prepare bool) (identity.FeatureCommandSpec, kernel.FeatureRegistration) {
	t.Helper()
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	action, schema, record, requirement := "identity.anonymous.upgrade", "identity.anonymous.upgrade.native-v1", "guest", identity.FeatureRecordRequired
	if prepare {
		schema, record, requirement = "identity.anonymous.upgrade.prepare.native-v1", "", identity.FeatureRecordOmitted
	}
	op := identity.FeatureOperation{Owner: "identity/anonymous", OperationID: action, SchemaID: schema, SchemaVersion: 1, RecordRequirement: requirement}
	s := identity.FeatureCommandSpec{Binding: identity.CommandBinding{CommandID: id, TenantID: "tenant", UserID: "target", ActorID: "target", ActorKind: authorization.SubjectUser, RecordID: record, OperationID: action, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: "upgrade", PolicyVersion: 1, CorrelationID: string(id)}, Operation: op, Fields: []identity.FeatureField{{Name: "mfa.anonymous-upgrade.factor-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: 7}}}}
	return s, kernel.FeatureRegistration{Contributor: kernel.ContributorDescriptor{Owner: "identity/anonymous/postgres", ContractID: "identity.anonymous", Version: 1}, Operation: op}
}

func TestAnonymousUpgradeFactorsFencePermanentTargetNotGuest(t *testing.T) {
	for _, prepare := range []bool{false, true} {
		s, registration := anonymousUpgradeFactorFixture(t, prepare)
		command, err := identity.NewFeatureCommand(s)
		if err != nil {
			t.Fatal(err)
		}
		user, err := anonymousUpgradeFactorSubject(command, s.Binding, registration, 7)
		if err != nil || user != "target" {
			t.Fatal("permanent target factor generation rejected", err)
		}
		for _, change := range []func(*identity.FeatureCommandSpec, *kernel.FeatureRegistration){
			func(s *identity.FeatureCommandSpec, _ *kernel.FeatureRegistration) { s.Binding.ActorID = "guest" },
			func(s *identity.FeatureCommandSpec, _ *kernel.FeatureRegistration) { s.Fields = nil },
			func(s *identity.FeatureCommandSpec, _ *kernel.FeatureRegistration) { s.Fields[0].Value.Uint64++ },
			func(s *identity.FeatureCommandSpec, _ *kernel.FeatureRegistration) {
				s.Fields = append(s.Fields, identity.FeatureField{Name: "mfa.anonymous-upgrade.extra", Value: identity.FeatureValue{Kind: identity.FeatureBool, Bool: true}})
			},
			func(s *identity.FeatureCommandSpec, f *kernel.FeatureRegistration) {
				s.Operation.SchemaID += ".alias"
				s.Binding.SchemaID = s.Operation.SchemaID
				f.Operation = s.Operation
			},
			func(_ *identity.FeatureCommandSpec, f *kernel.FeatureRegistration) {
				f.Contributor.ContractID = "identity.other"
			},
		} {
			s, registration := anonymousUpgradeFactorFixture(t, prepare)
			change(&s, &registration)
			command, err := identity.NewFeatureCommand(s)
			if err == nil {
				if _, err := anonymousUpgradeFactorSubject(command, s.Binding, registration, 7); err == nil {
					t.Fatal("changed or foreign original factor scope admitted")
				}
			}
		}
	}
	if _, err := ReadAnonymousUpgradeFactors(context.Background(), nil, "tenant", "target", time.Second); err == nil {
		t.Fatal("absent factor authority inferred known-empty state")
	}
	if _, err := RequireAnonymousUpgradeFactors(context.Background(), kernel.Work{}, nil, identity.Command{}, 7); err == nil {
		t.Fatal("unowned Work reached factor authority")
	}
}
