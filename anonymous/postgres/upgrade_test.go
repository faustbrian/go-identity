package anonymouspostgres_test

import (
	"context"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/anonymous"
	anonymouspg "github.com/faustbrian/go-identity/anonymous/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func upgradeMappingFixture(t *testing.T) (identity.FeatureCommandSpec, anonymous.MergePlan) {
	t.Helper()
	spec, source := creationFixture(t)
	guest, _ := source.Record()
	plan := anonymous.MergePlan{Source: source, Target: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Conflicts: []anonymous.Conflict{{Field: "profile.display_name", Disposition: anonymous.KeepTarget}}}
	spec.Binding.UserID, spec.Binding.ActorID, spec.Binding.ActorKind = identity.UserID(plan.Target), identity.ActorID(plan.Target), authorization.SubjectUser
	spec.Binding.AnonymousFlowID, spec.Binding.RecordID = "", string(guest.UserID)
	spec.Binding.OperationID, spec.Binding.SchemaID = "identity.anonymous.upgrade", "identity.anonymous.upgrade.native-v1"
	spec.Operation = identity.FeatureOperation{Owner: "identity/anonymous", OperationID: spec.Binding.OperationID, SchemaID: spec.Binding.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	var err error
	spec.Fields, err = anonymouspg.UpgradeFields(plan)
	if err != nil {
		t.Fatal(err)
	}
	return spec, plan
}

func TestUpgradeMappingBindsBothIdentitiesAndExactTypedMerge(t *testing.T) {
	spec, plan := upgradeMappingFixture(t)
	command, err := identity.NewFeatureCommand(spec)
	if err != nil || anonymouspg.ValidateUpgradePlan(command, plan) != nil {
		t.Fatal("original target/guest/merge mapping", err)
	}
	for _, change := range []func(*identity.FeatureCommandSpec){
		func(s *identity.FeatureCommandSpec) { s.Binding.UserID = identity.UserID(s.Binding.RecordID) },
		func(s *identity.FeatureCommandSpec) { s.Binding.ActorID = identity.ActorID(s.Binding.RecordID) },
		func(s *identity.FeatureCommandSpec) { s.Binding.TenantID = "other" },
		func(s *identity.FeatureCommandSpec) { s.Fields = s.Fields[1:] },
		func(s *identity.FeatureCommandSpec) {
			s.Fields = append(s.Fields, identity.FeatureField{Name: "anonymous.upgrade.extra", Value: identity.FeatureValue{Kind: identity.FeatureBool, Bool: true}})
		},
	} {
		changed := spec
		changed.Fields = append([]identity.FeatureField(nil), spec.Fields...)
		change(&changed)
		command, err := identity.NewFeatureCommand(changed)
		if err == nil && anonymouspg.ValidateUpgradePlan(command, plan) == nil {
			t.Fatal("foreign or incomplete upgrade mapping accepted")
		}
	}
	changed := plan
	changed.Conflicts = []anonymous.Conflict{{Field: "profile.display_name", Disposition: anonymous.KeepSource}}
	if anonymouspg.ValidateUpgradePlan(command, changed) == nil {
		t.Fatal("merge commitment ignored changed disposition")
	}
	var repository *anonymouspg.Repository
	if err := repository.StageUpgrade(context.Background(), kernel.Work{}, nil, identity.Command{}, plan); err == nil {
		t.Fatal("unowned upgrade wrote anonymous metadata")
	}
}
