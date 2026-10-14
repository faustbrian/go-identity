package reference

import (
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestPreAuthSelectionAndLifetime(t *testing.T) {
	for _, f := range []FeatureSet{{}, {state: &storeState{features: &featureState{composed: true}}}} {
		if owner, err := f.PreAuth(); owner != nil || err == nil {
			t.Fatal("unselected initiation exposed")
		}
	}
	lifetime, cancel := context.WithCancel(context.Background())
	defer cancel()
	drained := make(chan struct{})
	close(drained)
	s := &storeState{lifetime: lifetime, cancel: cancel, drained: drained,
		features: &featureState{composed: true, timeout: time.Second, preauth: &session.PreAuthIssuer{}}}
	owner, err := (FeatureSet{state: s}).PreAuth()
	if err != nil || owner == nil {
		t.Fatal("selected initiation unavailable", err)
	}
	deny := func() {
		t.Helper()
		if _, err := owner.Prepare(context.Background(), session.PreAuthPrepareInput{}); err == nil {
			t.Fatal("inactive/foreign tenant prepared flow")
		}
		if _, err := owner.Issue(context.Background(), session.PreparedPreAuthIssuance{}); err == nil {
			t.Fatal("inactive/foreign preparation issued flow")
		}
		if _, err := owner.Recover(context.Background(), session.PreAuthIssueCommand{}); err == nil {
			t.Fatal("inactive/foreign recovery admitted")
		}
		if s.active != 0 {
			t.Fatal("initiation leaked graph admission")
		}
	}
	deny()
	s.features.ready = true
	deny()
	s.closed = true
	cancel()
	deny()
	if owner, err := (FeatureSet{state: s}).PreAuth(); owner != nil || err == nil {
		t.Fatal("closed graph exposed initiation")
	}
}

func TestPreAuthInitiationDoesNotPreventLaterSigninSelection(t *testing.T) {
	c := featureMigrationConfig{otpSchema: "otp_store", sessionSchema: "preauth_store", global: "deployment", preauthIssue: true}
	s := StoreSet{state: &storeState{config: VelocityStoreConfiguration{Schema: "risk_store"}, features: &featureState{migrations: c}}}
	before, err := s.MigrationSource().Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	records := make([]migrations.Record, len(before))
	for i, step := range before {
		records[i], err = migrations.NewRecord(migrations.RecordKindMigration, step.Version(), step.Name(), step.Checksum(), time.Unix(1700000000, 0), time.Millisecond, false)
		if err != nil {
			t.Fatal(err)
		}
	}
	s.state.features.migrations.signinSchema = "preauth_store"
	after, err := s.MigrationSource().Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = migrations.PlanUp(after, records); err != nil {
		t.Fatal("owned initiation prevents later signin selection", err)
	}
}

func TestPreAuthPlanUsesEachPhysicalHistoryVersion(t *testing.T) {
	a := planFixture(t, "a", "identity/session/postgres", 2)
	record, err := migrations.NewRecord(migrations.RecordKindMigration, a.history.history[0].Version(), "step", a.history.history[0].Checksum(), time.Unix(1700000000, 0), time.Millisecond, false)
	if err != nil {
		t.Fatal(err)
	}
	a.records = []migrations.Record{record}
	a.statuses = a.history.project(a.records)
	b := planFixture(t, "b", "identity/session/postgres", 1)
	plan, err := buildMigrationPlan([]migrationSnapshot{a, b}, []ModuleID{"identity/session/postgres"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Modules[0].Version != 1 || len(plan.Steps) != 2 || plan.Steps[0].FromVersion != 1 || plan.Steps[1].FromVersion != 0 {
		t.Fatal("independent history adopted another history's current version", plan.Modules, plan.Steps)
	}
}

func TestPreAuthMigrationStatusRetainsAllHistoryFailures(t *testing.T) {
	for _, state := range []MigrationCompatibility{MigrationRequired, MigrationIncompatible, MigrationDirty} {
		bad := ModuleMigrationStatus{Module: "identity/session/postgres", CurrentVersion: 1201, RequiredVersion: 1416, Compatibility: state}
		good := ModuleMigrationStatus{Module: bad.Module, CurrentVersion: 1420, RequiredVersion: 1420, Compatibility: MigrationCompatible}
		for _, pair := range [][2]ModuleMigrationStatus{{bad, good}, {good, bad}} {
			out := mergeMigrationStatus(pair[0], pair[1])
			if out.Compatibility != state || out.CurrentVersion != 1420 || out.RequiredVersion != 1420 {
				t.Fatal("independent successful history hid incomplete owner", out)
			}
		}
	}
}
