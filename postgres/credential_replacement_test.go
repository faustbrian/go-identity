package postgres

import (
	"context"
	"errors"
	"math"
	"testing"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func replacementIntentFixture() CredentialReplacementIntent {
	s := compromiseIntentFixture()
	return CredentialReplacementIntent{Credential: s.Credential, ExpectedUserVersion: s.ExpectedUserVersion, ExpectedAuthorityVersion: s.ExpectedAuthorityVersion}
}

func TestCredentialReplacementMigrationPreservesInstalledHistory(t *testing.T) {
	base := CredentialMigrationSource{Base: StatusMigrationSource{Base: MigrationSource{}, Version: 12}, Version: 13}
	before, err := base.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got, err := (CredentialReplacementMigrationSource{Base: base, Version: 14}).Load(context.Background())
	if err != nil || len(got) != len(before)+1 {
		t.Fatal("replacement history unavailable", err)
	}
	for i := range before {
		if got[i].Checksum() != before[i].Checksum() {
			t.Fatal("installed credential history changed")
		}
	}
	for _, s := range []CredentialReplacementMigrationSource{{}, {Base: base}, {Base: base, Version: 13}, {Base: base, Version: migrations.Version(math.MaxUint64)}} {
		if rows, e := s.Load(context.Background()); e == nil || rows != nil {
			t.Fatal("invalid history composition returned migrations")
		}
	}
	s := CredentialReplacementMigrationSource{Base: base, Version: 14}
	if rows, e := s.Load(nil); e == nil || rows != nil {
		t.Fatal("nil context admitted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if rows, e := s.Load(ctx); !errors.Is(e, context.Canceled) || rows != nil {
		t.Fatal("migration cancellation lost", e)
	}
}

type replacementMappingPhase struct {
	FeatureExecutionContributor
	intent CredentialReplacementIntent
	err    error
}

func (p replacementMappingPhase) CredentialReplacement(identity.Command) (CredentialReplacementIntent, error) {
	return p.intent, p.err
}

func TestCredentialReplacementMatchesNativeMappingAndFrozenTransition(t *testing.T) {
	intent := replacementIntentFixture()
	s := featureCodecSpec()
	s.Operation = identity.FeatureOperation{Owner: "identity/password", OperationID: "identity.password.change", SchemaID: "password-change", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	s.Binding.TenantID, s.Binding.UserID, s.Binding.RecordID = intent.Credential.TenantID, intent.Credential.UserID, string(intent.Credential.ID)
	s.Binding.OperationID, s.Binding.SchemaID = s.Operation.OperationID, s.Operation.SchemaID
	s.Fields, _ = CredentialReplacementFields(intent)
	command := featureCodecCommand(t, s)
	plan := CommandPlan{SubjectType: "credential", Feature: &FeatureRegistration{Operation: s.Operation}, Lifecycle: &LifecyclePlan{EventType: "password.changed.v1", BeforeVersion: 7, AfterVersion: 8}, Audits: []AuditPlan{{RetentionClass: "protected"}}}
	p := replacementMappingPhase{intent: intent}
	if got, err := replacementCommand(p, command, plan); err != nil || got != intent {
		t.Fatal("exact native replacement denied", err)
	}
	for _, mutate := range []func(*CommandPlan, *replacementMappingPhase){
		func(_ *CommandPlan, p *replacementMappingPhase) { p.intent.ExpectedAuthorityVersion++ },
		func(_ *CommandPlan, p *replacementMappingPhase) { p.err = identity.UnavailableError{} },
		func(s *CommandPlan, _ *replacementMappingPhase) { s.SubjectType = "session" },
		func(s *CommandPlan, _ *replacementMappingPhase) {
			s.Feature.Operation.OperationID = "identity.password.reset-complete"
		},
		func(s *CommandPlan, _ *replacementMappingPhase) { s.Lifecycle.EventType = "password.reset.v1" },
		func(s *CommandPlan, _ *replacementMappingPhase) { s.Lifecycle.BeforeVersion++ },
		func(s *CommandPlan, _ *replacementMappingPhase) { s.Lifecycle.AfterVersion++ },
		func(s *CommandPlan, _ *replacementMappingPhase) { s.Audits[0].RetentionClass = "standard" },
	} {
		copy := plan
		f, l := *plan.Feature, *plan.Lifecycle
		copy.Feature, copy.Lifecycle = &f, &l
		copy.Audits = append([]AuditPlan(nil), plan.Audits...)
		native := p
		mutate(&copy, &native)
		if got, err := replacementCommand(native, command, copy); err == nil || got != (CredentialReplacementIntent{}) {
			t.Fatal("native/frozen replacement mismatch admitted")
		}
	}
	if r, err := (Work{}).StagedCredentialReplacement(); err == nil || r != (CredentialReplacementReceipt{}) {
		t.Fatal("zero Work disclosed replacement")
	}
}

func TestCredentialReplacementIntentBindsIndependentVersions(t *testing.T) {
	for _, v := range []uint64{1, 1<<53 + 1, 1 << 63, math.MaxUint64 - 1} {
		intent := replacementIntentFixture()
		intent.ExpectedAuthorityVersion = v
		fields, err := CredentialReplacementFields(intent)
		if err != nil {
			t.Fatal(err)
		}
		spec := identity.FeatureCommandSpec{Binding: identity.CommandBinding{TenantID: "tenant", UserID: "user", RecordID: "credential"}, Operation: identity.FeatureOperation{Owner: "identity/password"}, Fields: fields}
		got, err := decodeCredentialReplacement(spec)
		if err != nil || got != intent {
			t.Fatal("replacement lost original independent versions", err)
		}
		fields[0].Value.Text = "changed"
		if intent.Credential.ID != "credential" {
			t.Fatal("field projection aliases caller intent")
		}
	}
}

func TestCredentialReplacementRejectsUnboundOrExhaustedIntent(t *testing.T) {
	for _, mutate := range []func(*CredentialReplacementIntent){
		func(s *CredentialReplacementIntent) { s.ExpectedUserVersion = 0 },
		func(s *CredentialReplacementIntent) { s.ExpectedUserVersion = math.MaxUint64 },
		func(s *CredentialReplacementIntent) { s.ExpectedAuthorityVersion = 0 },
		func(s *CredentialReplacementIntent) { s.ExpectedAuthorityVersion = math.MaxUint64 },
		func(s *CredentialReplacementIntent) { s.Credential.Version = 0 },
		func(s *CredentialReplacementIntent) { s.Credential.Version = math.MaxUint64 },
		func(s *CredentialReplacementIntent) {
			s.Credential.Kind = identity.CredentialPasskey
			s.Credential.Owner = "passkey"
		},
		func(s *CredentialReplacementIntent) { s.Credential.Owner = "identity/oauth" },
	} {
		s := replacementIntentFixture()
		mutate(&s)
		if fields, err := CredentialReplacementFields(s); err == nil || fields != nil {
			t.Fatal("unsafe replacement intent accepted")
		}
	}
	fields, _ := CredentialReplacementFields(replacementIntentFixture())
	base := identity.FeatureCommandSpec{Binding: identity.CommandBinding{TenantID: "tenant", UserID: "user", RecordID: "credential"}, Operation: identity.FeatureOperation{Owner: "identity/password"}, Fields: fields}
	for _, mutate := range []func(*identity.FeatureCommandSpec){
		func(s *identity.FeatureCommandSpec) { s.Binding.TenantID = "foreign" },
		func(s *identity.FeatureCommandSpec) { s.Binding.UserID = "foreign" },
		func(s *identity.FeatureCommandSpec) { s.Binding.RecordID = "foreign" },
		func(s *identity.FeatureCommandSpec) { s.Operation.Owner = "passkey" },
		func(s *identity.FeatureCommandSpec) { s.Fields = s.Fields[:1] },
		func(s *identity.FeatureCommandSpec) { s.Fields = append(s.Fields, s.Fields[0]) },
		func(s *identity.FeatureCommandSpec) { s.Fields[0].Value.Bool = true },
	} {
		s := base
		s.Fields = append([]identity.FeatureField(nil), fields...)
		mutate(&s)
		if got, err := decodeCredentialReplacement(s); err == nil || got != (CredentialReplacementIntent{}) {
			t.Fatal("unbound or noncanonical replacement accepted")
		}
	}
}
