package postgres

import (
	"context"
	"errors"
	"math"
	"testing"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func compromiseIntentFixture() CredentialCompromiseIntent {
	return CredentialCompromiseIntent{Credential: identity.CredentialRef{ID: "credential", TenantID: "tenant", UserID: "user", Kind: identity.CredentialPassword, Owner: "identity/password", Version: 7}, ExpectedUserVersion: 11, ExpectedAuthorityVersion: 13}
}

func TestCredentialCompromiseMigrationPreservesHistory(t *testing.T) {
	base := CredentialMigrationSource{Base: StatusMigrationSource{Base: MigrationSource{}, Version: 12}, Version: 13}
	history, err := base.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	s := CredentialCompromiseMigrationSource{Base: base, Version: 14}
	got, err := s.Load(context.Background())
	if err != nil || len(got) != len(history)+1 {
		t.Fatal("allocated history", err)
	}
	for i := range history {
		if got[i].Checksum() != history[i].Checksum() {
			t.Fatal("installed history changed")
		}
	}
	for _, invalid := range []CredentialCompromiseMigrationSource{{}, {Base: base}, {Base: base, Version: 13}, {Base: base, Version: migrations.Version(math.MaxUint64)}} {
		if rows, e := invalid.Load(context.Background()); e == nil || rows != nil {
			t.Fatal("invalid composition returned partial history")
		}
	}
	if rows, e := s.Load(nil); e == nil || rows != nil {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if rows, e := s.Load(ctx); !errors.Is(e, context.Canceled) || rows != nil {
		t.Fatal("cancellation lost", e)
	}
}

func TestCredentialCompromiseIntentBindsIndependentVersions(t *testing.T) {
	intent := compromiseIntentFixture()
	for _, v := range []uint64{1, 1<<53 + 1, 1 << 63, math.MaxUint64 - 1} {
		intent.ExpectedAuthorityVersion = v
		fields, err := CredentialCompromiseFields(intent)
		if err != nil {
			t.Fatal(err)
		}
		spec := identity.FeatureCommandSpec{Binding: identity.CommandBinding{TenantID: "tenant", UserID: "user", RecordID: "credential"}, Operation: identity.FeatureOperation{Owner: "identity/password"}, Fields: fields}
		got, err := decodeCredentialCompromise(spec)
		if err != nil || got != intent {
			t.Fatal("exact independent intent changed", err)
		}
	}
}

func TestCredentialCompromiseIntentRejectsUnboundOrExhausted(t *testing.T) {
	for _, mutate := range []func(*CredentialCompromiseIntent){
		func(c *CredentialCompromiseIntent) { c.ExpectedUserVersion = 0 },
		func(c *CredentialCompromiseIntent) { c.ExpectedUserVersion = math.MaxUint64 },
		func(c *CredentialCompromiseIntent) { c.ExpectedAuthorityVersion = 0 },
		func(c *CredentialCompromiseIntent) { c.ExpectedAuthorityVersion = math.MaxUint64 },
		func(c *CredentialCompromiseIntent) { c.Credential.Version = 0 },
		func(c *CredentialCompromiseIntent) { c.Credential.Version = math.MaxUint64 },
		func(c *CredentialCompromiseIntent) { c.Credential.Owner = "identity/oauth" },
	} {
		c := compromiseIntentFixture()
		mutate(&c)
		if fields, err := CredentialCompromiseFields(c); err == nil || fields != nil {
			t.Fatal("invalid compromise intent accepted")
		}
	}
	c := compromiseIntentFixture()
	fields, _ := CredentialCompromiseFields(c)
	base := identity.FeatureCommandSpec{Binding: identity.CommandBinding{TenantID: "tenant", UserID: "user", RecordID: "credential"}, Operation: identity.FeatureOperation{Owner: "identity/password"}, Fields: fields}
	for _, change := range []func(*identity.FeatureCommandSpec){
		func(s *identity.FeatureCommandSpec) { s.Binding.TenantID = "foreign" },
		func(s *identity.FeatureCommandSpec) { s.Binding.UserID = "foreign" },
		func(s *identity.FeatureCommandSpec) { s.Binding.RecordID = "foreign" },
		func(s *identity.FeatureCommandSpec) { s.Operation.Owner = "passkey" },
		func(s *identity.FeatureCommandSpec) { s.Fields = s.Fields[:1] },
		func(s *identity.FeatureCommandSpec) { s.Fields = append(s.Fields, s.Fields[0]) },
	} {
		s := base
		s.Fields = append([]identity.FeatureField(nil), base.Fields...)
		change(&s)
		if got, err := decodeCredentialCompromise(s); err == nil || got != (CredentialCompromiseIntent{}) {
			t.Fatal("unbound/partial metadata accepted")
		}
	}
}
