package postgres

import "testing"

func TestProviderAuthorityMigrationIsAnIndependentForwardOnlyStep(t *testing.T) {
	history, err := (ProviderAuthorityMigrationSource{Schema: "provider_authority_test", Version: 2}).Load(t.Context())
	if err != nil || len(history) != 1 || history[0].Version() != 2 || history[0].DownSQL() != "" {
		t.Fatal("expected one independent forward-only migration", err)
	}
	for _, schema := range []string{"", "public", "identity", "audit", "pg_foo"} {
		if _, err := (ProviderAuthorityMigrationSource{Schema: schema, Version: 2}).Load(t.Context()); err == nil {
			t.Fatalf("accepted reserved schema %q", schema)
		}
	}
	var runtime *ProviderAuthority
	if state, err := runtime.Current(t.Context(), ProviderAuthorityKey{}); err == nil || state != (ProviderAuthorityState{}) {
		t.Fatal("unconfigured reader conveyed provider authority")
	}
	var operator *ProviderAuthorityOperator
	if state, err := operator.Apply(t.Context(), ProviderAuthorityChange{}); err == nil || state != (ProviderAuthorityState{}) {
		t.Fatal("unconfigured operator published a provider transition")
	}
}
