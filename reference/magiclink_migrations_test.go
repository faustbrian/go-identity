package reference

import (
	"context"
	magicpg "github.com/faustbrian/go-identity/magiclink/postgres"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	"testing"
)

func TestMagicLinkMigrationsRetainExistingPrefix(t *testing.T) {
	c := featureMigrationConfig{otpSchema: "otp_store", sessionSchema: "session_store", signinSchema: "session_store", global: "deployment"}
	s := StoreSet{state: &storeState{config: VelocityStoreConfiguration{Schema: "risk_store"}, httpRate: &httpRateState{}, features: &featureState{migrations: c}}}
	before, err := s.migrationCatalog(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	s.state.features.magicRequest = &magicpg.RequestService{}
	s.state.features.magicConsume = &magicpg.ConsumeService{}
	s.state.features.migrations.magicSessionSchema = "session_store"
	s.state.features.httpMagicLink = &magicLinkHTTPState{config: HTTPMagicLinkConfiguration{Consume: true}}
	after, err := s.migrationCatalog(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for i, m := range before[0].history {
		if m != after[0].history[i] {
			t.Fatal("magic-link rewrote installed shared prefix")
		}
	}
	want := map[string]bool{"identity_mfa": true, "identity_capability": true, "identity_magiclink_session": true, "identity_password_session": true, "identity_registration_session": true, "identity_password_change_session": true}
	for _, h := range after {
		delete(want, h.namespace)
		if h.namespace == "identity_http_rate" && len(h.history) != 2 {
			t.Fatal("native atomic rate migration absent")
		}
	}
	if len(want) != 0 {
		t.Fatal("native consuming prerequisites absent", want)
	}
}

func TestMagicLinkMFASelectedMigrationsPreserveFactorPrefix(t *testing.T) {
	base, err := (mfapg.MigrationSource{Version: 1}).Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	previous := []migrationHistory{{namespace: "identity_mfa", history: base, owners: map[migrations.Version]ModuleID{1: "identity/mfa/postgres"}}}
	selected, err := magicLinkMigrationCatalog(context.Background(), previous, "session_store", true)
	if err != nil {
		t.Fatal(err)
	}
	for _, history := range selected {
		if history.namespace != "identity_mfa" {
			continue
		}
		if len(history.history) != 3 || history.history[0] != base[0] || history.history[1].Version() != 2 || history.history[2].Version() != 3 || history.owners[2] != "identity/mfa/postgres" || history.owners[3] != "identity/mfa/postgres" || len(history.guards) != 2 {
			t.Fatal("selected challenge lacks owned durable continuation/TOTP histories or rewrites installed factors")
		}
		return
	}
	t.Fatal("MFA physical history absent")
}
