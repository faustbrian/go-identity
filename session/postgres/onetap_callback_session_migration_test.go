package postgres

import (
	"context"
	"errors"
	"math"
	"testing"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestOneTapCallbackSessionMigrationRequiresExplicitExpansionAndValidation(t *testing.T) {
	valid := OneTapCallbackSessionMigrationSource{Schema: "session_store", Version: 91, ValidationVersion: 92, PreviousConstraint: "session_issuances_purpose_v4"}
	steps, err := valid.Load(t.Context())
	if err != nil || len(steps) != 2 {
		t.Fatalf("want separate expansion and validation: %v", err)
	}
	if steps[0].Version() != 91 || steps[1].Version() != 92 || steps[0].DownSQL() != "" || steps[1].DownSQL() != "" {
		t.Fatal("want ordered forward-only migrations")
	}
	for _, previous := range []string{
		"session_issuances_purpose_check", "session_issuances_purpose_v2", "session_issuances_purpose_v3",
		"session_issuances_purpose_v4", "session_issuances_purpose_v5", "session_issuances_purpose_v6",
		"session_issuances_purpose_v7", "session_issuances_purpose_v8", "session_issuances_purpose_username_v1",
		"session_issuances_purpose_phone_password_v1", "session_issuances_purpose_phone_otp_v1",
		"session_issuances_purpose_anonymous_v1", "session_issuances_purpose_anonymous_upgrade_v1",
		"session_issuances_purpose_passkey_v1", "session_issuances_purpose_passkey_signup_v1",
		"session_issuances_purpose_oauth_v1", "session_issuances_purpose_sso_oidc_v1",
		"session_issuances_purpose_sso_oauth2_v1", "session_issuances_purpose_sso_saml_v1",
		"session_issuances_purpose_sso_saml_idp_v1",
	} {
		source := valid
		source.PreviousConstraint = previous
		if steps, err := source.Load(t.Context()); err != nil || len(steps) != 2 {
			t.Fatalf("supported predecessor %s rejected: %v", previous, err)
		}
	}

	for _, test := range []struct {
		name   string
		change func(*OneTapCallbackSessionMigrationSource)
	}{
		{"missing schema", func(s *OneTapCallbackSessionMigrationSource) { s.Schema = "" }},
		{"reserved schema", func(s *OneTapCallbackSessionMigrationSource) { s.Schema = "identity" }},
		{"unsafe schema", func(s *OneTapCallbackSessionMigrationSource) { s.Schema = "session_store;" }},
		{"zero version", func(s *OneTapCallbackSessionMigrationSource) { s.Version = 0 }},
		{"missing validation", func(s *OneTapCallbackSessionMigrationSource) { s.ValidationVersion = 0 }},
		{"equal versions", func(s *OneTapCallbackSessionMigrationSource) { s.ValidationVersion = s.Version }},
		{"reversed versions", func(s *OneTapCallbackSessionMigrationSource) { s.ValidationVersion = s.Version - 1 }},
		{"overflow version", func(s *OneTapCallbackSessionMigrationSource) {
			s.Version = migrations.Version(math.MaxInt64) + 1
			s.ValidationVersion = s.Version + 1
		}},
		{"overflow validation", func(s *OneTapCallbackSessionMigrationSource) {
			s.ValidationVersion = migrations.Version(math.MaxInt64) + 1
		}},
		{"missing predecessor", func(s *OneTapCallbackSessionMigrationSource) { s.PreviousConstraint = "" }},
		{"unknown predecessor", func(s *OneTapCallbackSessionMigrationSource) { s.PreviousConstraint = "arbitrary_check" }},
		{"successor predecessor", func(s *OneTapCallbackSessionMigrationSource) {
			s.PreviousConstraint = "session_issuances_purpose_onetap_v1"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := valid
			test.change(&source)
			steps, err := source.Load(t.Context())
			var invalid identity.InvalidInputError
			if steps != nil || !errors.As(err, &invalid) || invalid.Field != "session_onetap_callback_migration" {
				t.Fatalf("want redacted invalid configuration without partial steps: %v", err)
			}
		})
	}
	if steps, err := valid.Load(nil); err == nil || steps != nil {
		t.Fatal("nil migration context admitted")
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if steps, err := valid.Load(cancelled); steps != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("want unchanged cancellation without partial history: %v", err)
	}
}
