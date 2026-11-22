package mfapostgres

import (
	"context"
	"errors"
	"math"
	"testing"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestSSOOIDCJITFactorMigrationPreservesEverySupportedHistory(t *testing.T) {
	for _, profile := range []struct {
		name string
		base migrations.Source
	}{
		{"factor_authorities_initialized_purpose_check", MigrationSource{Version: 1}},
		{"factor_authorities_initialized_purpose_v2", MagicLinkSignupMigrationSource{Base: MigrationSource{Version: 1}, Version: 2}},
		{"factor_authorities_initialized_purpose_v3", UsernameSignupMigrationSource{Base: MigrationSource{Version: 1}, Version: 2}},
		{"factor_authorities_initialized_purpose_v4", PasskeySignupMigrationSource{Base: MigrationSource{Version: 1}, Version: 2}},
	} {
		t.Run(profile.name, func(t *testing.T) {
			prior, err := profile.base.Load(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			source := SSOOIDCJITFactorMigrationSource{Base: profile.base, Version: 7, ValidationVersion: 8, IndexVersion: 9}
			history, err := source.Load(t.Context())
			if err != nil || len(history) != len(prior)+3 {
				t.Fatal("missing separate expansion, validation or concurrent index", err)
			}
			for i, old := range prior {
				if history[i].Version() != old.Version() || history[i].UpSQL() != old.UpSQL() || history[i].DownSQL() != old.DownSQL() || history[i].TransactionMode() != old.TransactionMode() {
					t.Fatal("installed factor history changed")
				}
			}
			for i, version := range []migrations.Version{7, 8, 9} {
				step := history[len(prior)+i]
				mode := migrations.TransactionModeDefault
				if i == 2 {
					mode = migrations.TransactionModeNone
				}
				if step.Version() != version || step.DownSQL() != "" || step.TransactionMode() != mode {
					t.Fatal("invalid forward-only factor migration")
				}
			}
		})
	}
}

func TestSSOOIDCJITFactorMigrationRejectsInvalidOrUnorderedHistory(t *testing.T) {
	valid := SSOOIDCJITFactorMigrationSource{Base: MigrationSource{Version: 1}, Version: 2, ValidationVersion: 3, IndexVersion: 4}
	for name, change := range map[string]func(*SSOOIDCJITFactorMigrationSource){
		"missing base":          func(s *SSOOIDCJITFactorMigrationSource) { s.Base = nil },
		"typed nil base":        func(s *SSOOIDCJITFactorMigrationSource) { s.Base = (*MigrationSource)(nil) },
		"missing expansion":     func(s *SSOOIDCJITFactorMigrationSource) { s.Version = 0 },
		"overlapping expansion": func(s *SSOOIDCJITFactorMigrationSource) { s.Version = 1 },
		"missing validation":    func(s *SSOOIDCJITFactorMigrationSource) { s.ValidationVersion = 0 },
		"overlapping validation": func(s *SSOOIDCJITFactorMigrationSource) {
			s.ValidationVersion = s.Version
		},
		"overflow validation": func(s *SSOOIDCJITFactorMigrationSource) { s.ValidationVersion = migrations.Version(math.MaxUint64) },
		"missing index":       func(s *SSOOIDCJITFactorMigrationSource) { s.IndexVersion = 0 },
		"overlapping index":   func(s *SSOOIDCJITFactorMigrationSource) { s.IndexVersion = s.ValidationVersion },
		"overflow index":      func(s *SSOOIDCJITFactorMigrationSource) { s.IndexVersion = migrations.Version(math.MaxUint64) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := valid
			change(&bad)
			if history, err := bad.Load(t.Context()); err == nil || history != nil {
				t.Fatal("invalid factor migration configuration admitted")
			}
		})
	}
	if history, err := valid.Load(nil); err == nil || history != nil {
		t.Fatal("nil migration context admitted")
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if history, err := valid.Load(canceled); !errors.Is(err, context.Canceled) || history != nil {
		t.Fatal("migration cancellation lost", err)
	}
}

func TestSSOOIDCJITFactorInitializationRequiresActualProtectedCreation(t *testing.T) {
	for _, ctx := range []context.Context{nil, t.Context()} {
		if err := InitializeSSOOIDCJIT(ctx, kernel.Work{}, nil, identity.Command{}); err == nil {
			t.Fatal("factor authority initialized without protected prospective creation")
		}
	}
}
