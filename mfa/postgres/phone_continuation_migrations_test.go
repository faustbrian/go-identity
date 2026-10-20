package mfapostgres_test

import (
	"context"
	"testing"

	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestPhoneContinuationMigrationPreservesInstalledHistory(t *testing.T) {
	for _, verification := range []bool{false, true} {
		for _, username := range []bool{false, true} {
			var base migrations.Source = mfapg.PasswordContinuationMigrationSource{Base: mfapg.ContinuationMigrationSource{Base: mfapg.MigrationSource{Version: 1}, Version: 2}, Version: 3}
			if verification {
				base = mfapg.VerificationContinuationMigrationSource{Base: base, Version: 4}
			}
			if username {
				base = mfapg.UsernameContinuationMigrationSource{Base: base, Version: 5, VerificationSignin: verification}
			}
			before, err := base.Load(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			source := mfapg.PhoneContinuationMigrationSource{Base: base, Version: 6, VerificationSignin: verification, UsernameSignin: username}
			after, err := source.Load(t.Context())
			if err != nil || len(after) != len(before)+1 || after[len(before)].DownSQL() != "" {
				t.Fatal("phone continuation upgrade must append, not replace history", err)
			}
			for i, old := range before {
				if after[i].Version() != old.Version() || after[i].UpSQL() != old.UpSQL() || after[i].DownSQL() != old.DownSQL() {
					t.Fatal("installed MFA history changed")
				}
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if _, err := source.Load(ctx); err != context.Canceled {
				t.Fatal("migration lost cancellation", err)
			}
			for _, bad := range []mfapg.PhoneContinuationMigrationSource{{}, {Base: base}, {Base: base, Version: 1}, {Base: base, Version: migrations.Version(^uint64(0))}} {
				if _, err := bad.Load(t.Context()); err == nil {
					t.Fatal("invalid migration admitted")
				}
			}
		}
	}
}
