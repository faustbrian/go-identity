package postgres

import (
	"context"
	"testing"
)

func TestSSOOIDCLogoutMigrationSeparatesExpansionAndValidation(t *testing.T) {
	for _, predecessor := range []string{"session_revocations_purpose_check", "session_revocations_purpose_oidc_v1"} {
		t.Run(predecessor, func(t *testing.T) {
			s := SSOOIDCLogoutMigrationSource{Schema: "session_store", Version: 100, ValidationVersion: 101, PreviousConstraint: predecessor}
			steps, err := s.Load(t.Context())
			if err != nil || len(steps) != 2 {
				t.Fatal("supported predecessor does not generate separately applicable migrations", err)
			}
			if steps[0].Version() != 100 || steps[1].Version() != 101 || steps[0].DownSQL() != "" || steps[1].DownSQL() != "" {
				t.Fatal("migration is not ordered and forward-only")
			}
		})
	}
	s := SSOOIDCLogoutMigrationSource{Schema: "session_store", Version: 100, ValidationVersion: 101, PreviousConstraint: "foreign_check"}
	if steps, err := s.Load(t.Context()); err == nil || len(steps) != 0 {
		t.Fatal("foreign predecessor accepted")
	}
	s.PreviousConstraint = "session_revocations_purpose_check"
	ctx, stop := context.WithCancel(t.Context())
	stop()
	if steps, err := s.Load(ctx); err != context.Canceled || len(steps) != 0 {
		t.Fatal("cancelled migration source produced work", err)
	}
}
