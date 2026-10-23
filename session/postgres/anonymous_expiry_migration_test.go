package postgres

import (
	"context"
	"strings"
	"testing"
)

func TestAnonymousExpiryMigrationKeepsBrowserPositiveSourceRequirements(t *testing.T) {
	for _, upgrade := range []bool{false, true} {
		s := AnonymousExpiryMigrationSource{Schema: "session_store", Version: 90, Upgrade: upgrade}
		history, err := s.Load(t.Context())
		if err != nil || len(history) != 1 || history[0].DownSQL() != "" {
			t.Fatal("forward expiry suffix missing", err)
		}
		sql := history[0].UpSQL()
		if !strings.Contains(sql, "source_id IS NULL") || !strings.Contains(sql, "source_id IS NOT NULL AND revoked_count>0 AND family_count>0") || strings.Contains(sql, "identity.anonymous.upgrade") != upgrade {
			t.Fatal("selected browser source/profile requirements lost")
		}
	}
	for _, bad := range []AnonymousExpiryMigrationSource{{}, {Schema: "identity", Version: 90}, {Schema: "session_store"}} {
		if result, err := bad.Load(t.Context()); err == nil || result != nil {
			t.Fatal("invalid expiry history admitted")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := (AnonymousExpiryMigrationSource{Schema: "session_store", Version: 90}).Load(ctx); err != context.Canceled {
		t.Fatal("cancellation lost", err)
	}
}
