package postgres

import (
	"context"
	"strings"
	"testing"
)

func TestOIDCEndSessionHistoryExtendsExistingSingleSessionOwner(t *testing.T) {
	s := OIDCEndSessionMigrationSource{Schema: "session_store", Version: 99}
	history, err := s.Load(t.Context())
	if err != nil || len(history) != 1 || history[0].DownSQL() != "" {
		t.Fatal("forward OIDC revocation suffix missing", err)
	}
	if sql := history[0].UpSQL(); !strings.Contains(sql, "ALTER TABLE") || !strings.Contains(sql, "identity.session.revoke-one") || !strings.Contains(sql, "identity.oauth-server.end-session") || strings.Contains(sql, "CREATE TABLE") {
		t.Fatal("OIDC replaced the session revocation owner/history")
	}
	for _, invalid := range []OIDCEndSessionMigrationSource{{}, {Schema: "identity", Version: 99}, {Schema: "session_store"}} {
		if out, err := invalid.Load(t.Context()); err == nil || out != nil {
			t.Fatal("invalid selected history admitted")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := s.Load(ctx); err != context.Canceled {
		t.Fatal("cancellation lost", err)
	}
}
