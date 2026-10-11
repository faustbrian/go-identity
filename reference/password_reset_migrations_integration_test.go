//go:build integration

package reference

import (
	"context"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5/stdlib"
)

// Exercise actual contributed SQL and native ledgers. This is installation
// evidence, not a substitute for a public reference-server reset journey.
func TestPasswordResetNativeHistoryInstallation(t *testing.T) {
	port := os.Getenv("IDENTITY_REFERENCE_POSTGRES_PORT")
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		t.Fatal("disposable loopback PostgreSQL required")
	}
	credential, err := os.ReadFile(os.Getenv("IDENTITY_REFERENCE_PASSWORD_FILE"))
	if err != nil || len(credential) > 128 {
		t.Fatal("disposable fixture credential required")
	}
	dsn := (&url.URL{Scheme: "postgres", User: url.UserPassword("postgres", strings.TrimSpace(string(credential))), Host: net.JoinHostPort("127.0.0.1", port), Path: "/identity_test", RawQuery: "sslmode=disable&search_path=public"}).String()
	clear(credential)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	pool, err := database.New(ctx, database.Config{DSN: dsn})
	if err != nil {
		t.Fatal("disposable primary unavailable")
	}
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), time.Second)
		defer done()
		if err := pool.Close(cleanup); err != nil {
			t.Error("primary cleanup failed")
		}
	})
	c := featureMigrationConfig{otpSchema: "reset_otp", sessionSchema: "reset_sessions", resetSchema: "reset_sessions", global: "reset-deployment"}
	s := StoreSet{state: &storeState{pool: pool, config: VelocityStoreConfiguration{Schema: "reset_risk"}, httpRate: &httpRateState{}, features: &featureState{migrations: c, httpPasswordReset: &passwordResetHTTPState{}}}}
	db := stdlib.OpenDBFromPool(pool.Raw())
	defer db.Close()
	backend, err := migrationdb.New(db)
	if err != nil {
		t.Fatal(err)
	}
	prepared := make(map[string]bool)
	install := func() []migrationHistory {
		t.Helper()
		catalog, err := s.migrationCatalog(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, h := range catalog {
			owned := backend
			if h.namespace != "" {
				owned, err = backend.ForNamespace(h.namespace)
				if err != nil {
					t.Fatal(err)
				}
			}
			if h.preflight != "" && !prepared[h.namespace] {
				if _, err := pool.Raw().Exec(ctx, h.preflight); err != nil {
					t.Fatal("native preflight", h.namespace, err)
				}
				prepared[h.namespace] = true
				if h.namespace == "audit" {
					// Fresh preflight created these cluster-wide roles. A later
					// test uses another database in the same disposable cluster.
					t.Cleanup(func() {
						cleanup, done := context.WithTimeout(context.Background(), 3*time.Second)
						defer done()
						if _, err := pool.Raw().Exec(cleanup, "DROP OWNED BY audit_writer,audit_reader,audit_retention; DROP ROLE audit_writer,audit_reader,audit_retention"); err != nil {
							t.Error("owned audit role cleanup failed", err)
						}
					})
				}
			}
			runner, err := migrations.NewRunner(fixedMigrationSource(h.history), owned)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := runner.Up(ctx); err != nil {
				t.Fatal("native installation", h.namespace, err)
			}
		}
		return catalog
	}
	catalog := install()
	if present, err := readinessSchemaPresent(ctx, s.state, catalog); err != nil || !present {
		t.Fatal("installed reset graph lacks consumed objects", err)
	}
	// Selecting the old shared signin suffix after reset must still apply, and
	// repeating all histories must remain a native no-op.
	s.state.features.migrations.signinSchema = "reset_sessions"
	install()
	install()
	if _, err := pool.Raw().Exec(ctx, "DROP TABLE reset_sessions.password_resets"); err != nil {
		t.Fatal(err)
	}
	if present, err := readinessSchemaPresent(ctx, s.state, catalog); err != nil || present {
		t.Fatal("lost reset effect table retained readiness", err)
	}
}
