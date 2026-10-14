//go:build integration

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

func TestBaselineMigrationRequiresDurableRequestBeforeApply(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	dsn, connection := baselineTestDatabase(t, ctx)
	directory := filepath.Join(t.TempDir(), "baseline")
	if err := initializeCredentials(directory, time.Now()); err != nil {
		t.Fatal(err)
	}
	secrets, err := loadCredentials(directory, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	pool, err := database.New(ctx, database.Config{DSN: dsn, MaxConns: 4})
	if err != nil {
		t.Fatal("owned native pool unavailable")
	}
	defer pool.Close(context.Background())
	sender, err := openLocalMailbox(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	o, err := parseOptions([]string{"migrate", "--local-capture", "--directory", directory, "--dsn-file", "private-dsn"})
	if err != nil {
		t.Fatal(err)
	}
	graph, err := buildBaseline(ctx, o, secrets, pool, sender)
	if err != nil {
		t.Fatal("native command graph rejected", err)
	}
	defer graph.close(context.Background())
	var original []byte
	for range 2 {
		calls := 0
		err := migrateBaselineWithSync(ctx, graph.stores, directory, func(path string) error {
			calls++
			if path != directory {
				t.Fatal("acknowledgement did not cover original request parent")
			}
			return errors.New("synthetic directory acknowledgement failure")
		})
		if err == nil || calls != 1 {
			t.Fatal("native Apply ran without original request custody acknowledged")
		}
		content, err := readPrivateFile(filepath.Join(directory, "migration-request.json"), 1<<20)
		if err != nil {
			t.Fatal("original request was not retained for exact recovery")
		}
		if original != nil && !bytes.Equal(original, content) {
			t.Fatal("failed custody acknowledgement replaced original operator inputs")
		}
		original = content
		var installed bool
		if err := connection.QueryRow(ctx, `SELECT to_regclass('identity.users') IS NOT NULL`).Scan(&installed); err != nil || installed {
			t.Fatal("unacknowledged operator request changed the native schema")
		}
	}
	if err := migrateBaseline(ctx, graph.stores, directory); err != nil {
		t.Fatal("exact request acknowledgement could not recover native Apply", err)
	}
	content, err := readPrivateFile(filepath.Join(directory, "migration-request.json"), 1<<20)
	if err != nil || !bytes.Equal(original, content) {
		t.Fatal("recovered native Apply replaced original operator inputs")
	}
}

func baselineTestDatabase(t *testing.T, ctx context.Context) (string, *pgx.Conn) {
	t.Helper()
	port := os.Getenv("IDENTITY_REFERENCE_POSTGRES_PORT")
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		t.Fatal("explicit disposable PostgreSQL port required")
	}
	dsn := "host=127.0.0.1 port=" + port + " user=postgres dbname=identity_test sslmode=disable search_path=public"
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal("disposable PostgreSQL unavailable")
	}
	var unique [16]byte
	if _, err := rand.Read(unique[:]); err != nil {
		t.Fatal("fixture entropy unavailable")
	}
	name := "baseline_" + hex.EncodeToString(unique[:])
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		_ = admin.Close(ctx)
		t.Fatal("cannot create owned database")
	}
	t.Cleanup(func() {
		bounded, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, err := admin.Exec(bounded, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
			t.Error("owned database cleanup failed")
		}
		if err := admin.Close(bounded); err != nil {
			t.Error("owned admin connection cleanup failed")
		}
	})
	dsn = strings.Replace(dsn, "dbname=identity_test", "dbname="+name, 1)
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal("owned database unavailable")
	}
	t.Cleanup(func() {
		bounded, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := connection.Close(bounded); err != nil {
			t.Error("owned connection cleanup failed")
		}
	})
	t.Cleanup(func() {
		bounded, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		// Native audit roles are cluster-scoped even when their owned database
		// is disposable. This exact test-cluster fixture must retire both.
		if _, err := connection.Exec(bounded, `DO $$ DECLARE owned_role text; BEGIN
FOREACH owned_role IN ARRAY ARRAY['audit_writer','audit_reader','audit_retention'] LOOP
  IF EXISTS (SELECT FROM pg_roles WHERE rolname=owned_role) THEN
    EXECUTE format('DROP OWNED BY %I', owned_role);
    EXECUTE format('DROP ROLE %I', owned_role);
  END IF;
END LOOP; END $$`); err != nil {
			t.Error("owned audit role cleanup failed")
		}
	})
	return dsn, connection
}

func TestBaselineRunnableHTTPSConsumerAndShutdown(t *testing.T) {
	ctx, stop := context.WithTimeout(context.Background(), 40*time.Second)
	defer stop()
	dsn, _ := baselineTestDatabase(t, ctx)
	directory := filepath.Join(t.TempDir(), "baseline")
	if err := initializeCredentials(directory, time.Now()); err != nil {
		t.Fatal(err)
	}
	secrets, err := loadCredentials(directory, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// Only the external provider's IO is synthetic. Owned HIBP prefixing,
	// parsing, padded requests and caller-bound evidence remain on the path.
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Host != "api.pwnedpasswords.com" || !strings.HasPrefix(r.URL.Path, "/range/") || r.URL.RawQuery != "" || r.Header.Get("Add-Padding") != "true" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.ContentLength > 0 {
			t.Error("provider request violated password privacy")
			w.WriteHeader(400)
			return
		}
		_, _ = io.WriteString(w, strings.Repeat("0", 35)+":0\r\n")
	}))
	defer provider.Close()
	outbound := provider.Client().Transport.(*http.Transport).Clone()
	outbound.TLSClientConfig.ServerName = "example.com"
	outbound.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, provider.Listener.Addr().String())
	}
	defer outbound.CloseIdleConnections()
	pool, err := database.New(ctx, database.Config{DSN: dsn, MaxConns: 4})
	if err != nil {
		t.Fatal("owned native pool unavailable")
	}
	defer pool.Close(context.Background())
	mailbox, err := openLocalMailbox(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer mailbox.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("owned loopback listener unavailable")
	}
	defer listener.Close()
	origin := "https://" + listener.Addr().String()
	o, err := parseOptions([]string{"serve", "--local-capture", "--directory", directory, "--dsn-file", "private-dsn", "--origin", origin})
	if err != nil {
		t.Fatal(err)
	}
	graph, err := composeBaseline(ctx, o, secrets, pool, mailbox, outbound)
	if err != nil {
		t.Fatal("native command graph rejected", err)
	}
	defer graph.close(context.Background())
	if err := migrateBaseline(ctx, graph.stores, directory); err != nil {
		t.Fatal("fresh native command migrations rejected", err)
	}
	if err := graph.features.Initialize(ctx); err != nil || !graph.server.Readiness(ctx).Ready {
		t.Fatal("actual command graph could not initialize", err)
	}
	lifetime, cancel := context.WithCancel(ctx)
	defer cancel()
	completed := make(chan error, 1)
	go func() { completed <- serveBaselineOnListener(lifetime, graph, o, secrets, io.Discard, listener) }()
	defer func() {
		cancel()
		select {
		case err := <-completed:
			if err != nil {
				t.Error("command shutdown failed")
			}
		case <-time.After(6 * time.Second):
			t.Error("owned command goroutines did not drain")
		}
	}()
	var output bytes.Buffer
	if err := exerciseBaseline(ctx, o, secrets, &output); err != nil {
		t.Fatal("public HTTPS walkthrough did not complete", err)
	}
	if !strings.Contains(output.String(), "original session denied") || strings.Contains(output.String(), "PRIVATE KEY") {
		t.Fatal("consumer walkthrough did not report a safe complete outcome")
	}
}

func TestBaselineOperatorCommandInstallsRealNativeMigrations(t *testing.T) {
	ctx, stop := context.WithTimeout(context.Background(), 40*time.Second)
	defer stop()
	dsn, database := baselineTestDatabase(t, ctx)
	directory := filepath.Join(t.TempDir(), "baseline")
	var output bytes.Buffer
	if err := runBaseline(ctx, []string{"init", "--local-capture", "--directory", directory}, &output); err != nil {
		t.Fatal("explicit local initialization failed", err)
	}
	dsnFile := filepath.Join(directory, "postgres.dsn")
	if err := os.WriteFile(dsnFile, []byte(dsn), 0600); err != nil {
		t.Fatal("cannot write owned connection configuration")
	}
	args := []string{"migrate", "--local-capture", "--directory", directory, "--dsn-file", dsnFile}
	for range 2 {
		if err := runBaseline(ctx, args, &output); err != nil {
			t.Fatal("native operator migration failed", err)
		}
	}
	var users, counterTables int
	if err := database.QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.users), (SELECT count(*) FROM information_schema.tables WHERE table_schema='risk_store' AND table_name LIKE 'durable_counter_%')`).Scan(&users, &counterTables); err != nil || users != 0 || counterTables != 5 {
		t.Fatal("operator command did not install real owners or created an implicit account")
	}
	if strings.Contains(output.String(), dsn) || strings.Contains(output.String(), "PRIVATE KEY") {
		t.Fatal("command output disclosed private configuration")
	}
	if !strings.Contains(output.String(), "migrations compatible") {
		t.Fatal(fmt.Sprint("missing bounded operator outcome"))
	}
}
