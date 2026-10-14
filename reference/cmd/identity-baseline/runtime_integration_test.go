//go:build integration

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

func TestBaselineAuditReconciliationPreservesOriginalNativeRecord(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Second)
	defer cancel()
	dsn, _ := baselineTestDatabase(t, ctx)
	directory := filepath.Join(t.TempDir(), "baseline")
	var output bytes.Buffer
	if err := runBaseline(ctx, []string{"init", "--local-capture", "--directory", directory}, &output); err != nil {
		t.Fatal(err)
	}
	dsnFile := filepath.Join(directory, "postgres.dsn")
	if err := os.WriteFile(dsnFile, []byte(dsn), 0600); err != nil {
		t.Fatal("fixture connection custody unavailable")
	}
	args := []string{"migrate", "--password-reset", "--local-capture", "--directory", directory, "--dsn-file", dsnFile}
	if err := runBaseline(ctx, args, &output); err != nil {
		t.Fatal("native reset migrations unavailable", err)
	}
	pool, err := database.New(ctx, database.Config{DSN: dsn})
	if err != nil {
		t.Fatal("fixture native pool unavailable")
	}
	defer pool.Close(context.Background())
	store, err := auditpg.New(pool.Raw(), auditpg.Config{})
	if err != nil {
		t.Fatal(err)
	}
	record := custodyRecord(t)
	canonical, err := audit.CanonicalJSON(record)
	if err != nil {
		t.Fatal(err)
	}
	custody, err := openLocalAuditCustody(directory, lostAuditAcknowledgement{store})
	if err != nil {
		t.Fatal(err)
	}
	// Fault only the acknowledgement after actual PostgreSQL COMMIT. The
	// operator must resubmit exact original records after this owner closes.
	if _, err := custody.Append(ctx, record); err == nil || audit.AppendOutcomeOf(err) != audit.AppendUnknown {
		t.Fatal("uncertain audit acknowledgement became accepted evidence")
	}
	if err := custody.Close(); err != nil {
		t.Fatal(err)
	}
	spool := filepath.Join(directory, "audit-custody")
	entries, err := os.ReadDir(spool)
	if err != nil || len(entries) != 1 {
		t.Fatal("uncertain original audit lost durable custody")
	}
	name := entries[0].Name()
	args[0] = "reconcile-audits"
	for range 2 {
		if err := runBaseline(ctx, args, &output); err != nil {
			t.Fatal("original audit reconciliation unavailable", err)
		}
	}
	tenant, err := audit.Tenant(baselineTenant)
	if err != nil {
		t.Fatal(err)
	}
	query, err := audit.NewQuery(audit.QueryInput{Tenant: tenant, RecordID: record.ID(), Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	page, err := store.Query(ctx, query)
	if err != nil || len(page.Records) != 1 {
		t.Fatal("operator lost or duplicated the original native audit record")
	}
	recovered, err := audit.CanonicalJSON(page.Records[0])
	if err != nil || !bytes.Equal(canonical, recovered) {
		t.Fatal("operator regenerated original audit identity or bytes")
	}
	if _, err := os.Lstat(filepath.Join(spool, name)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("confirmed native record retained stale local custody")
	}
}

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
	proveBaselineRuntime(t, false)
}

func TestBaselineResetJourneyAndOriginalSessionRevocation(t *testing.T) {
	proveBaselineRuntime(t, true)
}

func TestBaselineResetUpgradePreservesPopulatedBaselineAndOperatorCustody(t *testing.T) {
	proveBaselineRuntimeWithUpgrade(t, true, true)
}

func TestBaselinePasswordChangeJourneyAndOriginalSessionRevocation(t *testing.T) {
	proveBaselineRuntimeWithProfiles(t, false, true, false)
}

func TestBaselinePasswordChangeUpgradePreservesPopulatedBaseline(t *testing.T) {
	proveBaselineRuntimeWithProfiles(t, false, true, true)
}

func TestBaselineCombinedResetAndChangeJourney(t *testing.T) {
	proveBaselineRuntimeWithProfiles(t, true, true, false)
}

func proveBaselineRuntime(t *testing.T, reset bool) {
	t.Helper()
	proveBaselineRuntimeWithUpgrade(t, reset, false)
}

func proveBaselineRuntimeWithUpgrade(t *testing.T, reset, upgrade bool) {
	proveBaselineRuntimeWithProfiles(t, reset, false, upgrade)
}

func proveBaselineRuntimeWithProfiles(t *testing.T, reset, change, upgrade bool) {
	t.Helper()
	ctx, stop := context.WithTimeout(context.Background(), 40*time.Second)
	defer stop()
	dsn, connection := baselineTestDatabase(t, ctx)
	directory := filepath.Join(t.TempDir(), "baseline")
	if err := initializeCredentials(directory, time.Now()); err != nil {
		t.Fatal(err)
	}
	originalKeys, err := readPrivateFile(filepath.Join(directory, "credentials.json"), 32768)
	if err != nil {
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
	if upgrade {
		proveBaselineRuntimeStage(t, ctx, directory, secrets, pool, mailbox, outbound, false)
		var users int
		if err := connection.QueryRow(ctx, `SELECT count(*) FROM identity.users`).Scan(&users); err != nil || users != 1 {
			t.Fatal("baseline journey did not populate the original account")
		}
	}
	var original []byte
	if upgrade {
		original, err = readPrivateFile(filepath.Join(directory, "migration-request.json"), 1<<20)
		if err != nil {
			t.Fatal("baseline original operator custody missing")
		}
	}
	if change {
		if err := prepareChangeCredentials(directory); err != nil {
			t.Fatal("additive change key custody unavailable", err)
		}
	}
	proveBaselineRuntimeStageWithProfiles(t, ctx, directory, secrets, pool, mailbox, outbound, reset, change)
	if reset {
		var effects int
		if err := connection.QueryRow(ctx, `SELECT count(*) FROM session_store.password_resets`).Scan(&effects); err != nil || effects != 1 {
			t.Fatal("reset journey did not commit its native all-session effect")
		}
	}
	if upgrade {
		after, err := readPrivateFile(filepath.Join(directory, "migration-request.json"), 1<<20)
		var users int
		if err != nil || !bytes.Equal(original, after) || connection.QueryRow(ctx, `SELECT count(*) FROM identity.users`).Scan(&users) != nil || users != 2 {
			t.Fatal("reset upgrade replaced original custody or existing account")
		}
	}
	if change {
		keys, err := readPrivateFile(filepath.Join(directory, "credentials.json"), 32768)
		var effects, consumed int
		if err != nil || !bytes.Equal(originalKeys, keys) || connection.QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.password_changes), (SELECT count(*) FROM identity_password.reauthentication_records WHERE consumed_command_id IS NOT NULL)`).Scan(&effects, &consumed) != nil || effects != 1 || consumed != 1 {
			t.Fatal("change replaced baseline key custody or lost atomic proof/session effects")
		}
		var proof string
		var commandBytes []byte
		if err := connection.QueryRow(ctx, "SELECT proof_id, consumed_command_id FROM identity_password.reauthentication_records WHERE consumed_command_id IS NOT NULL").Scan(&proof, &commandBytes); err != nil {
			t.Fatal("committed original verification custody unavailable")
		}
		command, err := identity.ParseCommandID(base64.RawURLEncoding.EncodeToString(commandBytes))
		if err != nil {
			t.Fatal("committed native command identity malformed")
		}
		committed := string(command)
		store, err := auditpg.New(pool.Raw(), auditpg.Config{})
		if err != nil {
			t.Fatal(err)
		}
		tenant, _ := audit.Tenant(baselineTenant)
		query, err := audit.NewQuery(audit.QueryInput{Tenant: tenant, Action: "identity.hibp.query_range", Limit: 16})
		if err != nil {
			t.Fatal(err)
		}
		page, err := store.Query(ctx, query)
		matched := 0
		for _, record := range page.Records {
			if record.Context().CorrelationID() == committed {
				matched++
				if record.Subject().ID() != proof || record.Actor().Kind() != audit.ActorHuman || record.Policy().PolicyID != baselineChangePolicy || record.Attributes()["command.id"] != committed {
					t.Fatal("change HIBP auditing replaced original proof/command/policy attribution")
				}
			}
		}
		if err != nil || matched != 1 {
			t.Fatal("committed change lacks confirmed original HIBP security audit")
		}
	}
}

func proveBaselineRuntimeStage(t *testing.T, ctx context.Context, directory string, secrets credentials, pool *database.Pool, mailbox *localMailbox, outbound *http.Transport, reset bool) {
	proveBaselineRuntimeStageWithProfiles(t, ctx, directory, secrets, pool, mailbox, outbound, reset, false)
}

func proveBaselineRuntimeStageWithProfiles(t *testing.T, ctx context.Context, directory string, secrets credentials, pool *database.Pool, mailbox *localMailbox, outbound *http.Transport, reset, change bool) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("owned loopback listener unavailable")
	}
	defer listener.Close()
	origin := "https://" + listener.Addr().String()
	args := []string{"serve", "--local-capture", "--directory", directory, "--dsn-file", "private-dsn", "--origin", origin}
	if reset {
		args = append(args, "--password-reset")
	}
	if change {
		args = append(args, "--password-change")
	}
	o, err := parseOptions(args)
	if err != nil {
		t.Fatal(err)
	}
	graph, err := composeBaseline(ctx, o, secrets, pool, mailbox, outbound)
	if err != nil {
		t.Fatal("native command graph rejected", err)
	}
	defer graph.close(context.Background())
	if err := migrateBaselineWithRequest(ctx, graph.stores, directory, migrationRequestName(o), syncDirectory); err != nil {
		t.Fatal("fresh native command migrations rejected", err)
	}
	if err := graph.features.Initialize(ctx); err != nil || !graph.server.Readiness(ctx).Ready {
		t.Fatal("actual command graph could not initialize", err)
	}
	lifetime, cancel := context.WithCancel(ctx)
	defer cancel()
	completed := make(chan error, 1)
	go func(serverOptions options) {
		completed <- serveBaselineOnListener(lifetime, graph, serverOptions, secrets, io.Discard, listener)
	}(o)
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
	if change {
		o.operation = "exercise-change"
		if reset {
			o.operation = "exercise"
		}
	}
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
	original, err := readPrivateFile(filepath.Join(directory, "migration-request.json"), 1<<20)
	if err != nil {
		t.Fatal("operator did not retain baseline custody")
	}
	resetArgs := append(append([]string(nil), args...), "--password-reset")
	for range 2 {
		if err := runBaseline(ctx, resetArgs, &output); err != nil {
			t.Fatal("opt-in reset operator migration or exact retry failed", err)
		}
	}
	after, err := readPrivateFile(filepath.Join(directory, "migration-request.json"), 1<<20)
	reset, resetErr := readPrivateFile(filepath.Join(directory, "migration-request-reset.json"), 1<<20)
	var baseRequest, resetRequest operatorRequest
	if err != nil || resetErr != nil || !bytes.Equal(original, after) || json.Unmarshal(original, &baseRequest) != nil || json.Unmarshal(reset, &resetRequest) != nil || baseRequest.Command == resetRequest.Command {
		t.Fatal("optional migration replaced baseline original-command custody")
	}
	var installed bool
	if err := database.QueryRow(ctx, `SELECT to_regclass('session_store.password_resets') IS NOT NULL`).Scan(&installed); err != nil || !installed {
		t.Fatal("reset command did not install the actual session-effect owner")
	}
	resetOriginal := append([]byte(nil), reset...)
	baselineKeys, err := readPrivateFile(filepath.Join(directory, "credentials.json"), 32768)
	if err != nil {
		t.Fatal(err)
	}
	combined := append(append([]string(nil), resetArgs...), "--password-change")
	for range 2 {
		if err := runBaseline(ctx, combined, &output); err != nil {
			t.Fatal("populated reset-to-change operator upgrade/retry failed", err)
		}
	}
	resetAfter, err := readPrivateFile(filepath.Join(directory, "migration-request-reset.json"), 1<<20)
	keysAfter, keysErr := readPrivateFile(filepath.Join(directory, "credentials.json"), 32768)
	changeRequest, changeErr := readPrivateFile(filepath.Join(directory, "migration-request-reset-change.json"), 1<<20)
	var combinedRequest operatorRequest
	if err != nil || keysErr != nil || changeErr != nil || !bytes.Equal(resetOriginal, resetAfter) || !bytes.Equal(baselineKeys, keysAfter) || json.Unmarshal(changeRequest, &combinedRequest) != nil || combinedRequest.Command == resetRequest.Command {
		t.Fatal("change upgrade replaced original key/operator custody")
	}
	if err := database.QueryRow(ctx, "SELECT to_regclass('session_store.password_changes') IS NOT NULL").Scan(&installed); err != nil || !installed {
		t.Fatal("change operator did not install the native session-effect owner")
	}
}
