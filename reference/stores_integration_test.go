//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/risk"
	riskvalkey "github.com/faustbrian/go-identity/risk/valkey"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

type liveStores struct {
	afterEmailRemovalPreparation       func(capability.Proof, identity.IdentifierID, passwordpg.EmailManagementRequest, []*http.Cookie, string)
	emailRemovalMode                   string
	afterManagedConfirmation           func(email.VerificationConfirmRequest, identity.IdentifierID)
	afterManagedChangeConfirmation     func(email.ChangeConfirmRequest, string)
	emailRequestHTTP                   func(passwordpg.EmailManagementRequest, bool, bool) (passwordpg.EmailManagementResult, error)
	afterEmailQueries                  func([]*http.Cookie, identity.UserID, identity.IdentifierID)
	emailQueriesStandalone             bool
	afterEmailSignin                   func(context.Context, identity.UserID, []*http.Cookie, string, func(...string) ([]*http.Cookie, string), func([]*http.Cookie) bool)
	disable                            bool
	disableAll                         bool
	disablePending                     bool
	pendingDisableFactor               string
	disableHTTP                        bool
	factorManagementHTTP               bool
	factorManagementRace               bool
	factorManagementDenials            bool
	factorManagementClear              bool
	factorRemoval                      bool
	factorRemovalReset                 bool
	factorRemovalResetHTTP             bool
	factorRemovalLocks                 bool
	removalSignin                      passwordpg.SigninConfig
	afterFactorRemoval                 func(context.Context, identity.UserID)
	factorManagement                   bool
	factorReplacement                  bool
	factorReplacementDelayed           bool
	factorReplacementRollback          bool
	factorReplacementConfirmationFault bool
	factorReplacementConfirmationRace  bool
	factorReplacementPredecessorUse    bool
	factorReplacementRecovery          bool
	replacementContinuationDenial      string
	replacementSourceMethod            string
	mfaListing                         bool
	mfaListHTTP                        bool
	mfaListStandalone                  bool
	mfaListDenials                     bool
	mfaListRecheck                     bool
	activeStepUp                       bool
	activeStepUpHTTP                   bool
	regeneration                       bool
	regenerationHTTP                   bool
	regenerationRace                   bool
	regenerationDenials                bool
	secondBearer                       string
	secondCSRF                         string
	recoveryRace                       bool
	completionFault                    *completionCommitFault
	stores                             reference.StoreSet
	pool                               *database.Pool
	config                             reference.StoreConfiguration
}

func newLiveStores(t *testing.T, ctx context.Context) liveStores {
	return newLiveStoresProfile(t, ctx, true)
}

func newLiveStoresProfile(t *testing.T, ctx context.Context, install bool, postgresOnly ...bool) liveStores {
	t.Helper()
	if len(postgresOnly) > 1 {
		t.Fatal("ambiguous fixture profile")
	}
	durable := len(postgresOnly) == 1 && postgresOnly[0]
	port := func(name string) string {
		value := os.Getenv(name)
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != value {
			t.Fatal("explicit disposable loopback service port required")
		}
		return value
	}
	read := func(name string) []byte {
		path := os.Getenv(name)
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 16384 {
			t.Fatal("bounded disposable service input required")
		}
		value, err := os.ReadFile(path)
		if err != nil {
			t.Fatal("cannot read disposable service input")
		}
		return value
	}
	password := ""
	if !durable {
		password = strings.TrimSpace(string(read("IDENTITY_REFERENCE_PASSWORD_FILE")))
		if len(password) != 44 || strings.ContainsAny(password, "'\\\n\r") {
			t.Fatal("generated base64 fixture credential required")
		}
	}
	dsn := "host=127.0.0.1 port=" + port("IDENTITY_REFERENCE_POSTGRES_PORT") + " user=postgres password='" + password + "' dbname=identity_test sslmode=disable search_path=public"
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal("cannot connect disposable primary")
	}
	var unique [16]byte
	if _, err := rand.Read(unique[:]); err != nil {
		t.Fatal("fixture entropy unavailable")
	}
	name := "reference_" + hex.EncodeToString(unique[:])
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal("cannot create owned fixture database")
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
			t.Error("owned fixture database cleanup failed")
		}
		if err := admin.Close(cleanup); err != nil {
			t.Error("fixture admin cleanup failed")
		}
	})
	dsn = strings.Replace(dsn, "dbname=identity_test", "dbname="+name, 1)
	pool, err := database.New(ctx, database.Config{DSN: dsn, MaxConns: 4})
	if err != nil {
		t.Fatal("cannot construct fixture primary pool")
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := pool.Close(cleanup); err != nil {
			t.Error("fixture primary pool cleanup failed")
		}
	})
	policy, err := risk.NewPolicy(risk.PolicyConfig{Version: 3, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}, Profiles: []risk.Profile{
		{Class: risk.Authentication, Phase: risk.BeforeCredential, Dimensions: []risk.Dimension{risk.TenantDimension, risk.NetworkDimension, risk.DeviceDimension, risk.IdentifierDimension}, Window: 5 * time.Minute, Limit: 2, ThresholdAction: risk.Throttle, EvidenceTTL: 5 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.CredentialMutation, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectDimension, risk.SessionDimension, risk.NetworkDimension}, Window: 15 * time.Minute, Limit: 5, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.Privileged, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.ActorDimension, risk.ResourceDimension, risk.NetworkDimension}, Window: time.Hour, Limit: 20, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.StateNeutralRead, Phase: risk.BeforeReturn, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectOrNetworkDimension}, Window: time.Minute, Limit: 120, ThresholdAction: risk.Throttle, EvidenceTTL: time.Minute, Unknown: risk.StepUpWithIndependentFactor, MaxCounters: 2, RequiredSignals: []string{"velocity"}},
	}})
	if err != nil {
		t.Fatal("invalid fixture policy")
	}
	key, err := risk.NewCounterDigestKey(1, bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal("invalid fixture key")
	}
	c := reference.StoreConfiguration{Velocity: reference.VelocityStoreConfiguration{
		Native: riskvalkey.VelocityRecoveryConfig{Namespace: name, ReplaySecret: bytes.Repeat([]byte{7}, 32), Policy: policy, Keys: []risk.CounterDigestKey{key}},
		Schema: "risk_store", Tenants: []string{"tenant", "other"}, PrimaryTimeout: time.Second, LeaseDuration: 5 * time.Second, RecoveryTimeout: 4 * time.Second, Batch: 100, MaxRecords: 10000,
	}}
	if !durable {
		credential, err := riskvalkey.NewCredential("default", []byte(password))
		if err != nil {
			t.Fatal("invalid fixture credential")
		}
		c.Velocity.Native.Endpoint = "rediss://" + net.JoinHostPort("localhost", port("IDENTITY_REFERENCE_VALKEY_PORT"))
		c.Velocity.Native.TLS = &tls.Config{ServerName: "localhost", MinVersion: tls.VersionTLS12}
		c.Velocity.Native.TrustPEM = read("IDENTITY_REFERENCE_TRUST_FILE")
		c.Velocity.Native.Credential = credential
		c.Velocity.Native.Timeout, c.Velocity.Native.PoolSize, c.Velocity.Native.Topology = time.Second, 4, "standalone"
	}
	selected := c
	if durable {
		selectDurableReferenceAdmission(&selected)
	}
	stores, err := reference.ComposeStores(selected, reference.ReferenceDependencies{PostgreSQL: pool})
	if err != nil {
		t.Fatal("owned composition failed", err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := stores.Close(cleanup); err != nil {
			t.Error("owned composition cleanup failed", err)
		}
	})
	pgconfig, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid generated primary input")
	}
	db := stdlib.OpenDB(*pgconfig)
	defer db.Close()
	backend, err := migrationdb.New(db)
	if err != nil {
		t.Fatal("cannot construct owned migration backend")
	}
	runner, err := migrations.NewRunner(stores.MigrationSource(), backend)
	if err != nil {
		t.Fatal("cannot compose owned migrations")
	}
	if install {
		if _, err := runner.Up(ctx); err != nil {
			t.Fatal("owned upstream migrations failed", err)
		}
	}
	return liveStores{stores: stores, pool: pool, config: c}
}

// Helpers share policy setup, not an overlapping runtime owner. This conversion
// precedes public composition, which receives only the selected durable lane.
func selectDurableReferenceAdmission(c *reference.StoreConfiguration) {
	v := c.Velocity
	c.DurableAdmission = &reference.DurableAdmissionConfiguration{Schema: v.Schema, Namespace: v.Native.Namespace, Policy: v.Native.Policy, Keys: v.Native.Keys, ReplayKey: v.Native.ReplaySecret, Tenants: v.Tenants, MaximumRecords: 10000, Timeout: v.PrimaryTimeout}
	c.Velocity = reference.VelocityStoreConfiguration{}
}

func TestReferenceFreshPrimaryAndNativeRemainUnavailable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	f := newLiveStores(t, ctx)
	if store, err := f.stores.RecoverVelocity(ctx, "tenant"); err == nil || store != nil {
		t.Fatal("fresh empty primary/native granted admission without actual full-window coverage")
	}
	var state string
	var started, now time.Time
	if err := f.pool.Raw().QueryRow(ctx, "SELECT state,journal_started_at,clock_timestamp() FROM risk_store.velocity_epochs WHERE state<>'retired'").Scan(&state, &started, &now); err != nil || state != "replaying" || started.After(now) || now.Sub(started) >= time.Minute {
		t.Fatal("fresh journal lifetime was invented or promoted")
	}
	var count int
	if err := f.pool.Raw().QueryRow(ctx, "SELECT count(*) FROM risk_store.velocity_attempts").Scan(&count); err != nil || count != 0 {
		t.Fatal("recovery created mutation intents")
	}
	if store, err := f.stores.RecoverVelocity(ctx, "not-selected"); err == nil || store != nil {
		t.Fatal("unselected tenant granted admission")
	}
	if err := f.stores.Close(ctx); err != nil {
		t.Fatal("owned close failed", err)
	}
	if store, err := f.stores.RecoverVelocity(ctx, "tenant"); err == nil || store != nil {
		t.Fatal("closed composition granted admission")
	}
	if err := f.pool.Raw().Ping(ctx); err != nil {
		t.Fatal("composition closed caller-owned primary pool")
	}
}

// This fixture supplies historical origin explicitly. It proves joint recovery
// mechanics conditioned on established coverage, NOT a genuine fresh warmup.
func TestReferenceHistoricalFixtureRecoversOriginalOutcome(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	f := newLiveStores(t, ctx)
	if store, err := f.stores.RecoverVelocity(ctx, "tenant"); err == nil || store != nil {
		t.Fatal("fresh fixture incorrectly healthy")
	}
	if _, err := f.pool.Raw().Exec(ctx, "UPDATE risk_store.velocity_epochs SET journal_started_at=clock_timestamp()-interval '61 minutes' WHERE state='replaying'"); err != nil {
		t.Fatal("historical-origin fixture setup failed")
	}
	wait(ctx, t, 6*time.Second)
	store, err := f.stores.RecoverVelocity(ctx, "tenant")
	if err != nil || store == nil {
		t.Fatal("covered fixture could not activate exact owned pair", err)
	}
	coordinator := liveCoordinator(t, f, store)
	command := liveCommand(t, coordinator, "original")
	result, err := store.Mutate(ctx, command)
	outcome, snapshot, declarationErr := result.Declaration(command)
	if err != nil || declarationErr != nil || outcome != risk.CounterCommitted || len(snapshot) != 4 {
		t.Fatal("joint original mutation did not commit", err, declarationErr)
	}
	for _, counter := range snapshot {
		if counter.Value != 1 || counter.WindowExpiresAt.Sub(counter.WindowStartedAt) != 5*time.Minute {
			t.Fatal("original counter facts not retained")
		}
	}
	replayed, err := store.Mutate(ctx, command)
	replayOutcome, replaySnapshot, declarationErr := replayed.Declaration(command)
	if err != nil || declarationErr != nil || replayOutcome != outcome || !sameCounters(replaySnapshot, snapshot) {
		t.Fatal("joint retry changed original outcome or window", err, declarationErr, replayOutcome, len(replaySnapshot))
	}
	wait(ctx, t, 6*time.Second)
	if _, err := store.Mutate(ctx, liveCommand(t, coordinator, "expired-handle")); err == nil {
		t.Fatal("expired original activation still granted admission")
	}
	successor, err := f.stores.RecoverVelocity(ctx, "tenant")
	if err != nil || successor == nil {
		t.Fatal("original durable history could not recover into successor", err)
	}
	restored, err := successor.Mutate(ctx, command)
	restoredOutcome, restoredSnapshot, declarationErr := restored.Declaration(command)
	if err != nil || declarationErr != nil || restoredOutcome != outcome || !sameCounters(restoredSnapshot, snapshot) {
		t.Fatal("successor changed original terminal facts", err, declarationErr)
	}
	var count int
	if err := f.pool.Raw().QueryRow(ctx, "SELECT count(*) FROM risk_store.velocity_attempts").Scan(&count); err != nil || count != 1 {
		t.Fatal("recovery/replay redispatched or created an expired-handle intent")
	}
	next := liveCommand(t, liveCoordinator(t, f, successor), "next")
	value, err := successor.Mutate(ctx, next)
	nextOutcome, nextSnapshot, declarationErr := value.Declaration(next)
	if err != nil || declarationErr != nil || nextOutcome != risk.CounterCommitted {
		t.Fatal("successor could not admit next original attempt", err)
	}
	for _, counter := range nextSnapshot {
		if counter.Value != 2 {
			t.Fatal("recovery forgot or doubled original debit")
		}
	}
	// Concurrent identical attempts may observe pending ambiguity; they must
	// never cause a second native debit. An eventual terminal replay is exact.
	thirdCoordinator := liveCoordinator(t, f, successor)
	third := liveCommand(t, thirdCoordinator, "concurrent")
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() { _, _ = successor.Mutate(ctx, third) })
	}
	group.Wait()
	thirdResult, err := successor.Mutate(ctx, third)
	thirdOutcome, thirdSnapshot, declarationErr := thirdResult.Declaration(third)
	if err != nil || declarationErr != nil || thirdOutcome != risk.CounterCommitted {
		t.Fatal("concurrent original attempt did not retain terminal outcome", err)
	}
	for _, counter := range thirdSnapshot {
		if counter.Value != 3 {
			t.Fatal("concurrent attempt doubled or forgot original debit")
		}
	}
	evaluated, err := thirdCoordinator.Mutate(ctx, third)
	if err != nil || evaluated.Outcome != risk.CounterCommitted || evaluated.Signal.State != risk.SignalThrottle {
		t.Fatal("limit N+1 did not throttle using original retained counters")
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	if err := f.stores.Close(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal("already-canceled shutdown lost its caller error", err)
	}
	if _, err := successor.Mutate(ctx, liveCommand(t, thirdCoordinator, "after-shutdown")); err == nil {
		t.Fatal("already-canceled shutdown left issued counter handle admitting work")
	}
	if err := f.pool.Raw().QueryRow(ctx, "SELECT count(*) FROM risk_store.velocity_attempts").Scan(&count); err != nil || count != 3 {
		t.Fatal("shutdown denial created a new primary intent")
	}
}

func TestReferenceCompositionRejectsUnsupportedConfigurationWithoutIO(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	f := newLiveStores(t, ctx)
	cases := []struct {
		name string
		edit func(*reference.StoreConfiguration)
	}{
		{"empty tenants", func(c *reference.StoreConfiguration) { c.Velocity.Tenants = nil }},
		{"duplicate tenants", func(c *reference.StoreConfiguration) { c.Velocity.Tenants = []string{"tenant", "tenant"} }},
		{"oversized tenants", func(c *reference.StoreConfiguration) { c.Velocity.Tenants = make([]string, 129) }},
		{"invalid tenant scope", func(c *reference.StoreConfiguration) { c.Velocity.Tenants = []string{"tenant with space"} }},
		{"batch low", func(c *reference.StoreConfiguration) { c.Velocity.Batch = 0 }},
		{"batch high", func(c *reference.StoreConfiguration) { c.Velocity.Batch = 1001 }},
		{"records low", func(c *reference.StoreConfiguration) { c.Velocity.MaxRecords = 0 }},
		{"records high", func(c *reference.StoreConfiguration) { c.Velocity.MaxRecords = 100001 }},
		{"timeout low", func(c *reference.StoreConfiguration) { c.Velocity.RecoveryTimeout = 0 }},
		{"timeout crosses lease", func(c *reference.StoreConfiguration) { c.Velocity.RecoveryTimeout = c.Velocity.LeaseDuration }},
		{"primary timeout", func(c *reference.StoreConfiguration) { c.Velocity.PrimaryTimeout = 0 }},
		{"lease excessive", func(c *reference.StoreConfiguration) { c.Velocity.LeaseDuration = 2 * time.Minute }},
		{"lease precision", func(c *reference.StoreConfiguration) { c.Velocity.LeaseDuration += time.Nanosecond }},
		{"native topology", func(c *reference.StoreConfiguration) { c.Velocity.Native.Topology = "cluster" }},
		{"schema", func(c *reference.StoreConfiguration) { c.Velocity.Schema = "identity" }},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			config := f.config
			item.edit(&config)
			stores, err := reference.ComposeStores(config, reference.ReferenceDependencies{PostgreSQL: f.pool})
			if err == nil {
				_ = stores.Close(ctx)
				t.Fatal("unsupported deployment configuration accepted")
			}
		})
	}
	for _, value := range []any{f.config, f.config.Velocity, f.stores, reference.ReferenceDependencies{PostgreSQL: f.pool}} {
		if formatted := fmt.Sprintf("%#v", value); !strings.Contains(formatted, "redacted") || strings.Contains(formatted, f.config.Velocity.Native.Namespace) {
			t.Fatal("composition formatting disclosed retained configuration")
		}
		if _, err := json.Marshal(value); !errors.Is(err, risk.ErrSensitiveSerialization) {
			t.Fatal("composition allowed sensitive serialization")
		}
		if _, err := value.(interface{ MarshalText() ([]byte, error) }).MarshalText(); !errors.Is(err, risk.ErrSensitiveSerialization) {
			t.Fatal("composition allowed sensitive text serialization")
		}
	}
}

// Counter declarations bind facts by dimension, not SQL row order or the
// location pointer of a time.Time decoded by a different native adapter.
func sameCounters(a, b []risk.Counter) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]bool, len(a))
	for _, v := range a {
		if seen[v.Kind] {
			return false
		}
		seen[v.Kind] = true
		found := false
		for _, w := range b {
			if v.Kind == w.Kind && v.Value == w.Value && v.ObservedAt.Equal(w.ObservedAt) && v.WindowStartedAt.Equal(w.WindowStartedAt) && v.WindowExpiresAt.Equal(w.WindowExpiresAt) {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func TestReferenceRecoveryCancellationJoinsPrimaryWork(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	f := newLiveStores(t, ctx)
	blocker, err := f.pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal("cannot start fixture lock")
	}
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), time.Second)
		defer done()
		if err := blocker.Rollback(cleanup); err != nil {
			t.Error("fixture lock cleanup failed")
		}
	}()
	if _, err := blocker.Exec(ctx, "LOCK TABLE risk_store.velocity_epochs IN ACCESS EXCLUSIVE MODE"); err != nil {
		t.Fatal("cannot hold fixture primary lock")
	}
	call, stop := context.WithCancel(ctx)
	defer stop()
	done := make(chan error, 1)
	go func() {
		store, err := f.stores.RecoverVelocity(call, "tenant")
		if store != nil {
			done <- errors.New("blocked recovery granted admission")
			return
		}
		done <- err
	}()
	// Observe the actual SQL lock wait, not a sleep-based scheduling assumption.
	for {
		var blocked bool
		if err := f.pool.Raw().QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%risk_store%velocity_epochs%')").Scan(&blocked); err != nil {
			t.Fatal("cannot observe fixture primary wait")
		}
		if blocked {
			break
		}
		select {
		case err := <-done:
			t.Fatal("recovery ended before primary lock wait", err)
		case <-ctx.Done():
			t.Fatal("primary lock wait not reached")
		case <-time.After(5 * time.Millisecond):
		}
	}
	stop()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("recovery did not preserve caller cancellation", err)
		}
	case <-ctx.Done():
		t.Fatal("canceled primary recovery did not join")
	}
	if err := f.stores.Close(ctx); err != nil {
		t.Fatal("closed recovery did not drain", err)
	}
}

func liveCoordinator(t *testing.T, f liveStores, store risk.CounterStore) risk.CounterCoordinator {
	t.Helper()
	c, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: f.config.Velocity.Native.Policy, Keys: f.config.Velocity.Native.Keys, Store: store, Clock: func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }, Timeout: time.Second})
	if err != nil {
		t.Fatal("invalid live coordinator")
	}
	return c
}

func liveCommand(t *testing.T, c risk.CounterCoordinator, attempt string) risk.CounterCommand {
	t.Helper()
	command, err := c.Prepare(risk.Context{Tenant: "tenant", Operation: "identity.otp.send", Attempt: attempt}, risk.Subject{Network: "192.0.2.1", Device: "device", IdentifierDigest: strings.Repeat("a", 64)}, risk.BeforeCredential)
	if err != nil {
		t.Fatal("invalid live command", err)
	}
	return command
}

func wait(ctx context.Context, t *testing.T, duration time.Duration) {
	t.Helper()
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal("bounded live wait canceled")
	}
}

func TestReferenceRealOneHourWarmup(t *testing.T) {
	if os.Getenv("IDENTITY_REFERENCE_REAL_WARMUP") != "1" {
		t.Skip("actual one-hour fresh bootstrap proof requires explicit long-running lane")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 65*time.Minute)
	defer cancel()
	f := newLiveStores(t, ctx)
	if store, err := f.stores.RecoverVelocity(ctx, "tenant"); err == nil || store != nil {
		t.Fatal("fresh journal incorrectly admitted")
	}
	var original time.Time
	if err := f.pool.Raw().QueryRow(ctx, "SELECT journal_started_at FROM risk_store.velocity_epochs WHERE state='replaying'").Scan(&original); err != nil {
		t.Fatal("cannot read actual primary journal origin")
	}
	t.Log("waiting for actual immutable one-hour journal coverage")
	wait(ctx, t, time.Hour+time.Second)
	store, err := f.stores.RecoverVelocity(ctx, "tenant")
	if err != nil || store == nil {
		t.Fatal("actual covered empty journal did not activate", err)
	}
	var retained, through time.Time
	if err := f.pool.Raw().QueryRow(ctx, "SELECT journal_started_at,replay_through FROM risk_store.velocity_epochs WHERE state='healthy'").Scan(&retained, &through); err != nil || !retained.Equal(original) || through.Sub(retained) < time.Hour {
		t.Fatal("actual coverage origin changed across generation")
	}
	command := liveCommand(t, liveCoordinator(t, f, store), "after-real-warmup")
	result, err := store.Mutate(ctx, command)
	outcome, snapshot, declarationErr := result.Declaration(command)
	if err != nil || declarationErr != nil || outcome != risk.CounterCommitted || len(snapshot) != 4 {
		t.Fatal("genuine warmup did not enable journaled native admission", err)
	}
}
