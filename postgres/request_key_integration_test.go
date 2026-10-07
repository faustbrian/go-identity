//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
)

// RK-01/02: public correlation owns one original ID, not an execution journal.
func TestRequestKeyIntegration(t *testing.T) {
	dsn := os.Getenv("IDENTITY_POSTGRES_TEST_DSN")
	config, err := pgx.ParseConfig(dsn)
	if dsn == "" || err != nil || config.Host != "127.0.0.1" || config.Database != "identity_test" {
		t.Fatal("explicit disposable loopback identity_test required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal("disposable cluster unavailable")
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if admin.Close(cleanup) != nil {
			t.Error("admin cleanup failed")
		}
	}()
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	name := "request_keys_" + string(id)
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+quoted); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+quoted); err != nil {
			t.Error("database cleanup failed")
		}
	}()
	config.Database = name
	db := stdlib.OpenDB(*config)
	defer db.Close()
	backend, err := migrationdb.New(db)
	if err != nil {
		t.Fatal(err)
	}
	baseRunner, err := migrations.NewRunner(MigrationSource{}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := baseRunner.Up(ctx); err != nil {
		t.Fatal("base migration failed", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('legacy','01ARZ3NDEKTSV4RRFFQ69G5FAV','banned',18446744073709551615)`); err != nil {
		t.Fatal(err)
	}
	runner, err := migrations.NewRunner(RequestKeyMigrationSource{Base: MigrationSource{}, Version: 10}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(ctx); err != nil {
		t.Fatal("request migration failed", err)
	}
	if _, err := runner.Up(ctx); err != nil {
		t.Fatal("migration replay failed", err)
	}
	var legacyID, legacyStatus, legacyVersion string
	if err := db.QueryRowContext(ctx, `SELECT user_id,status,version::text FROM identity.users WHERE tenant_id='legacy'`).Scan(&legacyID, &legacyStatus, &legacyVersion); err != nil || legacyID != "01ARZ3NDEKTSV4RRFFQ69G5FAV" || legacyStatus != "banned" || legacyVersion != "18446744073709551615" {
		t.Fatal("populated migration changed existing identity", err)
	}
	pool, err := database.Connect(ctx, database.Config{DSN: dsn, MaxConns: 12, Configure: func(native *database.PoolConfig) error { native.ConnConfig.Database = name; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if pool.Close(cleanup) != nil {
			t.Error("pool cleanup failed")
		}
	}()
	fixture, _, _ := coordinatorFixture(t)
	policy := CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(ctx context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
		if _, bounded := ctx.Deadline(); !bounded {
			t.Error("unbounded policy")
		}
		return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
	})}
	conf := CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Second, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}}
	lookupKey := [32]byte{2}
	requestKeys, err := NewRequestKeyConfig("test", lookupKey, policy)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewCoordinatorWithRequestKeys(pool, fixture.registry, conf, requestKeys)
	if err != nil {
		t.Fatal(err)
	}
	scope := RequestKeyScope{TenantID: "tenant", ActorID: "actor", ActorKind: authorization.SubjectUser, Method: "POST", RouteID: "identity.otp.send"}
	caller := requestKeyCaller(scope)
	key, _ := identity.NewIdempotencyKey([]byte("retry_original"))
	intent, _ := identity.NewRequestIntent([]identity.FeatureField{{Name: "target", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "user-original"}}})
	disabled, err := NewCoordinator(pool, fixture.registry, conf)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := disabled.ResolveRequestKey(ctx, scope, key, intent, caller); err == nil || got != (RequestKeyAdmission{}) {
		t.Fatal("ordinary constructor enabled correlation")
	}
	badKeys := requestKeys
	badKeys.lookupKey = nil
	if got, err := NewCoordinatorWithRequestKeys(pool, fixture.registry, conf, badKeys); err == nil || got != nil {
		t.Fatal("invalid request configuration usable")
	}
	if got, err := NewCoordinatorWithRequestKeys(pool, fixture.registry, CoordinatorConfig{}, requestKeys); err == nil || got != nil {
		t.Fatal("invalid coordinator configuration usable")
	}
	// Changing the caller's copied configuration must not alter this owner.
	originalKeys := requestKeys
	requestKeys.Namespace = "changed-caller-namespace"
	first, err := c.ResolveRequestKey(ctx, scope, key, intent, caller)
	requestKeys = originalKeys
	if err != nil || first.CommandID == "" || first.FingerprintKeyVersion != 1 {
		t.Fatal("valid request did not allocate original command", err)
	}
	if _, err := identity.ParseCommandID(string(first.CommandID)); err != nil {
		t.Fatal("noncanonical command")
	}
	for range 3 {
		restarted, err := NewCoordinatorWithRequestKeys(pool, fixture.registry, conf, requestKeys)
		if err != nil {
			t.Fatal(err)
		}
		again, err := restarted.ResolveRequestKey(ctx, scope, key, intent, caller)
		if err != nil || again != first {
			t.Fatal("retry remapped original command", err)
		}
	}
	changed, _ := identity.NewRequestIntent([]identity.FeatureField{{Name: "target", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "user-changed"}}})
	got, err := c.ResolveRequestKey(ctx, scope, key, changed, caller)
	var conflict identity.ConflictError
	if !errors.As(err, &conflict) || got != (RequestKeyAdmission{}) {
		t.Fatal("changed request reallocated or disclosed a command", err)
	}
	var mappings, claims, commands int
	if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.request_key_mappings),(SELECT count(*) FROM identity.identity_command_id_claims),(SELECT count(*) FROM identity.commands)`).Scan(&mappings, &claims, &commands); err != nil {
		t.Fatal(err)
	}
	if mappings != 1 || claims != 0 || commands != 0 {
		t.Fatal("correlation fabricated execution authority")
	}
	newCoordinator := func(config CoordinatorConfig) *Coordinator {
		t.Helper()
		got, err := NewCoordinatorWithRequestKeys(pool, fixture.registry, config, requestKeys)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	keyFor := func(raw string) identity.IdempotencyKey {
		t.Helper()
		key, err := identity.NewIdempotencyKey([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	count := func() int {
		t.Helper()
		var n int
		if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.request_key_mappings`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := count()
	for _, change := range []func(*RequestKeyScope){
		func(s *RequestKeyScope) { s.TenantID = "other" },
		func(s *RequestKeyScope) { s.ActorID = "other" },
		func(s *RequestKeyScope) { s.ActorKind = authorization.SubjectAPIKey },
		func(s *RequestKeyScope) { s.Method = "DELETE" },
		func(s *RequestKeyScope) { s.RouteID = "identity.other.send" },
	} {
		other := scope
		change(&other)
		admitted, err := c.ResolveRequestKey(ctx, other, key, intent, requestKeyCaller(other))
		if err != nil || admitted.CommandID == first.CommandID {
			t.Fatal("lookup scope aliased", err)
		}
	}
	if count() != before+5 {
		t.Fatal("scope dimensions missing from uniqueness")
	}
	// RK-04: connection-level barrier races, not sequential mock choreography.
	for _, different := range []bool{false, true} {
		start := make(chan struct{})
		var wg sync.WaitGroup
		results := make([]RequestKeyAdmission, 16)
		errorsByIndex := make([]error, 16)
		racedKey := keyFor("race_same")
		if different {
			racedKey = keyFor("race_conflict")
		}
		before := count()
		for i := range results {
			wg.Go(func() {
				<-start
				request := intent
				if different && i%2 == 1 {
					request = changed
				}
				results[i], errorsByIndex[i] = c.ResolveRequestKey(ctx, scope, racedKey, request, caller)
			})
		}
		close(start)
		wg.Wait()
		var winner RequestKeyAdmission
		conflicts := 0
		for i, got := range results {
			if err := errorsByIndex[i]; err != nil {
				if !different || !errors.As(err, &conflict) || got != (RequestKeyAdmission{}) {
					t.Fatal("unexpected race outcome", err)
				}
				conflicts++
				continue
			}
			if winner.CommandID == "" {
				winner = got
			}
			if got != winner {
				t.Fatal("parallel retries split original command")
			}
		}
		if winner.CommandID == "" || count() != before+1 || different && conflicts != 8 {
			t.Fatal("race did not conserve one allocation")
		}
	}
	// RK-05: retained versions, namespace pin and mixed old/new issuance.
	rotatedConfig := conf
	rotatedConfig.CurrentFingerprintKeyVersion = 2
	rotatedConfig.RetainedFingerprintKeys = map[uint32][32]byte{1: {1}, 2: {3}}
	rotated := newCoordinator(rotatedConfig)
	if got, err := rotated.ResolveRequestKey(ctx, scope, key, intent, caller); err != nil || got != first {
		t.Fatal("rotation changed historical command", err)
	}
	if got, err := rotated.ResolveRequestKey(ctx, scope, keyFor("new_version"), intent, caller); err != nil || got.FingerprintKeyVersion != 2 {
		t.Fatal("new command did not use current version", err)
	}
	retiredConfig := rotatedConfig
	retiredConfig.RetainedFingerprintKeys = map[uint32][32]byte{2: {3}}
	retired := newCoordinator(retiredConfig)
	before = count()
	if got, err := retired.ResolveRequestKey(ctx, scope, key, intent, caller); err == nil || got != (RequestKeyAdmission{}) || count() != before {
		t.Fatal("unverifiable old allocation reassigned")
	}
	namespaceCopy, err := NewRequestKeyConfig(requestKeys.Namespace, [32]byte{99}, requestKeys.Policy)
	if err != nil {
		t.Fatal(err)
	}
	namespaceCoordinator, err := NewCoordinatorWithRequestKeys(pool, fixture.registry, conf, namespaceCopy)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := namespaceCoordinator.ResolveRequestKey(ctx, scope, keyFor("namespace_changed"), intent, caller); !errors.As(err, &conflict) || got != (RequestKeyAdmission{}) || count() != before {
		t.Fatal("changed lookup key split namespace", err)
	}
	// An old and new process racing a fresh key must adopt the winner's version.
	start := make(chan struct{})
	var wg sync.WaitGroup
	var mixed [2]RequestKeyAdmission
	var mixedErrors [2]error
	oldPreparedConfig := conf
	oldPreparedConfig.RetainedFingerprintKeys = rotatedConfig.RetainedFingerprintKeys
	oldPrepared := newCoordinator(oldPreparedConfig)
	for i, coordinator := range []*Coordinator{oldPrepared, rotated} {
		wg.Go(func() {
			<-start
			mixed[i], mixedErrors[i] = coordinator.ResolveRequestKey(ctx, scope, keyFor("mixed_versions"), intent, caller)
		})
	}
	close(start)
	wg.Wait()
	if mixedErrors[0] != nil || mixedErrors[1] != nil || mixed[0] != mixed[1] {
		t.Fatal("rotated race split correlation")
	}
	// RK-06: denial/mismatched current authority never touches correlation rows.
	deniedKeys := requestKeys
	deniedKeys.Policy.Authorization = queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
		return authorization.Decision{Outcome: authorization.Deny, Revision: 9}, nil
	})
	denied, err := NewCoordinatorWithRequestKeys(pool, fixture.registry, conf, deniedKeys)
	if err != nil {
		t.Fatal(err)
	}
	before = count()
	for _, retryKey := range []identity.IdempotencyKey{key, keyFor("denied_absent")} {
		var forbidden identity.ForbiddenError
		if got, err := denied.ResolveRequestKey(ctx, scope, retryKey, intent, caller); !errors.As(err, &forbidden) || got != (RequestKeyAdmission{}) {
			t.Fatal("denied mapping disclosed or created", err)
		}
	}
	wrongCaller := caller.Clone()
	wrongCaller.Request.Subject.ID = "other"
	if got, err := c.ResolveRequestKey(ctx, scope, keyFor("wrong_actor"), intent, wrongCaller); err == nil || got != (RequestKeyAdmission{}) || count() != before {
		t.Fatal("wrong actor allocated")
	}
	// RK-07: commit acknowledgment failure is not rollback evidence.
	for _, committed := range []bool{false, true} {
		faulted := newCoordinator(conf)
		faulted.requestKeyBegin = func(w context.Context) (pgx.Tx, error) {
			tx, err := pool.Raw().Begin(w)
			if err != nil {
				return nil, err
			}
			return requestKeyCommitFault{Tx: tx, committed: committed}, nil
		}
		retryKey := keyFor("precommit_failure")
		if committed {
			retryKey = keyFor("lost_ack")
		}
		before := count()
		unknown, err := faulted.ResolveRequestKey(ctx, scope, retryKey, intent, caller)
		var ambiguous identity.UnknownCommitError
		if !errors.As(err, &ambiguous) || ambiguous.CommandID == "" || unknown != (RequestKeyAdmission{}) {
			t.Fatal("commit fault granted execution or forged rollback", err)
		}
		wantCount := before
		if committed {
			wantCount++
		}
		if count() != wantCount {
			t.Fatal("commit fault incorrectly modeled durable storage")
		}
		recovered, err := c.ResolveRequestKey(ctx, scope, retryKey, intent, caller)
		if err != nil || committed && recovered.CommandID != ambiguous.CommandID || !committed && recovered.CommandID == ambiguous.CommandID {
			t.Fatal("same-key retry did not resolve actual commit", err)
		}
	}
	// RK-08: an actually aged mapping and retired execution tombstone stay bound.
	agedKey := keyFor("aged_mapping")
	agedDigest, _ := agedKey.Digest(lookupKey)
	agedID, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	agedRaw, _ := base64.RawURLEncoding.DecodeString(string(agedID))
	firstRaw, _ := base64.RawURLEncoding.DecodeString(string(first.CommandID))
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.request_key_mappings(namespace,tenant_id,actor_id,actor_kind,method,route_id,key_digest,command_id,fingerprint,fingerprint_key_version,safe_fields,created_at)
 SELECT namespace,tenant_id,actor_id,actor_kind,method,route_id,$1,$2,fingerprint,fingerprint_key_version,safe_fields,clock_timestamp()-interval '2 days' FROM identity.request_key_mappings WHERE command_id=$3`, agedDigest[:], agedRaw, firstRaw); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.identity_command_id_claims(command_id,retired) VALUES($1,true)`, agedRaw); err != nil {
		t.Fatal(err)
	}
	if got, err := c.ResolveRequestKey(ctx, scope, agedKey, intent, caller); err != nil || got.CommandID != agedID {
		t.Fatal("aged/retired correlation reassigned", err)
	}
	// RK-10: cancellation while an insertion waits for its exact unique-key lock.
	blocker, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	blockedKey := keyFor("blocked_insert")
	blockedDigest, _ := blockedKey.Digest(lookupKey)
	blockedID, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	blockedRaw, _ := base64.RawURLEncoding.DecodeString(string(blockedID))
	if _, err := blocker.Exec(ctx, `INSERT INTO identity.request_key_mappings(namespace,tenant_id,actor_id,actor_kind,method,route_id,key_digest,command_id,fingerprint,fingerprint_key_version,safe_fields)
 SELECT namespace,tenant_id,actor_id,actor_kind,method,route_id,$1,$2,fingerprint,fingerprint_key_version,safe_fields FROM identity.request_key_mappings WHERE command_id=$3`, blockedDigest[:], blockedRaw, firstRaw); err != nil {
		blocker.Rollback(ctx)
		t.Fatal(err)
	}
	short, stop := context.WithTimeout(ctx, 25*time.Millisecond)
	blocked, err := c.ResolveRequestKey(short, scope, blockedKey, intent, caller)
	stop()
	if err == nil || blocked != (RequestKeyAdmission{}) {
		blocker.Rollback(ctx)
		t.Fatal("blocked deadline granted allocation")
	}
	if err := blocker.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if got, err := c.ResolveRequestKey(ctx, scope, blockedKey, intent, caller); err != nil || got.CommandID == "" || got.CommandID == blockedID {
		t.Fatal("timeout leaked lock or adopted rollback row", err)
	}
	// Database enforcement prevents cleanup/update from silently changing meaning.
	for _, table := range []string{"request_key_mappings", "request_key_namespaces"} {
		for _, statement := range []string{"DELETE FROM identity." + table, "TRUNCATE identity." + table + " CASCADE"} {
			_, err := pool.Raw().Exec(ctx, statement)
			var sqlErr *pgconn.PgError
			if !errors.As(err, &sqlErr) || sqlErr.Code != "23514" {
				t.Fatal("correlation removal not fenced")
			}
		}
	}
	if _, err := pool.Raw().Exec(ctx, `UPDATE identity.request_key_mappings SET created_at=clock_timestamp()`); err == nil {
		t.Fatal("replay age reset permitted")
	}
}

func requestKeyCaller(s RequestKeyScope) authorization.DecisionContext {
	return authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Subject: authorization.Subject{ID: authorization.SubjectID(s.ActorID), Kind: s.ActorKind}, Tenant: authorization.TenantID(s.TenantID), Action: authorization.Action(s.RouteID), Resource: authorization.Resource{Type: "identity.request-admission", ID: authorization.ResourceID(s.RouteID)}}}
}

// The only fake boundary is the transaction's transport acknowledgment. SQL and
// actual commit/rollback are real; a returned error alone is never rollback proof.
type requestKeyCommitFault struct {
	pgx.Tx
	committed bool
}

func (tx requestKeyCommitFault) Commit(ctx context.Context) error {
	if tx.committed {
		if err := tx.Tx.Commit(ctx); err != nil {
			return err
		}
	} else {
		if err := tx.Tx.Rollback(ctx); err != nil {
			return err
		}
	}
	return errors.New("synthetic-private-transport-failure")
}
