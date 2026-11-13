//go:build integration

package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

func testCanonicalRequests(t *testing.T, ctx context.Context, db *sql.DB, pool *database.Pool, config CoordinatorConfig, policy CommandQueryPolicy, keys RequestKeyConfig) {
	t.Helper()
	backend, err := migrationdb.New(db)
	if err != nil {
		t.Fatal(err)
	}
	base := RequestKeyExpiryMigrationSource{Base: RequestKeyPreparationMigrationSource{Base: RequestKeyMigrationSource{Base: MigrationSource{}, Version: 10}, Version: 11}, Version: 12}
	runner, err := migrations.NewRunner(CanonicalRequestMigrationSource{Base: base, Version: 13}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(ctx); err != nil {
		t.Fatal("populated canonical upgrade", err)
	}
	_, command, plan := featurePlanFixture(t)
	spec, _ := command.Feature()
	calls := 0
	owner := &requestPreparationParticipant{scopeFeatureParticipant: scopeFeatureParticipant{operations: []identity.FeatureOperation{spec.Operation}}, prepare: func(_ context.Context, b RequestKeyPreparationBinding, _ identity.RequestIntent) ([]byte, error) {
		calls++
		return []byte(b.Admission.CommandID), nil
	}}
	registry, err := NewContributorRegistry([]Contributor{owner})
	if err != nil {
		t.Fatal(err)
	}
	feature := *plan.Feature
	feature.Contributor = owner.Descriptor()
	keys.Namespace = "canonical-delete-test"
	config.QueryPolicy = &policy
	c, err := NewCoordinatorWithCanonicalRequestKeys(pool, registry, config, keys)
	if err != nil {
		t.Fatal(err)
	}
	scope := RequestKeyScope{TenantID: "tenant", ActorID: "actor", ActorKind: spec.Binding.ActorKind, Method: "DELETE", RouteID: spec.Operation.OperationID}
	caller := requestKeyCaller(scope)
	selector, _ := NewCanonicalRequestKey([]byte("connection/target/expected-version"))
	intent, _ := identity.NewRequestIntent([]identity.FeatureField{{Name: "configuration", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: 1}}})
	first, wire, err := c.ResolvePreparedCanonicalRequest(ctx, scope, selector, nil, intent, caller, feature, owner)
	if err != nil || first.Admission.CommandID == "" || !bytes.Equal(wire, []byte(first.Admission.CommandID)) || calls != 1 {
		t.Fatal("headerless original not retained", err)
	}
	alias, _ := identity.NewIdempotencyKey([]byte("late-optional-key"))
	again, stored, err := c.ResolvePreparedCanonicalRequest(ctx, scope, selector, &alias, intent, caller, feature, owner)
	if err != nil || again != first || !bytes.Equal(stored, wire) || calls != 1 {
		t.Fatal("late optional alias changed original command", err)
	}
	read, original, found, err := c.ReadPreparedCanonicalRequest(ctx, scope, selector, &alias, intent, caller, feature, owner)
	if err != nil || !found || read != first || !bytes.Equal(original, wire) || calls != 1 {
		t.Fatal("read-only canonical custody lost", err)
	}
	changed, _ := identity.NewRequestIntent([]identity.FeatureField{{Name: "configuration", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: 2}}})
	if b, out, err := c.ResolvePreparedCanonicalRequest(ctx, scope, selector, nil, changed, caller, feature, owner); err == nil || b != (RequestKeyPreparationBinding{}) || out != nil {
		t.Fatal("changed intent acquired original custody")
	}
	other, _ := NewCanonicalRequestKey([]byte("connection/another-target/expected-version"))
	if b, out, err := c.ResolvePreparedCanonicalRequest(ctx, scope, other, &alias, intent, caller, feature, owner); err == nil || b != (RequestKeyPreparationBinding{}) || out != nil {
		t.Fatal("alias rebound to another canonical request")
	}
	t.Run("known alias conflicts before failed preparation", func(t *testing.T) {
		prepare := owner.prepare
		defer func() { owner.prepare = prepare }()
		called := false
		owner.prepare = func(context.Context, RequestKeyPreparationBinding, identity.RequestIntent) ([]byte, error) {
			called = true
			return nil, errors.New("private new-target preparation failure")
		}
		b, out, err := c.ResolvePreparedCanonicalRequest(ctx, scope, other, &alias, intent, caller, feature, owner)
		var conflict identity.ConflictError
		if !errors.As(err, &conflict) || called || b != (RequestKeyPreparationBinding{}) || out != nil {
			t.Fatal("known alias did not conflict before unrelated preparation", called, err)
		}
	})
	var mappings, aliases int
	if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.request_key_mappings WHERE namespace=$1),(SELECT count(*) FROM identity.request_key_aliases WHERE namespace=$1)`, keys.Namespace).Scan(&mappings, &aliases); err != nil || mappings != 1 || aliases != 1 {
		t.Fatal("conflict left orphan correlation or alias", mappings, aliases, err)
	}
	config.CurrentFingerprintKeyVersion = 2
	config.RetainedFingerprintKeys = map[uint32][32]byte{1: {1}, 2: {9}}
	rotated, err := NewCoordinatorWithCanonicalRequestKeys(pool, registry, config, keys)
	if err != nil {
		t.Fatal(err)
	}
	recovered, out, err := rotated.ResolvePreparedCanonicalRequest(ctx, scope, selector, nil, intent, caller, feature, owner)
	if err != nil || recovered != first || !bytes.Equal(out, wire) {
		t.Fatal("retained fingerprint rotation changed original custody", err)
	}
	legacy, err := NewCoordinatorWithRequestKeys(pool, registry, config, keys)
	if err != nil {
		t.Fatal(err)
	}
	if admission, err := legacy.ResolveRequestKey(ctx, scope, alias, intent, caller); err == nil || admission != (RequestKeyAdmission{}) {
		t.Fatal("namespace admitted mixed canonical and legacy allocation")
	}
	if b, out, err := c.ResolvePreparedRequestKey(ctx, scope, alias, intent, caller, feature, owner); err == nil || b != (RequestKeyPreparationBinding{}) || out != nil {
		t.Fatal("canonical owner admitted legacy key allocation")
	}
	missing, _ := NewCanonicalRequestKey([]byte("connection/missing/expected-version"))
	before := calls
	if b, out, found, err := c.ReadPreparedCanonicalRequest(ctx, scope, missing, nil, intent, caller, feature, owner); err != nil || found || b != (RequestKeyPreparationBinding{}) || out != nil || calls != before {
		t.Fatal("canonical read absence allocated or prepared")
	}
	t.Run("lost acknowledgement retains one canonical and alias", func(t *testing.T) {
		selector, _ := NewCanonicalRequestKey([]byte("connection/unknown-target/version"))
		alias, _ := identity.NewIdempotencyKey([]byte("unknown-optional-key"))
		c.requestKeyBegin = func(ctx context.Context) (pgx.Tx, error) {
			tx, err := pool.Raw().Begin(ctx)
			if err != nil {
				return nil, err
			}
			return &requestKeyCommitFault{Tx: tx, committed: true}, nil
		}
		b, out, err := c.ResolvePreparedCanonicalRequest(ctx, scope, selector, &alias, intent, caller, feature, owner)
		c.requestKeyBegin = nil
		var unknown identity.UnknownCommitError
		if !errors.As(err, &unknown) || unknown.CommandID == "" || b != (RequestKeyPreparationBinding{}) || out != nil {
			t.Fatal("unknown acknowledgement returned custody or lost correlation", err)
		}
		before := calls
		b, out, err = c.ResolvePreparedCanonicalRequest(ctx, scope, selector, &alias, intent, caller, feature, owner)
		if err != nil || b.Admission.CommandID != unknown.CommandID || !bytes.Equal(out, []byte(unknown.CommandID)) || calls != before {
			t.Fatal("unknown retry allocated or prepared another original", err)
		}
	})
	t.Run("concurrent headerless and keyed share original", func(t *testing.T) {
		// Distinct exact owner/registry for this race: its pure preparation reads
		// only the supplied binding, not the outer serial test's call counter.
		parallelOwner := &requestPreparationParticipant{scopeFeatureParticipant: owner.scopeFeatureParticipant, prepare: func(_ context.Context, b RequestKeyPreparationBinding, _ identity.RequestIntent) ([]byte, error) {
			return []byte(b.Admission.CommandID), nil
		}}
		parallelRegistry, err := NewContributorRegistry([]Contributor{parallelOwner})
		if err != nil {
			t.Fatal(err)
		}
		parallel, err := NewCoordinatorWithCanonicalRequestKeys(pool, parallelRegistry, config, keys)
		if err != nil {
			t.Fatal(err)
		}
		selector, _ := NewCanonicalRequestKey([]byte("connection/concurrent-target/version"))
		alias, _ := identity.NewIdempotencyKey([]byte("concurrent-optional-key"))
		start := make(chan struct{})
		var wg sync.WaitGroup
		var results [2]RequestKeyPreparationBinding
		var outputs [2][]byte
		var failures [2]error
		for index := range results {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()
				<-start
				var optional *identity.IdempotencyKey
				if index == 1 {
					optional = &alias
				}
				results[index], outputs[index], failures[index] = parallel.ResolvePreparedCanonicalRequest(ctx, scope, selector, optional, intent, caller, feature, parallelOwner)
			}(index)
		}
		close(start)
		wg.Wait()
		if failures[0] != nil || failures[1] != nil || results[0] != results[1] || !bytes.Equal(outputs[0], outputs[1]) || !bytes.Equal(outputs[0], []byte(results[0].Admission.CommandID)) {
			t.Fatal("concurrent requests selected different originals", failures)
		}
		b, out, err := parallel.ResolvePreparedCanonicalRequest(ctx, scope, selector, &alias, intent, caller, feature, parallelOwner)
		if err != nil || b != results[0] || !bytes.Equal(out, outputs[0]) {
			t.Fatal("concurrent alias was not attached to winner", err)
		}
	})
	// Existing recovery owns outcome: an original mapping without a journal is
	// unknown, never proof that a DELETE did not commit.
	testMappedFeatureRecovery(t, ctx, c, owner, first, wire, spec.Binding)
	var conflict identity.ConflictError
	if _, _, err := c.ResolvePreparedCanonicalRequest(ctx, scope, other, &alias, intent, caller, feature, owner); !errors.As(err, &conflict) {
		t.Fatal("alias conflict lost typed outcome", err)
	}
}
