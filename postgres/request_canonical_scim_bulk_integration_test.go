//go:build integration

package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	database "github.com/faustbrian/go-postgres"
)

type scimBulkRequestPreparationProbe struct{ requestPreparationParticipant }

func (*scimBulkRequestPreparationProbe) Descriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "scim/postgres", ContractID: "identity.scim", Version: 1}
}

func testCanonicalSCIMBulkRequests(t *testing.T, ctx context.Context, db *sql.DB, pool *database.Pool, config CoordinatorConfig, policy CommandQueryPolicy, keys RequestKeyConfig) {
	t.Helper()
	backend, err := migrationdb.New(db)
	if err != nil {
		t.Fatal(err)
	}
	base := CanonicalSAMLStartRequestMigrationSource{Base: CanonicalRequestMigrationSource{
		Base: RequestKeyExpiryMigrationSource{Base: RequestKeyPreparationMigrationSource{
			Base: RequestKeyMigrationSource{Base: MigrationSource{}, Version: 10}, Version: 11,
		}, Version: 12}, Version: 13,
	}, Version: 14}
	historyCounts := func() [2]int {
		t.Helper()
		var counts [2]int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FILTER (WHERE method='DELETE'), count(*) FILTER (WHERE method='GET') FROM identity.request_key_aliases`).Scan(&counts[0], &counts[1]); err != nil {
			t.Fatal(err)
		}
		return counts
	}
	before := historyCounts()
	if before[0] == 0 || before[1] == 0 {
		t.Fatal("expected populated DELETE and SAML start aliases")
	}
	runner, err := migrations.NewRunner(CanonicalSCIMBulkRequestMigrationSource{Base: base, Version: 16}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(ctx); err != nil {
		t.Fatal("populated SCIM Bulk upgrade", err)
	}

	const route = "identity.scim.bulk"
	operation := identity.FeatureOperation{Owner: "scim", OperationID: route, SchemaID: route + ".native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	otherOperation := identity.FeatureOperation{Owner: "scim", OperationID: "identity.scim.group-create", SchemaID: "identity.scim.group-create.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	alternateBulk := operation
	alternateBulk.SchemaID = route + ".alternate-v1"
	preparations := 0
	owner := &scimBulkRequestPreparationProbe{requestPreparationParticipant{
		scopeFeatureParticipant: scopeFeatureParticipant{operations: []identity.FeatureOperation{operation, otherOperation, alternateBulk}},
		prepare: func(_ context.Context, binding RequestKeyPreparationBinding, _ identity.RequestIntent) ([]byte, error) {
			preparations++
			return []byte(binding.Admission.CommandID), nil
		},
	}}
	registry, err := NewContributorRegistry([]Contributor{owner})
	if err != nil {
		t.Fatal(err)
	}
	keys.Namespace = "canonical-scim-bulk-test"
	config.QueryPolicy = &policy
	bulk, err := NewCoordinatorWithCanonicalSCIMBulkRequestKeys(pool, registry, config, keys)
	if err != nil {
		t.Fatal(err)
	}
	scope := RequestKeyScope{TenantID: "tenant", ActorID: "actor", ActorKind: authorization.SubjectServiceAccount, Method: "POST", RouteID: route}
	feature := FeatureRegistration{Operation: operation, Contributor: owner.Descriptor()}
	caller := requestKeyCaller(scope)
	selector, _ := NewCanonicalRequestKey([]byte("connection/ordered-original-bulk"))
	intent, _ := identity.NewRequestIntent([]identity.FeatureField{{Name: "configuration", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: 1}}})
	first, original, err := bulk.ResolvePreparedCanonicalRequest(ctx, scope, selector, nil, intent, caller, feature, owner)
	if err != nil || first.Admission.CommandID == "" || preparations != 1 || !bytes.Equal(original, []byte(first.Admission.CommandID)) {
		t.Fatal("headerless Bulk did not retain one original command", err)
	}
	alias, _ := identity.NewIdempotencyKey([]byte("optional-scim-bulk-key"))
	again, keyed, err := bulk.ResolvePreparedCanonicalRequest(ctx, scope, selector, &alias, intent, caller, feature, owner)
	if err != nil || again != first || !bytes.Equal(keyed, original) || preparations != 1 {
		t.Fatal("late retry key did not alias the original parent", err)
	}
	other, _ := NewCanonicalRequestKey([]byte("connection/changed-ordered-bulk"))
	var conflict identity.ConflictError
	if binding, wire, err := bulk.ResolvePreparedCanonicalRequest(ctx, scope, other, &alias, intent, caller, feature, owner); !errors.As(err, &conflict) || binding != (RequestKeyPreparationBinding{}) || wire != nil || preparations != 1 {
		t.Fatal("key reuse for a changed request prepared or disclosed custody", err)
	}
	for _, retryKey := range []*identity.IdempotencyKey{nil, &alias} {
		binding, wire, found, err := bulk.ReadPreparedCanonicalRequest(ctx, scope, selector, retryKey, intent, caller, feature, owner)
		if err != nil || !found || binding != first || !bytes.Equal(wire, original) || preparations != 1 {
			t.Fatal("matching read did not recover original custody", err)
		}
	}
	wrongRoute, wrongFeature := scope, feature
	wrongRoute.RouteID, wrongFeature.Operation = otherOperation.OperationID, otherOperation
	wrongActor := scope
	wrongActor.ActorKind = authorization.SubjectUser
	wrongSchema := feature
	wrongSchema.Operation = alternateBulk
	for _, denied := range []struct {
		name    string
		scope   RequestKeyScope
		feature FeatureRegistration
	}{
		{"unrelated POST", wrongRoute, wrongFeature},
		{"non-service actor", wrongActor, feature},
		{"alternate registered Bulk schema", scope, wrongSchema},
	} {
		binding, wire, err := bulk.ResolvePreparedCanonicalRequest(ctx, denied.scope, selector, nil, intent, requestKeyCaller(denied.scope), denied.feature, owner)
		if err == nil || binding != (RequestKeyPreparationBinding{}) || wire != nil || preparations != 1 {
			t.Fatalf("selected Bulk profile accepted %s: %v", denied.name, err)
		}
	}
	if after := historyCounts(); after != before {
		t.Fatal("existing DELETE and SAML aliases changed", before, after)
	}
}
