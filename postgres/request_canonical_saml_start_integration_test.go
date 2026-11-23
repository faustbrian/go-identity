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

type samlStartRequestPreparationProbe struct{ requestPreparationParticipant }

func (*samlStartRequestPreparationProbe) Descriptor() ContributorDescriptor {
	descriptor, _ := ssoEnterpriseStartProfile(SSOSAMLSigninStartOperation())
	return descriptor
}

func testCanonicalSAMLStartRequests(t *testing.T, ctx context.Context, db *sql.DB, pool *database.Pool, config CoordinatorConfig, policy CommandQueryPolicy, keys RequestKeyConfig) {
	t.Helper()
	backend, err := migrationdb.New(db)
	if err != nil {
		t.Fatal(err)
	}
	base := CanonicalRequestMigrationSource{
		Base: RequestKeyExpiryMigrationSource{Base: RequestKeyPreparationMigrationSource{
			Base: RequestKeyMigrationSource{Base: MigrationSource{}, Version: 10}, Version: 11,
		}, Version: 12},
		Version: 13,
	}
	var oldMappings, oldAliases int
	if err := db.QueryRowContext(ctx, `SELECT
		(SELECT count(*) FROM identity.request_key_mappings WHERE method='DELETE'),
		(SELECT count(*) FROM identity.request_key_aliases WHERE method='DELETE')`).Scan(&oldMappings, &oldAliases); err != nil || oldMappings == 0 || oldAliases == 0 {
		t.Fatal("expected populated canonical DELETE history", err)
	}
	runner, err := migrations.NewRunner(CanonicalSAMLStartRequestMigrationSource{Base: base, Version: 14}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(ctx); err != nil {
		t.Fatal("populated SAML start upgrade", err)
	}

	operation := SSOSAMLSigninStartOperation()
	calls := 0
	owner := &samlStartRequestPreparationProbe{requestPreparationParticipant{
		scopeFeatureParticipant: scopeFeatureParticipant{operations: []identity.FeatureOperation{operation}},
		prepare: func(_ context.Context, b RequestKeyPreparationBinding, _ identity.RequestIntent) ([]byte, error) {
			calls++
			return []byte(b.Admission.CommandID), nil
		},
	}}
	registry, err := NewContributorRegistry([]Contributor{owner})
	if err != nil {
		t.Fatal(err)
	}
	feature := FeatureRegistration{Operation: operation, Contributor: owner.Descriptor()}
	keys.Namespace = "canonical-saml-start-test"
	config.QueryPolicy = &policy
	coordinator, err := NewCoordinatorWithCanonicalSSOSAMLStartRequestKeys(pool, registry, config, keys)
	if err != nil {
		t.Fatal(err)
	}
	scope := RequestKeyScope{TenantID: "tenant", ActorID: "actor", ActorKind: authorization.SubjectServiceAccount, Method: "GET", RouteID: operation.OperationID}
	caller := requestKeyCaller(scope)
	selector, _ := NewCanonicalRequestKey([]byte("original-anonymous-flow/selected-provider"))
	intent, _ := identity.NewRequestIntent([]identity.FeatureField{{Name: "provider", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: 1}}})
	first, wire, err := coordinator.ResolvePreparedCanonicalRequest(ctx, scope, selector, nil, intent, caller, feature, owner)
	if err != nil || first.Admission.CommandID == "" || calls != 1 || !bytes.Equal(wire, []byte(first.Admission.CommandID)) {
		t.Fatal("headerless SAML start did not retain the original command", err)
	}
	alias, _ := identity.NewIdempotencyKey([]byte("optional-saml-start-key"))
	again, stored, err := coordinator.ResolvePreparedCanonicalRequest(ctx, scope, selector, &alias, intent, caller, feature, owner)
	if err != nil || again != first || calls != 1 || !bytes.Equal(stored, wire) {
		t.Fatal("optional client key selected another SAML command", err)
	}
	other, _ := NewCanonicalRequestKey([]byte("another-anonymous-flow/selected-provider"))
	var conflict identity.ConflictError
	if _, out, err := coordinator.ResolvePreparedCanonicalRequest(ctx, scope, other, &alias, intent, caller, feature, owner); !errors.As(err, &conflict) || out != nil || calls != 1 {
		t.Fatal("an alias was rebound to a different server selector", err)
	}
	read, original, found, err := coordinator.ReadPreparedCanonicalRequest(ctx, scope, selector, &alias, intent, caller, feature, owner)
	if err != nil || !found || read != first || !bytes.Equal(original, wire) || calls != 1 {
		t.Fatal("exact read-only recovery did not reuse original SAML input", err)
	}
	var mappings, aliases int
	if err := db.QueryRowContext(ctx, `SELECT
		(SELECT count(*) FROM identity.request_key_mappings WHERE method='DELETE'),
		(SELECT count(*) FROM identity.request_key_aliases WHERE method='DELETE')`).Scan(&mappings, &aliases); err != nil || mappings != oldMappings || aliases != oldAliases {
		t.Fatal("existing DELETE history changed", err)
	}
}
