//go:build integration

package postgres

import (
	"bytes"
	"context"
	"errors"
	"testing"

	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

func testCanonicalPostRequests(t *testing.T, ctx context.Context, pool *database.Pool, config CoordinatorConfig, policy CommandQueryPolicy, keys RequestKeyConfig) {
	t.Helper()
	_, command, plan := featurePlanFixture(t)
	spec, _ := command.Feature()
	scope := RequestKeyScope{TenantID: "tenant", ActorID: "actor", ActorKind: spec.Binding.ActorKind, Method: "POST", RouteID: spec.Operation.OperationID}
	caller := requestKeyCaller(scope)
	feature := *plan.Feature
	calls := 0
	owner := &requestPreparationParticipant{scopeFeatureParticipant: scopeFeatureParticipant{operations: []identity.FeatureOperation{spec.Operation}}, prepare: func(_ context.Context, b RequestKeyPreparationBinding, _ identity.RequestIntent) ([]byte, error) {
		calls++
		return []byte(b.Admission.CommandID), nil
	}}
	feature.Contributor = owner.Descriptor()
	registry, err := NewContributorRegistry([]Contributor{owner})
	if err != nil {
		t.Fatal(err)
	}
	keys.Namespace = "canonical-post-test"
	config.QueryPolicy = &policy
	coordinator, err := NewCoordinatorWithCanonicalPostRequestKeys(pool, registry, config, keys)
	if err != nil {
		t.Fatal(err)
	}
	selector, _ := NewCanonicalRequestKey([]byte("organization/provider/version"))
	intent, _ := identity.NewRequestIntent([]identity.FeatureField{{Name: "configuration", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: 1}}})
	changed, _ := identity.NewRequestIntent([]identity.FeatureField{{Name: "configuration", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: 2}}})
	optional, _ := identity.NewIdempotencyKey([]byte("canonical-post-no-client-key"))
	zero := RequestKeyPreparationBinding{}
	if binding, wire, found, err := coordinator.ReadPreparedCanonicalRequest(ctx, scope, selector, nil, intent, caller, feature, owner); err != nil || found || binding != zero || wire != nil || calls != 0 {
		t.Fatal("read-only POST absence allocated an original", err)
	}
	if binding, wire, err := coordinator.ResolvePreparedCanonicalRequest(ctx, scope, selector, &optional, intent, caller, feature, owner); err == nil || binding != zero || wire != nil || calls != 0 {
		t.Fatal("canonical POST accepted a client alias")
	}
	wrong := scope
	wrong.Method = "DELETE"
	if binding, wire, err := coordinator.ResolvePreparedCanonicalRequest(ctx, wrong, selector, nil, intent, requestKeyCaller(wrong), feature, owner); err == nil || binding != zero || wire != nil || calls != 0 {
		t.Fatal("POST coordinator admitted a DELETE request")
	}
	coordinator.requestKeyBegin = func(ctx context.Context) (pgx.Tx, error) {
		tx, err := pool.Raw().Begin(ctx)
		if err != nil {
			return nil, err
		}
		return &requestKeyCommitFault{Tx: tx, committed: true}, nil
	}
	binding, wire, err := coordinator.ResolvePreparedCanonicalRequest(ctx, scope, selector, nil, intent, caller, feature, owner)
	var unknown identity.UnknownCommitError
	if !errors.As(err, &unknown) || unknown.CommandID == "" || binding != zero || wire != nil || calls != 1 {
		t.Fatal("unacknowledged POST did not retain original identity or disclosed custody", err)
	}
	restarted, err := NewCoordinatorWithCanonicalPostRequestKeys(pool, registry, config, keys)
	if err != nil {
		t.Fatal(err)
	}
	read, original, found, err := restarted.ReadPreparedCanonicalRequest(ctx, scope, selector, nil, intent, caller, feature, owner)
	if err != nil || !found || read.Scope != scope || read.Admission.CommandID != unknown.CommandID || !bytes.Equal(original, []byte(unknown.CommandID)) {
		t.Fatal("restart did not observe the exact acknowledged original", err)
	}
	defer clear(original)
	repeat, stored, err := restarted.ResolvePreparedCanonicalRequest(ctx, scope, selector, nil, intent, caller, feature, owner)
	defer clear(stored)
	if err != nil || repeat != read || !bytes.Equal(stored, original) || calls != 1 {
		t.Fatal("matching POST recreated original preparation", err)
	}
	var conflict identity.ConflictError
	if binding, wire, err := restarted.ResolvePreparedCanonicalRequest(ctx, scope, selector, nil, changed, caller, feature, owner); !errors.As(err, &conflict) || binding != zero || wire != nil || calls != 1 {
		t.Fatal("changed POST intent acquired or remapped custody", err)
	}
	legacy, err := NewCoordinatorWithRequestKeys(pool, registry, config, keys)
	if err != nil {
		t.Fatal(err)
	}
	if admission, err := legacy.ResolveRequestKey(ctx, scope, optional, intent, caller); !errors.As(err, &conflict) || admission != (RequestKeyAdmission{}) {
		t.Fatal("legacy key allocation shared the installed POST namespace", err)
	}
	deletion, err := NewCoordinatorWithCanonicalRequestKeys(pool, registry, config, keys)
	if err != nil {
		t.Fatal(err)
	}
	if binding, wire, err := deletion.ResolvePreparedCanonicalRequest(ctx, wrong, selector, nil, intent, requestKeyCaller(wrong), feature, owner); !errors.As(err, &conflict) || binding != zero || wire != nil || calls != 1 {
		t.Fatal("canonical DELETE shared the installed POST namespace", err)
	}
	testMappedFeatureRecovery(t, ctx, restarted, owner, read, original, spec.Binding)
}
