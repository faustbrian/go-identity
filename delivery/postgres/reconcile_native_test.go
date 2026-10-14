package postgres

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

func TestNativeReconciliationClosedCommandAndInvocation(t *testing.T) {
	b := cancellationTestBinding(t)
	op := reconciliationOperation()
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	q := receiptShape()
	q.IntentID = delivery.IntentID(b.RecordID)
	store := &receiptStore{deployment: "test", namespaceKey: [32]byte{1}}
	command, err := newReconciliationCommand(b, q, 42, 3, [32]byte{1}, [32]byte{2}, store)
	if err != nil {
		t.Fatal(err)
	}
	spec, decoded, event, evidence, version, step, before, after, err := decodeReconciliation(command)
	wantEvent, wantEvidence := store.digests(q)
	if err != nil || spec.Binding != b || decoded.Status != q.Status || event != wantEvent || evidence != wantEvidence || version != 42 || step != 3 || before != ([32]byte{1}) || after != ([32]byte{2}) {
		t.Fatal("closed reconciliation lost original scope", err)
	}
	for _, field := range spec.Fields {
		if strings.Contains(field.Value.Text, q.ProviderEventID) {
			t.Fatal("provider event entered journal")
		}
	}
	if _, err := newReconciliationCommand(b, q, 42, -1, [32]byte{}, [32]byte{}, store); !errors.Is(err, delivery.ErrInvalidInput) {
		t.Fatal("negative checkpoint step", err)
	}
	native := &reconciliationContributor{store: store}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := native.ApplyFeature(ctx, identitypostgres.Work{}, command); !errors.Is(err, context.Canceled) {
		t.Fatal("lost cancellation", err)
	}
	if _, err := native.ApplyFeature(context.Background(), identitypostgres.Work{}, command); !errors.Is(err, delivery.ErrForbidden) {
		t.Fatal("unregistered work granted mutation", err)
	}
	if _, err := native.RecoverParticipant(context.Background(), identitypostgres.RecoveryWork{}); !errors.Is(err, delivery.ErrForbidden) {
		t.Fatal("unregistered recovery granted proof", err)
	}
}

func TestNativeReconciliationRejectsChangedClosedShape(t *testing.T) {
	b := cancellationTestBinding(t)
	op := reconciliationOperation()
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	q := receiptShape()
	q.IntentID = delivery.IntentID(b.RecordID)
	store := &receiptStore{deployment: "test", namespaceKey: [32]byte{1}}
	command, err := newReconciliationCommand(b, q, 1, 0, [32]byte{}, [32]byte{}, store)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*identity.FeatureCommandSpec){
		func(s *identity.FeatureCommandSpec) { s.Fields = s.Fields[:9] },
		func(s *identity.FeatureCommandSpec) {
			s.Fields = append(s.Fields, identity.FeatureField{Name: "extra.value", Value: identity.FeatureValue{Kind: identity.FeatureBool}})
		},
		func(s *identity.FeatureCommandSpec) { s.Fields[0].Value.Bytes = make([]byte, 31) },
		func(s *identity.FeatureCommandSpec) { s.Fields[1].Value.Bytes = make([]byte, 33) },
		func(s *identity.FeatureCommandSpec) { s.Fields[2].Value.Uint64 = math.MaxInt64 },
		func(s *identity.FeatureCommandSpec) { s.Fields[3].Value.Bytes = make([]byte, 32) },
		func(s *identity.FeatureCommandSpec) { s.Fields[5].Value.Uint64 = 0 },
		func(s *identity.FeatureCommandSpec) { s.Fields[9].Value.Uint64 = math.MaxUint64 },
	} {
		spec, _ := command.Feature()
		mutate(&spec)
		changed, err := identity.NewFeatureCommand(spec)
		if err != nil {
			continue
		}
		if _, _, _, _, _, _, _, _, err := decodeReconciliation(changed); !errors.Is(err, delivery.ErrInvalidInput) {
			t.Fatal("changed closed shape admitted", err)
		}
	}
	native := &reconciliationContributor{store: store}
	plan := identitypostgres.CommandPlan{SubjectType: "delivery_intent", Feature: &identitypostgres.FeatureRegistration{Contributor: native.Descriptor(), Operation: op}, Lifecycle: &identitypostgres.LifecyclePlan{EventType: "delivery.reconciled.v1", BeforeVersion: 1, AfterVersion: 2}, Audits: []identitypostgres.AuditPlan{{EventType: op.OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, RetentionClass: "protected", RetentionPolicyVersion: 1}}}
	if err := native.ValidateFeatureCommand(command, plan); err != nil {
		t.Fatal(err)
	}
	plan.Lifecycle.EventType = "delivery.receipt-recorded.v1"
	if !errors.Is(native.ValidateFeatureCommand(command, plan), delivery.ErrInvalidInput) {
		t.Fatal("wrong lifecycle admitted")
	}
}
