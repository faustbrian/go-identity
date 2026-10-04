package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

func TestNativeReceiptClosedCommandAndInvocation(t *testing.T) {
	b := cancellationTestBinding(t)
	op := receiptOperation()
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	q := receiptShape()
	q.IntentID = delivery.IntentID(b.RecordID)
	s := &receiptStore{deployment: "test", namespaceKey: [32]byte{1}}
	command, err := newReceiptCommand(b, q, 42, s)
	if err != nil {
		t.Fatal(err)
	}
	spec, request, event, evidence, version, err := decodeReceiptCommand(command)
	wantEvent, wantEvidence := s.digests(q)
	if err != nil || spec.Binding != b || request.Status != q.Status || request.Provider != q.Provider || request.Generation != q.Generation || version != 42 || event != wantEvent || evidence != wantEvidence {
		t.Fatal("closed receipt lost scope", err)
	}
	for _, f := range spec.Fields {
		if strings.Contains(f.Value.Text, q.ProviderEventID) {
			t.Fatal("raw provider event entered journal")
		}
	}
	for _, v := range []uint64{0, ^uint64(0)} {
		if _, err := newReceiptCommand(b, q, v, s); !errors.Is(err, delivery.ErrInvalidInput) {
			t.Fatal("unsafe version admitted", err)
		}
	}
	for _, edit := range []func(*identity.FeatureCommandSpec){
		func(s *identity.FeatureCommandSpec) { s.Fields[0].Value.Bytes = make([]byte, 32) },
		func(s *identity.FeatureCommandSpec) { s.Fields[2].Value.Uint64 = 4294967296 },
		func(s *identity.FeatureCommandSpec) { s.Fields[5].Value.Uint64 = uint64(delivery.StateQueued) },
		func(s *identity.FeatureCommandSpec) { s.Fields = s.Fields[:6] },
	} {
		bad, _ := command.Feature()
		edit(&bad)
		changed, e := identity.NewFeatureCommand(bad)
		if e == nil {
			if _, _, _, _, _, e = decodeReceiptCommand(changed); e == nil {
				t.Fatal("ambiguous receipt admitted")
			}
		}
	}
	native := &receiptContributor{store: s}
	ctx, stop := context.WithCancel(context.Background())
	stop()
	if _, err := native.ApplyFeature(ctx, identitypostgres.Work{}, command); !errors.Is(err, context.Canceled) {
		t.Fatal("lost cancellation", err)
	}
	if _, err := native.ApplyFeature(context.Background(), identitypostgres.Work{}, command); !errors.Is(err, delivery.ErrForbidden) {
		t.Fatal("zero Work granted authority", err)
	}
	if _, err := native.RecoverParticipant(context.Background(), identitypostgres.RecoveryWork{}); !errors.Is(err, delivery.ErrForbidden) {
		t.Fatal("zero recovery granted evidence", err)
	}
}
