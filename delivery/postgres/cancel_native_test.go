package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

func cancellationTestBinding(t *testing.T) identity.CommandBinding {
	t.Helper()
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	user, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	op := cancelOperation()
	return identity.CommandBinding{CommandID: id, TenantID: "tenant-a", UserID: identity.UserID(user), ActorID: "actor-a", ActorKind: authorization.SubjectUser, OperationID: op.OperationID, PolicyID: "policy", PolicyVersion: 1, SchemaID: op.SchemaID, SchemaVersion: 1, RecordID: strings.Repeat("a", 64), CorrelationID: "correlation"}
}

func TestNativeCancellationClosedCommandAndInvocation(t *testing.T) {
	b := cancellationTestBinding(t)
	command, err := newCancellationCommand(b, 4294967295, 42, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	spec, generation, version, err := decodeCancellation(command)
	if err != nil || generation != 4294967295 || version != 42 || spec.Binding != b {
		t.Fatal("closed cancellation command changed", err)
	}
	for _, version := range []uint64{0, ^uint64(0)} {
		if _, err := newCancellationCommand(b, 0, version, [32]byte{1}); !errors.Is(err, delivery.ErrInvalidInput) {
			t.Fatal("unsafe status version accepted", err)
		}
	}
	if _, err := newCancellationCommand(b, 0, 1, [32]byte{}); err == nil {
		t.Fatal("empty reason digest accepted")
	}
	for _, edit := range []func(*identity.FeatureCommandSpec){
		func(s *identity.FeatureCommandSpec) { s.Fields[0].Value.Uint64 = 4294967296 },
		func(s *identity.FeatureCommandSpec) { s.Fields[0].Name = "delivery.other" },
		func(s *identity.FeatureCommandSpec) { s.Fields[1].Value.Bytes = make([]byte, 32) },
		func(s *identity.FeatureCommandSpec) { s.Fields = s.Fields[:2] },
		func(s *identity.FeatureCommandSpec) { s.Operation = EnqueueOperation() },
	} {
		s, _ := command.Feature()
		edit(&s)
		bad, err := identity.NewFeatureCommand(s)
		if err == nil {
			if _, _, _, err := decodeCancellation(bad); err == nil {
				t.Fatal("ambiguous cancellation command accepted")
			}
		}
	}
	native := &cancelContributor{store: &attemptStore{deployment: "test"}}
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	if _, err := native.ApplyFeature(cancelled, identitypostgres.Work{}, command); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
	if _, err := native.ApplyFeature(context.Background(), identitypostgres.Work{}, command); !errors.Is(err, delivery.ErrForbidden) {
		t.Fatal("zero Work granted authority", err)
	}
	if _, err := native.RecoverParticipant(context.Background(), identitypostgres.RecoveryWork{}); !errors.Is(err, delivery.ErrForbidden) {
		t.Fatal("zero recovery Work granted evidence", err)
	}
	if native.Descriptor() == (*EnqueueContributor)(nil).Descriptor() || len(native.FeatureOperations()) != 1 || native.FeatureOperations()[0] != cancelOperation() {
		t.Fatal("native owner collided with enqueue")
	}
}
