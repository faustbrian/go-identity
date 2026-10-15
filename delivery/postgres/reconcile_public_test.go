package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/delivery"
)

type reconcileQueryFunc func(context.Context, delivery.OutcomeQuery) (delivery.OutcomeObservation, error)

func (f reconcileQueryFunc) QueryOutcome(ctx context.Context, q delivery.OutcomeQuery) (delivery.OutcomeObservation, error) {
	return f(ctx, q)
}

func TestReconciliationRecoveryRequiresOwnedComposition(t *testing.T) {
	if _, err := (&EnqueueService{}).RecoverReconciliation(context.Background(), identity.RecoveryQuery{}, authorization.DecisionContext{}); !errors.Is(err, delivery.ErrInvalidInput) {
		t.Fatal("zero composition admitted recovery", err)
	}
}

func TestPublicReconciliationConfigurationAndRedaction(t *testing.T) {
	c := EnqueueConfig{Timeout: 2 * time.Second, StateTracking: true, Custody: ContributorConfig{ProviderProfiles: map[uint64]ProviderProfile{1: {Provider: "provider", PolicyVersion: 1}}}, Reconciliation: &ReconciliationConfig{Timeout: time.Second, Concurrency: 1, Providers: []ReconciliationProvider{{TenantID: "tenant", ProviderConfigVersion: 1, ActorID: "query-service", Querier: reconcileQueryFunc(func(context.Context, delivery.OutcomeQuery) (delivery.OutcomeObservation, error) {
		return delivery.OutcomeObservation{}, delivery.ErrUnavailable
	})}}}}
	if _, err := reconciliationConfiguration(c); err != nil {
		t.Fatal(err)
	}
	bad := c
	bad.StateTracking = false
	if _, err := reconciliationConfiguration(bad); !errors.Is(err, delivery.ErrInvalidInput) {
		t.Fatal("untracked query enabled", err)
	}
	c.Reconciliation.Providers[0].Querier = nil
	if _, err := reconciliationConfiguration(c); !errors.Is(err, delivery.ErrInvalidInput) {
		t.Fatal("missing real querier enabled", err)
	}
	request := ReconcileCommandRequest{Checkpoint: "synthetic-private-checkpoint"}
	if strings.Contains(fmt.Sprintf("%+v", request), request.Checkpoint) {
		t.Fatal("checkpoint diagnostic disclosure")
	}
	if _, err := json.Marshal(request); !errors.Is(err, delivery.ErrSerializationForbidden) {
		t.Fatal("checkpoint serialization", err)
	}
	if _, err := (&EnqueueService{}).Reconcile(context.Background(), request); !errors.Is(err, delivery.ErrInvalidInput) {
		t.Fatal("zero service granted query", err)
	}
}
