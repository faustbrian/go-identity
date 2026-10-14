package postgres_test

import (
	"context"
	"errors"
	"testing"

	"github.com/faustbrian/go-identity/delivery"
	postgres "github.com/faustbrian/go-identity/delivery/postgres"
)

// Consumers need no private lease fence or replacement worker adapter.
func TestPublicWorkerLeaseInvalidOwners(t *testing.T) {
	for _, worker := range []*postgres.Worker{nil, {}} {
		if until, err := worker.RenewLease(context.Background(), "synthetic-intent-0001", 1); !errors.Is(err, delivery.ErrInvalidInput) || !until.IsZero() {
			t.Fatal("invalid worker heartbeat produced ownership", err)
		}
		if result, err := worker.ReleaseLease(context.Background(), "synthetic-intent-0001", 1); !errors.Is(err, delivery.ErrInvalidInput) || result != (delivery.CompleteResult{}) {
			t.Fatal("invalid worker release produced outcome", err)
		}
	}
	for _, queue := range []*postgres.Queue{nil, {}} {
		if until, err := queue.RenewLease(context.Background(), "synthetic-intent-0001", 1); !errors.Is(err, delivery.ErrInvalidInput) || !until.IsZero() {
			t.Fatal("invalid queue heartbeat produced ownership", err)
		}
		if result, err := queue.ReleaseLease(context.Background(), "synthetic-intent-0001", 1); !errors.Is(err, delivery.ErrInvalidInput) || result != (delivery.CompleteResult{}) {
			t.Fatal("invalid queue release produced outcome", err)
		}
	}
}
