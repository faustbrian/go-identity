package delivery

import (
	"context"
	"errors"
	"testing"
)

// QA3/QA5: the public worker must use the same bounded handshake as Service,
// without forcing an adapter to implement unrelated admission methods.
func TestPublicWorkerUsesDurableSubsetAndRejectsCapture(t *testing.T) {
	config := DefaultConfig()
	config.Production = true
	queue := &serviceQueue{backend: QueueBackendPostgreSQL}
	worker, err := NewWorker(config, queue, senderFunc(func(context.Context, Attempt) (DeliveryResult, error) {
		t.Fatal("empty durable queue invoked Sender")
		return DeliveryResult{}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if out, err := worker.ProcessOne(context.Background(), ClaimRequest{TenantID: "tenant", WorkerID: "worker"}); err != nil || out.Claimed {
		t.Fatal("public worker did not preserve empty-claim result", err)
	}
	queue.backend = QueueBackendCapture
	if _, err := NewWorker(config, queue, senderFunc(nil)); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("production worker admitted capture queue", err)
	}
	queue.backend = QueueBackendPostgreSQL
	if _, err := NewWorker(config, queue, nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("production worker admitted missing Sender", err)
	}
	var missing *serviceQueue
	if _, err := NewWorker(config, missing, senderFunc(nil)); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("typed-nil durable queue admitted", err)
	}
}
