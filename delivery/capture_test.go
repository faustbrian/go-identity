package delivery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func captureConfig() CaptureConfig {
	return CaptureConfig{TenantID: "tenant", MaxAttempts: 64, MaxBytes: 1 << 20}
}

// Deliberate public queue boundary double: a pre-recorded claim and attributable
// completion observation, not PostgreSQL, lease/CAS or authorization evidence.
type captureClaimQueue struct {
	serviceQueue
	completed CompleteRequest
}

func (*captureClaimQueue) Claim(context.Context, ClaimRequest) (ClaimResult, error) {
	return ClaimResult{Claimed: true, Attempt: testAttempt(), LeaseUntil: time.Now().UTC().Add(time.Minute)}, nil
}
func (q *captureClaimQueue) Complete(ctx context.Context, r CompleteRequest) (CompleteResult, error) {
	if _, ok := ctx.Deadline(); !ok || r.Validate() != nil {
		return CompleteResult{}, ErrInvalidInput
	}
	q.completed = r
	return CompleteResult{State: r.Result.State, Commit: CommitCommitted}, nil
}

func TestCaptureServiceUsesPublicQueueAndSender(t *testing.T) {
	capture, err := NewCaptureSender(captureConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer capture.Close()
	renderer, err := NewTemplateRenderer([]Template{plainTemplate()})
	if err != nil {
		t.Fatal(err)
	}
	queue := &captureClaimQueue{serviceQueue: serviceQueue{backend: QueueBackendCapture}}
	var publicQueue Queue = queue
	var publicSender Sender = capture
	s, err := New(DefaultConfig(), publicQueue, renderer, publicSender)
	if err != nil {
		t.Fatal(err)
	}
	result, err := s.ProcessOne(context.Background(), ClaimRequest{TenantID: "tenant", WorkerID: "capture-worker"})
	if err != nil || !result.Claimed || result.Completion.State != StateAccepted || result.Completion.Commit != CommitCommitted {
		t.Fatal("public capture path fabricated delivery or lost admission")
	}
	items, err := capture.Snapshot(context.Background())
	if err != nil || len(items) != 1 || items[0].Body != "synthetic-content" {
		t.Fatal("public worker did not capture exactly one rendered attempt")
	}
	if !queue.completed.Invoked || queue.completed.TenantID != "tenant" || queue.completed.WorkerID != "capture-worker" || queue.completed.Generation != 1 || queue.completed.Result.State != StateAccepted {
		t.Fatal("capture lost public queue completion binding")
	}
}

func TestCaptureUsesSenderContractAndCannotEnterProduction(t *testing.T) {
	capture, err := NewCaptureSender(captureConfig())
	if err != nil {
		t.Fatal(err)
	}
	var sender Sender = capture
	executor, err := newSenderExecutor(DefaultConfig(), sender)
	if err != nil {
		t.Fatal(err)
	}
	result, err := executor.send(context.Background(), testAttempt())
	if err != nil || result.State != StateAccepted {
		t.Fatal("capture failed or claimed real delivery")
	}
	items, err := capture.Snapshot(context.Background())
	if err != nil || len(items) != 1 || items[0].Body != "synthetic-content" || items[0].IntentID != "synthetic-intent-0001" {
		t.Fatal("capture lost rendered attempt")
	}
	items[0].Body = "caller-mutation"
	again, err := capture.Snapshot(context.Background())
	if err != nil || again[0].Body != "synthetic-content" {
		t.Fatal("snapshot aliases capture ownership")
	}
	c := DefaultConfig()
	c.Production = true
	if _, err := newSenderExecutor(c, sender); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("capture accepted by production executor")
	}
	renderer, _ := NewTemplateRenderer([]Template{plainTemplate()})
	if _, err := New(c, &serviceQueue{backend: QueueBackendPostgreSQL}, renderer, sender); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("capture accepted by production service")
	}
	if strings.Contains(fmt.Sprintf("%#v", capture), "synthetic-content") {
		t.Fatal("capture diagnostics leaked")
	}
	if _, err := json.Marshal(capture); !errors.Is(err, ErrSerializationForbidden) {
		t.Fatal("capture implicitly serialized")
	}
}

func TestCaptureBoundsScopeCancellationAndCleanup(t *testing.T) {
	config := captureConfig()
	config.MaxAttempts = 1
	capture, err := NewCaptureSender(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := capture.Send(ctx, testAttempt()); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled capture admitted")
	}
	if _, err := capture.Send(nil, testAttempt()); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("nil context admitted")
	}
	wrong := testAttempt()
	wrong.TenantID = "other-tenant"
	if _, err := capture.Send(context.Background(), wrong); !errors.Is(err, ErrForbidden) {
		t.Fatal("cross-scope capture admitted")
	}
	if _, err := capture.Send(context.Background(), testAttempt()); err != nil {
		t.Fatal(err)
	}
	if _, err := capture.Send(context.Background(), testAttempt()); !errors.Is(err, ErrUnavailable) {
		t.Fatal("capture exceeded attempt limit")
	}
	backing := capture.attempts
	if err := capture.Close(); err != nil {
		t.Fatal(err)
	}
	if capture.bytes != 0 || capture.attempts != nil || backing[0] != (Attempt{}) {
		t.Fatal("close retained owned payload references")
	}
	if err := capture.Close(); err != nil {
		t.Fatal("close is not idempotent")
	}
	if _, err := capture.Snapshot(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatal("closed capture exposed retained payload")
	}
	if _, err := capture.Send(context.Background(), testAttempt()); !errors.Is(err, ErrUnavailable) {
		t.Fatal("closed capture admitted new payload")
	}
	var zero CaptureSender
	if _, err := zero.Send(context.Background(), testAttempt()); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("zero sender usable")
	}
	var missing *CaptureSender
	if _, err := missing.Snapshot(context.Background()); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("nil capture usable")
	}
	if err := zero.Close(); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("zero capture close admitted")
	}
}

func TestCaptureByteLimitAndInvalidConfiguration(t *testing.T) {
	for _, config := range []CaptureConfig{{}, {TenantID: "tenant", MaxAttempts: 1}, {TenantID: "tenant", MaxAttempts: 1025, MaxBytes: 1000}, {TenantID: "tenant", MaxAttempts: 1, MaxBytes: 4<<20 + 1}} {
		if _, err := NewCaptureSender(config); !errors.Is(err, ErrInvalidInput) {
			t.Fatal("invalid capture bounds")
		}
	}
	config := captureConfig()
	config.MaxBytes = 1
	capture, err := NewCaptureSender(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := capture.Send(context.Background(), testAttempt()); !errors.Is(err, ErrUnavailable) {
		t.Fatal("byte limit exceeded")
	}
	items, err := capture.Snapshot(context.Background())
	if err != nil || len(items) != 0 {
		t.Fatal("overflow partly retained payload")
	}
	if err := capture.Close(); err != nil {
		t.Fatal(err)
	}
	a := testAttempt()
	config = captureConfig()
	config.MaxBytes = uint32(len(a.TenantID) + len(a.IntentID) + len(a.Recipient) + len(a.Subject) + len(a.Body) + len(a.ContentType) + len(a.IdempotencyKey))
	capture, err = NewCaptureSender(config)
	if err != nil {
		t.Fatal(err)
	}
	defer capture.Close()
	expired := a
	expired.ValidUntil = time.Unix(1, 0).UTC()
	if _, err := capture.Send(context.Background(), expired); !errors.Is(err, ErrExpired) {
		t.Fatal("expired test effect captured")
	}
	if _, err := capture.Send(context.Background(), a); err != nil {
		t.Fatal("exact byte boundary rejected")
	}
	if _, err := capture.Send(context.Background(), a); !errors.Is(err, ErrUnavailable) {
		t.Fatal("aggregate byte budget reset")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := capture.Snapshot(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled snapshot revealed content")
	}
	if _, err := capture.Snapshot(nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("nil snapshot context admitted")
	}
}

func TestCaptureConcurrentCallsAndOwnedSnapshots(t *testing.T) {
	capture, err := NewCaptureSender(captureConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer capture.Close()
	var joined sync.WaitGroup
	for range 64 {
		joined.Add(1)
		go func() {
			defer joined.Done()
			if _, err := capture.Send(context.Background(), testAttempt()); err != nil {
				t.Error("concurrent capture failed")
			}
			snapshot, err := capture.Snapshot(context.Background())
			if err != nil {
				t.Error(err)
			}
			for i := range snapshot {
				snapshot[i].Body = "snapshot-local-mutation"
			}
		}()
	}
	joined.Wait()
	snapshot, err := capture.Snapshot(context.Background())
	if err != nil || len(snapshot) != 64 {
		t.Fatal("capture lost concurrent attempts")
	}
	for _, attempt := range snapshot {
		if attempt.Body != "synthetic-content" {
			t.Fatal("snapshot mutation reached capture")
		}
	}
}
