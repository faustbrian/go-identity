package reference

import (
	"context"
	"errors"
	"testing"
	"time"

	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	"github.com/faustbrian/go-identity/otp"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
)

// NATIVE-06 isolates the shared graph lifetime, not persistence or provider IO.
// The joint public workflow test separately supplies the real native owners.
func TestFeatureAdmissionIsBoundedCanceledAndDrained(t *testing.T) {
	lifetime, cancel := context.WithCancel(context.Background())
	defer cancel()
	drained := make(chan struct{})
	close(drained)
	s := &storeState{lifetime: lifetime, cancel: cancel, drained: drained, features: &featureState{composed: true, timeout: time.Second}}
	features := FeatureSet{state: s}
	if _, err := features.OTP(); err == nil {
		t.Fatal("unselected OTP exported a handle")
	}
	s.features.otp = &otppg.SendService{}
	service, err := features.OTP()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Send(context.Background(), otp.SendRequest{}); err == nil {
		t.Fatal("pre-start handle admitted work")
	}
	if s.active != 0 {
		t.Fatal("denied admission retained an active slot")
	}
	s.features.ready = true
	bounded, done, err := s.enterFeature(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	deadline, ok := bounded.Deadline()
	if !ok || time.Until(deadline) > time.Second || s.active != 1 {
		done()
		t.Fatal("missing bounded admission")
	}
	select {
	case <-s.drained:
		done()
		t.Fatal("active operation reported drained")
	default:
	}
	cancel()
	select {
	case <-bounded.Done():
	case <-time.After(time.Second):
		done()
		t.Fatal("graph lifetime did not cancel operation")
	}
	if !errors.Is(bounded.Err(), context.Canceled) {
		done()
		t.Fatal("lost graph cancellation")
	}
	done()
	if s.active != 0 {
		t.Fatal("finished operation retained active slot")
	}
	select {
	case <-s.drained:
	default:
		t.Fatal("finished operation did not publish drain")
	}
	s.closed = true
	if _, _, err := s.enterFeature(context.Background(), true); err == nil {
		t.Fatal("closed graph admitted new operation")
	}
	if _, err := features.OTP(); err == nil {
		t.Fatal("closed graph exported new feature handle")
	}
}

// One capacity owner must dominate native worker entry, before any claim. Two
// worker handles share it; an exhausted sender budget cannot touch either owner.
func TestDeliveryWorkersShareSenderCapacityBeforeClaim(t *testing.T) {
	lifetime, cancel := context.WithCancel(context.Background())
	defer cancel()
	drained := make(chan struct{})
	close(drained)
	slots := make(chan struct{}, 1)
	slots <- struct{}{}
	s := &storeState{lifetime: lifetime, cancel: cancel, drained: drained, features: &featureState{composed: true, ready: true, timeout: time.Second, deliverySlots: slots}}
	workers := WorkerSet{state: s, delivery: []*deliverypg.Worker{{}, {}}}
	for _, index := range []int{0, 1} {
		ctx, stop := context.WithTimeout(context.Background(), 10*time.Millisecond)
		_, err := workers.ProcessDeliveryOne(ctx, index)
		stop()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("exhausted shared capacity reached a native worker instead of waiting")
		}
	}
	if s.active != 0 || len(slots) != 1 {
		t.Fatal("waiting caller leaked lifetime admission or stole sender capacity")
	}
}

func TestFeatureAdmissionRejectsCanceledAndIncompleteOwners(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, s := range []*storeState{nil, {}, {features: &featureState{}}} {
		if _, _, err := s.enterFeature(context.Background(), true); err == nil {
			t.Fatal("incomplete owner admitted operation")
		}
		if _, _, err := s.enterFeature(nil, false); err == nil {
			t.Fatal("nil context admitted operation")
		}
	}
	s := &storeState{features: &featureState{composed: true, ready: true, timeout: time.Second}}
	if _, _, err := s.enterFeature(canceled, true); !errors.Is(err, context.Canceled) {
		t.Fatal("lost already-canceled caller")
	}
	if s.active != 0 {
		t.Fatal("canceled caller retained a slot")
	}
}
