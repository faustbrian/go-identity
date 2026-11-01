package hibp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	audit "github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-identity/risk"
)

type boundaryClock func() time.Time

func (c boundaryClock) Now() time.Time { return c() }

func TestCheckerRevalidatesClockAndShutdownAfterCandidateBorrow(t *testing.T) {
	for _, shutdown := range []bool{false, true} {
		t.Run(map[bool]string{false: "regression", true: "shutdown"}[shutdown], func(t *testing.T) {
			var reads atomic.Int32
			borrowed, original := checkerFixture(t, func(w http.ResponseWriter, _ *http.Request) {
				reads.Add(1)
				fmt.Fprint(w, "00000000000000000000000000000000000:0\n")
			})
			base := original.Now()
			var observations atomic.Int32
			var client *Client
			wall := boundaryClock(func() time.Time {
				if observations.Add(1) == 2 {
					if shutdown {
						if err := client.Close(context.Background()); err != nil {
							t.Error("clock callback could not close an idle checker", err)
						}
					} else {
						return base.Add(-time.Nanosecond)
					}
				}
				return base
			})
			checker, err := New(testConfig(), borrowed.http, wall)
			if err != nil {
				t.Fatal(err)
			}
			client = checker.(*Client)
			t.Cleanup(func() { _ = client.Close(context.Background()) })
			request := requestFor(t, "synthetic-borrow-boundary")
			result, err := client.Check(context.Background(), request)
			want := ErrProviderUnavailable
			if shutdown {
				want = ErrClosed
			}
			if !errors.Is(err, want) || result.Outcome != OutcomeUnavailable || result.BreachCount != 0 || !result.ProviderValidUntil.IsZero() || reads.Load() != 0 {
				t.Fatal("post-borrow invalidation reached provider work or usable evidence", err)
			}
			if err := request.Candidate.Use(func(raw []byte) error {
				if string(raw) != "synthetic-borrow-boundary" {
					t.Fatal("post-borrow invalidation changed caller-owned candidate")
				}
				return nil
			}); err != nil {
				t.Fatal("post-borrow invalidation retained candidate custody", err)
			}
			if !shutdown {
				result, err = client.Check(context.Background(), request)
				if err != nil || result.Outcome != OutcomeNoMatch || reads.Load() != 1 {
					t.Fatal("clock recovery did not release admission for a new provider observation", err)
				}
			}
		})
	}
}

func TestCheckerCancellationAtCacheBoundaryCannotReturnReusableEvidence(t *testing.T) {
	var reads atomic.Int32
	borrowed, original := checkerFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		reads.Add(1)
		fmt.Fprint(w, "00000000000000000000000000000000000:0\n")
	})
	base := original.Now()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var armed atomic.Bool
	var observations atomic.Int32
	wall := boundaryClock(func() time.Time {
		if armed.Load() && observations.Add(1) == 2 {
			cancel()
		}
		return base
	})
	checker, err := New(testConfig(), borrowed.http, wall)
	if err != nil {
		t.Fatal(err)
	}
	client := checker.(*Client)
	t.Cleanup(func() { _ = client.Close(context.Background()) })
	request := requestFor(t, "synthetic-cancelled-cache")
	first, err := client.Check(context.Background(), request)
	if err != nil || first.Outcome != OutcomeNoMatch {
		t.Fatal("could not establish reusable provider observation", err)
	}
	armed.Store(true)
	result, err := client.Check(ctx, request)
	if !errors.Is(err, context.Canceled) || result.Outcome != OutcomeCancelled || result.BreachCount != 0 || !result.ProviderValidUntil.IsZero() {
		t.Fatal("cache hit ignored cancellation during candidate borrowing", err)
	}
	armed.Store(false)
	retry, err := client.Check(context.Background(), request)
	if err != nil || retry.Outcome != OutcomeNoMatch || retry.CheckedAt != first.CheckedAt || retry.ProviderValidUntil != first.ProviderValidUntil || reads.Load() != 1 {
		t.Fatal("one cancelled cache caller changed private provider observation or admission", err)
	}
}

func TestCheckerCancellationDuringFinalObservationCannotReturnCallerEvidence(t *testing.T) {
	var reads atomic.Int32
	borrowed, original := checkerFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		reads.Add(1)
		fmt.Fprint(w, "00000000000000000000000000000000000:0\n")
	})
	base := original.Now()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var observations atomic.Int32
	wall := boundaryClock(func() time.Time {
		if observations.Add(1) == 4 {
			cancel()
		}
		return base
	})
	checker, err := New(testConfig(), borrowed.http, wall)
	if err != nil {
		t.Fatal(err)
	}
	client := checker.(*Client)
	t.Cleanup(func() { _ = client.Close(context.Background()) })
	request := requestFor(t, "synthetic-cancelled-final-observation")
	result, err := client.Check(ctx, request)
	if !errors.Is(err, context.Canceled) || result.Outcome != OutcomeCancelled || result.BreachCount != 0 || !result.ProviderValidUntil.IsZero() {
		t.Fatal("final clock callback cancellation became usable caller evidence", err)
	}
	retry, err := client.Check(context.Background(), request)
	if err != nil || retry.Outcome != OutcomeNoMatch || retry.CheckedAt != base || retry.ProviderValidUntil != base.Add(time.Hour) || reads.Load() != 1 {
		t.Fatal("late caller cancellation changed the completed private provider observation", err)
	}
}

func TestObservedCheckerRecordsSharedClientSaturationWithoutProviderWork(t *testing.T) {
	started := make(chan struct{})
	var reads atomic.Int32
	borrowed, wall := checkerFixture(t, func(_ http.ResponseWriter, request *http.Request) {
		reads.Add(1)
		close(started)
		<-request.Context().Done()
	})
	config := testConfig()
	config.MaxWaiters = 1
	checker, err := New(config, borrowed.http, wall)
	if err != nil {
		t.Fatal(err)
	}
	client := checker.(*Client)
	t.Cleanup(func() { _ = client.Close(context.Background()) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := launch(client, ctx, requestFor(t, "synthetic-client-saturation"))
	receive(t, started)
	sink := &observationSink{}
	observed := observedFixture(t, client, sink)
	result, err := observed.Check(context.Background(), attributedRequest(t, "synthetic-observed-saturation"))
	if !errors.Is(err, ErrOverloaded) || result.Outcome != OutcomeUnavailable || result.BreachCount != 0 || !result.ProviderValidUntil.IsZero() || reads.Load() != 1 {
		t.Fatal("shared client saturation became usable evidence or another request", err)
	}
	records := result.Events.Records()
	if len(records) != 2 || records[0].Outcome() != audit.OutcomeDenied || records[0].ReasonCode() != "rate_limited" || records[0].Attributes()["provider.result"] != "throttled" || records[1].Action() != "identity.hibp.reject_range" || result.Events.Disposition() != audit.DeliveryPersisted {
		t.Fatal("shared saturation lost closed security classification or required delivery")
	}
	assertErrorDelivery(t, result, err)
	assertSameRecordBytes(t, records, sink.snapshot())
	cancel()
	if reply := receive(t, first); !errors.Is(reply.err, context.Canceled) {
		t.Fatal("saturation changed the independently cancelled original caller", reply.err)
	}
}

func TestCheckerRejectsNonCanonicalBindingsBeforeProviderWork(t *testing.T) {
	client, wall := checkerFixture(t, func(http.ResponseWriter, *http.Request) {
		t.Error("invalid configuration or attribution reached provider")
	})
	for _, version := range []string{"contains space", "contains\nnewline", "non-ascii-\u00e9"} {
		config := testConfig()
		config.PolicyVersion = version
		checker, err := New(config, client.http, wall)
		if !errors.Is(err, ErrInvalidConfiguration) || checker != nil {
			t.Fatal("non-ASCII or whitespace configuration became usable", err)
		}
	}
	for _, invalid := range []func(*CheckRequest){
		func(r *CheckRequest) {
			r.OperationID = "Identity.password.register"
			r.Action = risk.Action(r.OperationID)
		},
		func(r *CheckRequest) { r.Purpose = "Create" },
		func(r *CheckRequest) { r.SubjectScope = "subject\r\ninjected" },
	} {
		request := requestFor(t, "synthetic-invalid-binding")
		invalid(&request)
		result, err := client.Check(context.Background(), request)
		if !errors.Is(err, ErrInvalidRequest) || result.Outcome != OutcomeUnavailable || result.BreachCount != 0 || !result.ProviderValidUntil.IsZero() {
			t.Fatal("noncanonical scope became usable provider evidence", err)
		}
	}
}

func TestSignalProviderRejectsInvalidContextClockAndObservedPolicyBeforeIO(t *testing.T) {
	borrowed, _ := checkerFixture(t, func(http.ResponseWriter, *http.Request) {
		t.Error("invalid signal preflight reached provider")
	})
	checker, err := New(testConfig(), borrowed.http, boundaryClock(func() time.Time { return time.Time{} }))
	if err != nil {
		t.Fatal(err)
	}
	client := checker.(*Client)
	t.Cleanup(func() { _ = client.Close(context.Background()) })
	provider, err := NewSignalProvider(client, adapterPolicy(t, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	request := requestFor(t, "synthetic-invalid-preflight")
	request.OperationID = "identity.password.signup"
	request.Action = risk.Action(request.OperationID)
	if signal, err := provider.Assess(nil, request); !errors.Is(err, ErrInvalidRequest) || signal.State != 0 || signal.BreachCount != 0 || !signal.ExpiresAt.IsZero() {
		t.Fatal("nil signal context produced usable evidence", err)
	}
	if signal, err := provider.Assess(context.Background(), request); !errors.Is(err, ErrProviderUnavailable) || signal.State != 0 || signal.BreachCount != 0 || !signal.ExpiresAt.IsZero() {
		t.Fatal("invalid provider clock produced usable neutral evidence", err)
	}
	observed := observedFixture(t, borrowed, &observationSink{})
	if provider, err := NewObservedSignalProvider(observed, risk.Policy{}); !errors.Is(err, ErrInvalidConfiguration) || provider != nil {
		t.Fatal("observed provider accepted disabled screening policy", err)
	}
}
