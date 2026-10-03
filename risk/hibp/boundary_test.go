package hibp

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	audit "github.com/faustbrian/go-audit"
)

func TestPublicConstructionAndZeroValuesRejectMissingDependencies(t *testing.T) {
	client, wall := checkerFixture(t, func(http.ResponseWriter, *http.Request) { t.Error("invalid construction performed provider work") })
	for _, build := range []func() error{
		func() error { _, err := New(Config{}, client.http, wall); return err },
		func() error { _, err := New(testConfig(), nil, wall); return err },
		func() error { _, err := New(testConfig(), client.http, nil); return err },
		func() error { _, err := NewObservedChecker(nil, ObservationConfig{}); return err },
		func() error {
			_, err := NewObservedChecker(client, ObservationConfig{AuditTimeout: time.Second})
			return err
		},
		func() error { _, err := NewObservedSignalProvider(nil, adapterPolicy(t, time.Hour)); return err },
	} {
		if !errors.Is(build(), ErrInvalidConfiguration) {
			t.Fatal("missing dependency became usable construction")
		}
	}
	request := requestFor(t, "synthetic-zero-candidate")
	for _, checker := range []Checker{(*Client)(nil), &Client{}, (*ObservedChecker)(nil), &ObservedChecker{}} {
		result, err := checker.Check(context.Background(), request)
		if !errors.Is(err, ErrInvalidConfiguration) || result.BreachCount != 0 || !result.ProviderValidUntil.IsZero() {
			t.Fatal("invalid zero checker produced evidence", err)
		}
	}
	if !errors.Is((*Client)(nil).Close(context.Background()), ErrInvalidConfiguration) || !errors.Is(client.Close(nil), ErrInvalidRequest) {
		t.Fatal("invalid shutdown inputs accepted")
	}
	observed := observedFixture(t, client, &observationSink{})
	if _, err := observed.Check(nil, request); !errors.Is(err, ErrInvalidRequest) {
		t.Fatal("nil observed context accepted", err)
	}
	if _, err := observed.Check(context.Background(), request); !errors.Is(err, ErrInvalidRequest) {
		t.Fatal("missing trusted attribution accepted", err)
	}
}

func TestObservedExpiredCallerAndDestroyedCandidateHaveClosedSecurityReasons(t *testing.T) {
	for _, expired := range []bool{true, false} {
		t.Run(map[bool]string{true: "expired", false: "destroyed"}[expired], func(t *testing.T) {
			var reads atomic.Int32
			client, _ := checkerFixture(t, func(http.ResponseWriter, *http.Request) { reads.Add(1) })
			sink := &observationSink{}
			observed := observedFixture(t, client, sink)
			request := attributedRequest(t, "synthetic-precheck-failure")
			ctx := context.Background()
			wantErr, wantReason, wantResult := error(ErrInvalidRequest), "invalid_input", "binding_mismatch"
			wantOutcome := audit.OutcomeDenied
			if expired {
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer cancel()
				wantErr, wantReason, wantResult, wantOutcome = context.DeadlineExceeded, "timeout", "timeout", audit.OutcomeFailed
			} else {
				request.Candidate.Destroy()
			}
			result, err := observed.Check(ctx, request)
			if !errors.Is(err, wantErr) || reads.Load() != 0 || result.BreachCount != 0 || !result.ProviderValidUntil.IsZero() {
				t.Fatal("precheck failure performed provider work or produced evidence", err)
			}
			records := result.Events.Records()
			if len(records) != 2 || records[0].ReasonCode() != wantReason || records[0].Outcome() != wantOutcome || records[0].Attributes()["provider.result"] != wantResult || records[1].Action() != "identity.hibp.reject_range" {
				t.Fatal("precheck failure lost closed security classification")
			}
			assertErrorDelivery(t, result, err)
			assertSameRecordBytes(t, records, sink.snapshot())
		})
	}
}
