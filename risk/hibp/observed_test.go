package hibp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	audit "github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
)

// The sink boundary deliberately controls acknowledgement and failure. These
// fixtures prove submission and policy handling, not durable database storage.
type observationSink struct {
	mu       sync.Mutex
	records  []audit.Record
	fail     error
	invalid  bool
	onAppend func()
}

func (s *observationSink) Append(ctx context.Context, r audit.Record) (audit.AppendResult, error) {
	b, e := s.AppendBatch(ctx, []audit.Record{r})
	if e != nil {
		return audit.AppendResult{}, e
	}
	return b.Results[0], nil
}
func (s *observationSink) AppendBatch(ctx context.Context, rs []audit.Record) (audit.BatchResult, error) {
	if s.onAppend != nil {
		s.onAppend()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := ctx.Deadline(); !ok {
		return audit.BatchResult{}, errors.New("unbounded append")
	}
	s.records = append(s.records, rs...)
	if s.fail != nil {
		return audit.BatchResult{}, s.fail
	}
	result := audit.BatchResult{}
	for _, r := range rs {
		status := audit.AppendAccepted
		if s.invalid {
			status = 0
		}
		result.Results = append(result.Results, audit.AppendResult{RecordID: r.ID(), Status: status})
	}
	return result, nil
}
func (s *observationSink) snapshot() []audit.Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]audit.Record(nil), s.records...)
}

func observedFixture(t *testing.T, c *Client, sink *observationSink) *ObservedChecker {
	t.Helper()
	observed, e := NewObservedChecker(c, ObservationConfig{Delivery: audit.RecorderConfig{Sink: sink, Mode: audit.DeliveryFailClosed}, AuditTimeout: time.Second})
	if e != nil {
		t.Fatal(e)
	}
	return observed
}

func TestObservedCheckerRecordsSelectedPaddingProfile(t *testing.T) {
	for _, padding := range []bool{true, false} {
		t.Run(fmt.Sprintf("padding-%t", padding), func(t *testing.T) {
			borrowed, wall := checkerFixture(t, func(w http.ResponseWriter, req *http.Request) {
				if (req.Header.Get("Add-Padding") == "true") != padding {
					t.Error("transport profile differed from selection")
				}
				fmt.Fprint(w, "00000000000000000000000000000000000:0\n")
			})
			cfg := testConfig()
			cfg.AddPadding = padding
			checker, err := New(cfg, borrowed.http, wall)
			if err != nil {
				t.Fatal(err)
			}
			client := checker.(*Client)
			t.Cleanup(func() { _ = client.Close(context.Background()) })
			sink := &observationSink{}
			observed := observedFixture(t, client, sink)
			result, err := observed.Check(context.Background(), attributedRequest(t, "synthetic-profile-audit"))
			if err != nil || result.Outcome != OutcomeNoMatch {
				t.Fatal("selected profile lost observed checking", err)
			}
			want := "hibp.range.padded.v1"
			if !padding {
				want = "hibp.range.unpadded.v1"
			}
			records := sink.snapshot()
			if len(records) != 1 || records[0].Attributes()["provider.profile"] != want {
				t.Fatal("security record misrepresented privacy profile")
			}
		})
	}
}

func TestObservedUnpaddedProfileSurvivesSecondaryEventsAndCache(t *testing.T) {
	for _, malformed := range []bool{false, true} {
		t.Run(fmt.Sprintf("malformed-%t", malformed), func(t *testing.T) {
			r := attributedRequest(t, "synthetic-unpadded-events")
			derived, err := deriveCandidate(context.Background(), r.Candidate, 1024)
			if err != nil {
				t.Fatal(err)
			}
			defer derived.clear()
			var calls atomic.Int32
			borrowed, wall := checkerFixture(t, func(w http.ResponseWriter, req *http.Request) {
				calls.Add(1)
				if len(req.Header.Values("Add-Padding")) != 0 {
					t.Error("unpadded event reported for padded request")
				}
				fmt.Fprintf(w, "%s:7\n", derived.suffix[:])
				if malformed {
					fmt.Fprint(w, "invalid\n")
				}
			})
			cfg := testConfig()
			cfg.AddPadding = false
			checker, err := New(cfg, borrowed.http, wall)
			if err != nil {
				t.Fatal(err)
			}
			client := checker.(*Client)
			t.Cleanup(func() { _ = client.Close(context.Background()) })
			sink := &observationSink{}
			observed := observedFixture(t, client, sink)
			var priorID string
			for range 2 {
				result, err := observed.Check(context.Background(), r)
				if malformed {
					if !errors.Is(err, ErrMalformedRange) || result.BreachCount != 0 || !result.ProviderValidUntil.IsZero() {
						t.Fatal("malformed evidence became usable", err)
					}
					assertErrorDelivery(t, result, err)
				} else if err != nil || result.Outcome != OutcomeMatch || result.BreachCount != 7 {
					t.Fatal("unpadded match lost evidence", err)
				}
				records := result.Events.Records()
				if len(records) != 2 || records[0].ID() == priorID || records[1].Context().CausationID() != records[0].ID() {
					t.Fatal("secondary causation or caller record identity lost")
				}
				priorID = records[0].ID()
				stored := sink.snapshot()
				stored = stored[len(stored)-2:]
				for i, record := range records {
					if record.Attributes()["provider.profile"] != "hibp.range.unpadded.v1" {
						t.Fatal("secondary/cache event misrepresented privacy profile")
					}
					got, err := audit.CanonicalJSON(record)
					if err != nil {
						t.Fatal(err)
					}
					want, err := audit.CanonicalJSON(stored[i])
					if err != nil || string(got) != string(want) {
						t.Fatal("retained profile records differed from submitted bytes")
					}
				}
			}
			wantCalls := int32(1)
			if malformed {
				wantCalls = 2
			}
			if calls.Load() != wantCalls {
				t.Fatal("profile cache retained failure or lost success")
			}
		})
	}
}

func assertErrorDelivery(t *testing.T, result CheckResult, e error) {
	t.Helper()
	var checkErr *CheckError
	if !errors.As(e, &checkErr) {
		t.Fatal("missing classified observed failure", e)
	}
	want, got := result.Events.Records(), checkErr.Events.Records()
	if len(want) == 0 || len(got) != len(want) || result.Events.Disposition() != checkErr.Events.Disposition() || result.Events.AppendOutcome() != checkErr.Events.AppendOutcome() {
		t.Fatal("observed error discarded submitted delivery metadata")
	}
	for i := range want {
		wantBytes, e := audit.CanonicalJSON(want[i])
		if e != nil {
			t.Fatal(e)
		}
		gotBytes, e := audit.CanonicalJSON(got[i])
		if e != nil || string(gotBytes) != string(wantBytes) {
			t.Fatal("observed error substituted original event bytes")
		}
	}
}
func attributedRequest(t *testing.T, raw string) CheckRequest {
	t.Helper()
	r := requestFor(t, raw)
	tenant, e := identity.NewCommandID()
	if e != nil {
		t.Fatal(e)
	}
	attempt, e := identity.NewPreAuthTransactionID()
	if e != nil {
		t.Fatal(e)
	}
	policy, e := identity.NewCommandID()
	if e != nil {
		t.Fatal(e)
	}
	correlation, e := identity.NewCommandID()
	if e != nil {
		t.Fatal(e)
	}
	r.TenantID = identity.TenantID(tenant)
	r.Attribution = &SecurityAttribution{CommandID: r.ReplayID, CorrelationID: correlation, AttemptID: attempt, PolicyID: string(policy), PolicyVersion: 3, Actor: audit.ActorInput{Kind: audit.ActorAnonymous}}
	return r
}

func TestObservedCheckerPerCallerCacheAttributionAndPrivacy(t *testing.T) {
	var reads atomic.Int32
	r := attributedRequest(t, "synthetic-observed-password")
	candidate, e := deriveCandidate(context.Background(), r.Candidate, 1024)
	if e != nil {
		t.Fatal(e)
	}
	defer candidate.clear()
	c, wall := checkerFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		reads.Add(1)
		fmt.Fprintf(w, "%s:17\n", candidate.suffix[:])
	})
	sink := &observationSink{}
	observed := observedFixture(t, c, sink)
	first, e := observed.Check(context.Background(), r)
	if e != nil || first.Outcome != OutcomeMatch {
		t.Fatal("match lost", e)
	}
	other := attributedRequest(t, "synthetic-observed-password")
	wall.nanos.Add(int64(time.Minute))
	second, e := observed.Check(context.Background(), other)
	if e != nil || second.CheckedAt != first.CheckedAt || reads.Load() != 1 {
		t.Fatal("cached provider age changed", e)
	}
	records := sink.snapshot()
	if len(records) != 4 {
		t.Fatalf("per-caller actions missing: %d", len(records))
	}
	for index, request := range []CheckRequest{r, other} {
		query, match := records[index*2], records[index*2+1]
		if query.Action() != "identity.hibp.query_range" || match.Action() != "identity.hibp.detect_match" || match.Context().CausationID() != query.ID() || query.Context().TenantID() != string(request.TenantID) || query.Subject().ID() != string(request.Attribution.AttemptID) || query.Attributes()["command.id"] != string(request.Attribution.CommandID) || query.Policy().Version != "3" {
			t.Fatal("caller or event causality substituted")
		}
		for _, record := range []audit.Record{query, match} {
			raw, e := audit.CanonicalJSON(record)
			if e != nil {
				t.Fatal(e)
			}
			if _, e := audit.ParseCanonicalJSON(raw, audit.DefaultLimits()); e != nil {
				t.Fatal(e)
			}
			if record.Attributes()["retention.class"] != "protected" || !record.RedactionApplied() || record.Outcome() != audit.OutcomeSucceeded {
				t.Fatal("security profile missing")
			}
			if len(record.Attributes()) != 7 {
				t.Fatal("unexpected provider attributes")
			}
			for _, forbidden := range []string{"synthetic-observed-password", string(candidate.suffix[:]), "breach_count", "api.pwnedpasswords.com"} {
				if strings.Contains(string(raw), forbidden) {
					t.Fatal("security event exposed provider/candidate material")
				}
			}
		}
	}
	if first.Events.Disposition() != audit.DeliveryPersisted || len(first.Events.Records()) != 2 {
		t.Fatal("delivery acknowledgement absent")
	}
	saved := first.Events.Records()
	saved[0] = audit.Record{}
	if first.Events.Records()[0].ID() == "" {
		t.Fatal("event result escaped custody")
	}
}

func TestObservedCheckerFailureAndAuditUnknownRemainUnusable(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		want       error
		provider   string
	}{
		{"malformed", "invalid\n", ErrMalformedRange, "malformed"},
		{"unavailable", "", ErrProviderUnavailable, "unavailable"},
		{"clean", "00000000000000000000000000000000000:0\n", nil, "accepted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := checkerFixture(t, func(w http.ResponseWriter, _ *http.Request) {
				if tc.body == "" {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				fmt.Fprint(w, tc.body)
			})
			sink := &observationSink{}
			observed := observedFixture(t, c, sink)
			result, e := observed.Check(context.Background(), attributedRequest(t, "synthetic-failure"))
			if !errors.Is(e, tc.want) {
				t.Fatal("provider classification changed", e)
			}
			records := result.Events.Records()
			want := 1
			if tc.want != nil {
				want = 2
			}
			if len(records) != want || records[0].Attributes()["provider.result"] != tc.provider {
				t.Fatal("wrong provider event")
			}
			if tc.want != nil && (records[0].Outcome() != audit.OutcomeFailed || records[1].Action() != "identity.hibp.reject_range") {
				t.Fatal("failure became clean or unknown")
			}
			if tc.want != nil {
				assertErrorDelivery(t, result, e)
			}
			sink.fail = errors.New("SECRET provider diagnostics")
			result, e = observed.Check(context.Background(), attributedRequest(t, "synthetic-failure"))
			if !errors.Is(e, ErrAuditUnavailable) || result.Outcome == OutcomeNoMatch || result.BreachCount != 0 || !result.ProviderValidUntil.IsZero() || result.Events.AppendOutcome() != audit.AppendUnknown || strings.Contains(fmt.Sprint(e), "SECRET") {
				t.Fatal("unknown audit became usable or leaked", e)
			}
			if tc.want != nil && !errors.Is(e, tc.want) {
				t.Fatal("audit failure erased provider denial", e)
			}
			assertErrorDelivery(t, result, e)
		})
	}
}

func TestObservedCheckerCancellationAndInvalidAttribution(t *testing.T) {
	var reads atomic.Int32
	c, _ := checkerFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		reads.Add(1)
		fmt.Fprint(w, "00000000000000000000000000000000000:0\n")
	})
	sink := &observationSink{}
	observed := observedFixture(t, c, sink)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, e := observed.Check(ctx, attributedRequest(t, "synthetic-cancelled"))
	if !errors.Is(e, context.Canceled) || reads.Load() != 0 || len(result.Events.Records()) != 2 || result.Events.Records()[0].ReasonCode() != "cancelled" {
		t.Fatal("cancelled caller lacks bounded terminal emission", e)
	}
	assertErrorDelivery(t, result, e)
	request := attributedRequest(t, "synthetic-invalid")
	request.Attribution.AttemptID = identity.PreAuthTransactionID("email@example.test")
	_, e = observed.Check(context.Background(), request)
	if !errors.Is(e, ErrInvalidRequest) || reads.Load() != 0 || len(sink.snapshot()) != 2 {
		t.Fatal("invalid attribution reached provider or persistence", e)
	}
}

func TestObservedSignalProviderPreservesProviderFailureOnClockFailure(t *testing.T) {
	c, wall := checkerFixture(t, func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "invalid\n") })
	sink := &observationSink{onAppend: func() { wall.nanos.Add(-1) }}
	p, e := NewObservedSignalProvider(observedFixture(t, c, sink), adapterPolicy(t, time.Hour))
	if e != nil {
		t.Fatal(e)
	}
	r := attributedRequest(t, "synthetic-provider-clock-failure")
	r.OperationID = "identity.password.signup"
	r.Action = risk.Action(r.OperationID)
	_, e = p.Assess(context.Background(), r)
	var checkErr *CheckError
	if !errors.Is(e, ErrMalformedRange) || !errors.Is(e, ErrProviderUnavailable) || !errors.As(e, &checkErr) || len(checkErr.Events.Records()) != 2 {
		t.Fatal("normalization discarded original provider failure", e)
	}
}

func launchObserved(o *ObservedChecker, ctx context.Context, r CheckRequest) <-chan checkReply {
	done := make(chan checkReply, 1)
	go func() { result, e := o.Check(ctx, r); done <- checkReply{result, e} }()
	return done
}

func TestObservedCheckerCoalescedWaiterCancellationIsIndependent(t *testing.T) {
	a := attributedRequest(t, "hibp-synthetic-748")
	b := attributedRequest(t, "hibp-synthetic-1195")
	da, e := deriveCandidate(context.Background(), a.Candidate, 1024)
	if e != nil {
		t.Fatal(e)
	}
	defer da.clear()
	arrived, release := make(chan struct{}), make(chan struct{})
	var reads atomic.Int32
	c, _ := checkerFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if reads.Add(1) == 1 {
			close(arrived)
		}
		select {
		case <-release:
			fmt.Fprintf(w, "%s:19\n", da.suffix[:])
		case <-r.Context().Done():
		}
	})
	// Always release before fixture teardown, including failed assertions.
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	sink := &observationSink{}
	o := observedFixture(t, c, sink)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cancelled := launchObserved(o, ctx, a)
	receive(t, arrived)
	surviving := launchObserved(o, context.Background(), b)
	awaitEnrollment(t, c, 2)
	cancel()
	first := receive(t, cancelled)
	if !errors.Is(first.err, context.Canceled) || len(first.result.Events.Records()) != 2 || first.result.Events.Records()[1].Action() != "identity.hibp.reject_range" {
		t.Fatal("cancelled waiter emission missing", first.err)
	}
	releaseOnce.Do(func() { close(release) })
	second := receive(t, surviving)
	if second.err != nil || second.result.Outcome != OutcomeNoMatch || len(second.result.Events.Records()) != 1 || reads.Load() != 1 {
		t.Fatal("cancellation/match crossed waiters", second.err)
	}
	recovered, e := o.Check(context.Background(), a)
	if e != nil || recovered.Outcome != OutcomeMatch || len(recovered.Events.Records()) != 2 || reads.Load() != 1 {
		t.Fatal("cached match lost its own events", e)
	}
	for _, r := range second.result.Events.Records() {
		if r.Subject().ID() != string(b.Attribution.AttemptID) || r.Context().TenantID() != string(b.TenantID) {
			t.Fatal("survivor received cancelled caller identity")
		}
	}
}

func TestObservedSignalProviderEmitsOnlyCheckerEvents(t *testing.T) {
	c, _ := checkerFixture(t, func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "00000000000000000000000000000000000:0\n") })
	sink := &observationSink{}
	o := observedFixture(t, c, sink)
	p, e := NewObservedSignalProvider(o, adapterPolicy(t, time.Hour))
	if e != nil {
		t.Fatal(e)
	}
	r := attributedRequest(t, "synthetic-normalized")
	r.OperationID = "identity.password.signup"
	r.Action = risk.Action(r.OperationID)
	signal, e := p.Assess(context.Background(), r)
	if e != nil || signal.State != risk.SignalClean || len(sink.snapshot()) != 1 {
		t.Fatal("normalization duplicated or changed evidence", e)
	}
	sink.fail = audit.NewAppendError(audit.AppendRejected, errors.New("SECRET"))
	signal, e = p.Assess(context.Background(), r)
	if e == nil || signal.State != risk.SignalUnavailable {
		t.Fatal("audit failure became clean signal", e)
	}
	var failure *CheckError
	if !errors.As(e, &failure) || !errors.Is(e, ErrAuditUnavailable) || len(failure.Events.Records()) != 1 {
		t.Fatal("normalization lost audit reconciliation identity", e)
	}
}

func TestObservedCheckerAcknowledgementsRemainSeparate(t *testing.T) {
	for _, tc := range []struct {
		name    string
		failure error
		invalid bool
		want    audit.AppendOutcome
	}{
		{"rejected", audit.NewAppendError(audit.AppendRejected, errors.New("SECRET")), false, audit.AppendRejected},
		{"committed_error", audit.NewAppendError(audit.AppendCommitted, errors.New("SECRET")), false, audit.AppendCommitted},
		{"malformed_ack", nil, true, audit.AppendUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := checkerFixture(t, func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "00000000000000000000000000000000000:0\n") })
			sink := &observationSink{fail: tc.failure, invalid: tc.invalid}
			o := observedFixture(t, c, sink)
			result, e := o.Check(context.Background(), attributedRequest(t, "synthetic-ack"))
			if !errors.Is(e, ErrAuditUnavailable) || result.Outcome != OutcomeUnavailable || result.Events.AppendOutcome() != tc.want || len(result.Events.Records()) != 1 || result.Events.Records()[0].ID() != sink.snapshot()[0].ID() {
				t.Fatal("audit acknowledgement fabricated or rebuilt", e)
			}
			assertErrorDelivery(t, result, e)
		})
	}
}

func TestObservedCheckerRetainsCancellationDuringTerminalAudit(t *testing.T) {
	c, _ := checkerFixture(t, func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "00000000000000000000000000000000000:0\n") })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sink := &observationSink{onAppend: cancel}
	o := observedFixture(t, c, sink)
	result, e := o.Check(ctx, attributedRequest(t, "synthetic-terminal-cancel"))
	if !errors.Is(e, context.Canceled) || result.Outcome != OutcomeCancelled || result.Events.Disposition() != audit.DeliveryPersisted {
		t.Fatal("terminal audit swallowed caller cancellation", e)
	}
	assertErrorDelivery(t, result, e)
}

func TestObservedSignalProviderRetainsTerminalDeliveryOnFailure(t *testing.T) {
	for _, mode := range []string{"cancel", "cancel_unknown", "clock_unknown"} {
		t.Run(mode, func(t *testing.T) {
			c, wall := checkerFixture(t, func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "00000000000000000000000000000000000:0\n") })
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			sink := &observationSink{onAppend: cancel}
			wantCause := error(context.Canceled)
			wantOutcome := audit.AppendCommitted
			if mode != "cancel" {
				sink.fail = audit.NewAppendError(audit.AppendUnknown, errors.New("SECRET"))
				wantOutcome = audit.AppendUnknown
			}
			if mode == "clock_unknown" {
				sink.onAppend = func() { wall.nanos.Add(-1) }
				wantCause = ErrProviderUnavailable
			}
			p, e := NewObservedSignalProvider(observedFixture(t, c, sink), adapterPolicy(t, time.Hour))
			if e != nil {
				t.Fatal(e)
			}
			r := attributedRequest(t, "synthetic-normalized-terminal")
			r.OperationID = "identity.password.signup"
			r.Action = risk.Action(r.OperationID)
			_, e = p.Assess(ctx, r)
			var checkErr *CheckError
			if !errors.Is(e, wantCause) || !errors.As(e, &checkErr) {
				t.Fatal("terminal failure classification lost", e)
			}
			if mode != "cancel" && !errors.Is(e, ErrAuditUnavailable) {
				t.Fatal("unknown delivery classification lost", e)
			}
			records := checkErr.Events.Records()
			submitted := sink.snapshot()
			if len(records) != 1 || len(submitted) != 1 || records[0].ID() != submitted[0].ID() || checkErr.Events.AppendOutcome() != wantOutcome {
				t.Fatal("normalization discarded terminal reconciliation identity")
			}
		})
	}
}

type blockedObservationSink struct {
	observationSink
	entered chan struct{}
	release chan struct{}
	blocked atomic.Bool
}

func (s *blockedObservationSink) AppendBatch(ctx context.Context, records []audit.Record) (audit.BatchResult, error) {
	if s.blocked.Load() {
		select {
		case s.entered <- struct{}{}:
		default:
		}
		select {
		case <-s.release:
		case <-ctx.Done():
			return audit.BatchResult{}, ctx.Err()
		}
	}
	return s.observationSink.AppendBatch(ctx, records)
}

func TestObservedCheckerAdmissionIncludesTerminalDelivery(t *testing.T) {
	c, _ := checkerFixture(t, func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "00000000000000000000000000000000000:0\n") })
	c.config.MaxWaiters = 1 // Configure before sharing to exercise exact capacity.
	sink := &blockedObservationSink{entered: make(chan struct{}, 2), release: make(chan struct{})}
	o, e := NewObservedChecker(c, ObservationConfig{Delivery: audit.RecorderConfig{Sink: sink, Mode: audit.DeliveryFailClosed}, AuditTimeout: time.Second})
	if e != nil {
		t.Fatal(e)
	}
	r := attributedRequest(t, "synthetic-bounded-audit")
	if _, e := o.Check(context.Background(), r); e != nil {
		t.Fatal(e)
	} // Warm the provider cache.
	sink.blocked.Store(true)
	done := make(chan error, c.config.MaxWaiters)
	started := 0
	defer func() {
		close(sink.release)
		for range started {
			if e := <-done; e != nil {
				t.Error(e)
			}
		}
	}()
	for range c.config.MaxWaiters {
		started++
		go func() { _, e := o.Check(context.Background(), r); done <- e }()
		select {
		case <-sink.entered:
		case <-time.After(2 * time.Second):
			t.Fatal("admitted call did not reach sink")
		}
	}
	for _, cancelled := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		if cancelled {
			cancel()
		}
		result, e := o.Check(ctx, r)
		cancel()
		if !errors.Is(e, ErrOverloaded) || len(result.Events.Records()) != 0 {
			t.Fatal("terminal callbacks escaped bounded observed admission", e)
		}
	}
}

func TestObservedCheckerAlertedLossPreservesAuthoritativeOutcome(t *testing.T) {
	for _, want := range []audit.AppendOutcome{audit.AppendRejected, audit.AppendUnknown} {
		t.Run(fmt.Sprint(want), func(t *testing.T) {
			c, _ := checkerFixture(t, func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "00000000000000000000000000000000000:0\n") })
			sink := &observationSink{fail: audit.NewAppendError(want, errors.New("SECRET"))}
			alerted := audit.AppendOutcome(0)
			alerter := audit.AlertFunc(func(ctx context.Context, a audit.DeliveryAlert) error {
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("unbounded alert")
				}
				alerted = a.Outcome
				return nil
			})
			o, e := NewObservedChecker(c, ObservationConfig{Delivery: audit.RecorderConfig{Sink: sink, Mode: audit.DeliveryFailOpenWithAlert, Alerter: alerter, RecoveryTimeout: time.Second}, AuditTimeout: time.Second})
			if e != nil {
				t.Fatal(e)
			}
			result, e := o.Check(context.Background(), attributedRequest(t, "synthetic-alerted-loss"))
			if !errors.Is(e, ErrAuditUnavailable) || result.Outcome != OutcomeUnavailable || result.Events.Disposition() != audit.DeliveryProceededAfterAlert || alerted != want || result.Events.AppendOutcome() != want {
				t.Fatal("alerted loss erased authoritative append classification", e)
			}
			assertErrorDelivery(t, result, e)
		})
	}
}
