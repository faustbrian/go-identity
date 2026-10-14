package risk

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-identity"
)

type decisionSink func(context.Context, audit.Record) (audit.AppendResult, error)

func (s decisionSink) Append(c context.Context, r audit.Record) (audit.AppendResult, error) {
	return s(c, r)
}

type decisionBuffer struct{ decisionSink }

func (decisionBuffer) BufferLimits() audit.BufferLimits {
	return audit.BufferLimits{MaxRecords: 16, MaxBytes: 1 << 20, MaxBatchRecords: 16}
}

func TestDecisionAuditBufferedAcknowledgmentAndCounterOutcome(t *testing.T) {
	for _, failure := range []bool{false, true} {
		now := testContext().Now
		mutations, buffered := 0, 0
		cfg := countedConfig(t, &now, counterStoreFunc(func(_ context.Context, c CounterCommand) (CounterResult, error) {
			mutations++
			return NewCounterResult(c, CounterCommitted, snapshotFor(c, c.Bindings().Limit+1))
		}))
		observed := auditedConfig(t, &now, func(context.Context, audit.Record) (audit.AppendResult, error) {
			return audit.AppendResult{}, audit.NewAppendError(audit.AppendRejected, errors.New("unavailable"))
		})
		cfg.DecisionAudit = observed.DecisionAudit
		if !failure {
			cfg.DecisionAudit.Delivery.Mode = audit.DeliveryDurableBuffer
			cfg.DecisionAudit.Delivery.RecoveryTimeout = time.Second
			cfg.DecisionAudit.Delivery.Buffer = decisionBuffer{decisionSink(func(_ context.Context, r audit.Record) (audit.AppendResult, error) {
				buffered++
				now = now.Add(500 * time.Millisecond)
				return audit.AppendResult{RecordID: r.ID(), Status: audit.AppendAccepted}, nil
			})}
		}
		e, err := NewEvaluator(cfg)
		if err != nil {
			t.Fatal(err)
		}
		r := auditRequest(t)
		r.Subject = counterSubject()
		got, err := e.Evaluate(context.Background(), r)
		if got.counter == nil || got.counter.Outcome != CounterCommitted || mutations != 1 || got.Decision.Action != Throttle {
			t.Fatal("counter outcome erased/repeated", err)
		}
		if failure {
			if !errors.Is(err, ErrDecisionAuditUnavailable) || got.provenance != nil {
				t.Fatal("failed delivery admitted", err)
			}
		} else if err != nil || buffered != 1 || got.Audit.Disposition() != audit.DeliveryBuffered || got.Decision.RetryAfter != got.counter.Signal.RetryAfter-500*time.Millisecond {
			t.Fatal("buffer acknowledgment or original throttle window changed", err)
		}
	}
}

func TestDecisionAuditStartupAndNativeIssuerVariant(t *testing.T) {
	now := testContext().Now
	for _, mutate := range []func(*DecisionAuditConfig){
		func(c *DecisionAuditConfig) { c.PolicyID = "" },
		func(c *DecisionAuditConfig) { c.Timeout = 0 },
		func(c *DecisionAuditConfig) { c.Timeout = 6 * time.Second },
		func(c *DecisionAuditConfig) { c.OnLoss = nil },
		func(c *DecisionAuditConfig) { c.Delivery.Sink = nil },
		func(c *DecisionAuditConfig) { c.Delivery.RecoveryTimeout = 2 * time.Second },
	} {
		cfg := auditedConfig(t, &now, func(context.Context, audit.Record) (audit.AppendResult, error) {
			t.Fatal("startup called sink")
			return audit.AppendResult{}, nil
		})
		mutate(cfg.DecisionAudit)
		if _, err := NewEvaluator(cfg); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatal("unsafe startup admitted", err)
		}
	}
	cfg := issuerConfig(t, &now, evidenceExecutor{resolve: missingEvidence})
	ec := countedConfig(t, &now, cfg.Evaluation.state.counters.state.store)
	for i := range ec.Sources {
		ec.Sources[i].Version = "v1"
	}
	ec.DecisionAudit = auditedConfig(t, &now, func(context.Context, audit.Record) (audit.AppendResult, error) {
		t.Fatal("issuer construction delivered")
		return audit.AppendResult{}, nil
	}).DecisionAudit
	var err error
	cfg.Evaluation, err = NewEvaluator(ec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewPhoneEvidenceIssuer(cfg); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatal("duplicate native decision owner admitted", err)
	}
}

func TestDecisionAuditConcurrentAttributionAndConfigurationCopies(t *testing.T) {
	now := testContext().Now
	var mu sync.Mutex
	seen := make(map[string]string)
	cfg := auditedConfig(t, &now, func(_ context.Context, r audit.Record) (audit.AppendResult, error) {
		mu.Lock()
		seen[r.Attributes()["command.id"]] = r.Subject().ID()
		mu.Unlock()
		return audit.AppendResult{RecordID: r.ID(), Status: audit.AppendAccepted}, nil
	})
	e, err := NewEvaluator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.DecisionAudit.PolicyID = "changed"
	cfg.DecisionAudit.OnLoss = nil
	var wg sync.WaitGroup
	for range 16 {
		r := auditRequest(t)
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := e.Evaluate(context.Background(), r)
			if err != nil || got.Audit.CommandID() != r.Attribution.CommandID || got.Audit.Record().Policy().PolicyID == "changed" {
				t.Error("configuration/scope contaminated", err)
			}
		}()
	}
	wg.Wait()
	if len(seen) != 16 {
		t.Fatal("concurrent scopes collapsed")
	}
	for id, subject := range seen {
		if id != subject {
			t.Fatal("cross-request attribution")
		}
	}
}
func (s decisionSink) AppendBatch(context.Context, []audit.Record) (audit.BatchResult, error) {
	return audit.BatchResult{}, errors.New("unexpected batch")
}

func auditRequest(t *testing.T) EvaluateRequest {
	t.Helper()
	r := EvaluateRequest{Context: testContext(), Phase: NonIssuing}
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	r.Context.Tenant, r.Context.Attempt = string(id), string(id)
	r.Attribution = &DecisionAttribution{CommandID: id, CorrelationID: id, Actor: audit.ActorInput{Kind: audit.ActorAnonymous}, Subject: identity.SecurityAuthenticationAttempt, SubjectID: string(id)}
	return r
}

func auditedConfig(t *testing.T, now *time.Time, sink decisionSink) EvaluatorConfig {
	t.Helper()
	c := evaluatorConfig(t)
	c.Clock = func() time.Time { return *now }
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	c.DecisionAudit = &DecisionAuditConfig{PolicyID: string(id), Timeout: time.Second,
		Delivery: audit.RecorderConfig{Sink: sink, Mode: audit.DeliveryFailClosed},
		OnLoss:   func(context.Context, DecisionDelivery) error { return nil }}
	return c
}

func TestDecisionAuditActualClassificationAndClosedDefaults(t *testing.T) {
	for _, want := range []DecisionAction{Allow, Deny, Throttle, StepUp} {
		t.Run(string(want), func(t *testing.T) {
			now := testContext().Now
			var records []audit.Record
			cfg := auditedConfig(t, &now, func(ctx context.Context, r audit.Record) (audit.AppendResult, error) {
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("unbounded audit")
				}
				records = append(records, r)
				return audit.AppendResult{RecordID: r.ID(), Status: audit.AppendAccepted}, nil
			})
			cfg.Sources[0].Read = func(_ context.Context, c Context) (Signal, error) {
				s := testSignal(c, "status", SignalClean)
				switch want {
				case Deny:
					s.State = SignalDeny
				case Throttle:
					s.State = SignalThrottle
					s.RetryAfter = time.Second
				case StepUp:
					s.State = SignalStepUp
				}
				return s, nil
			}
			e, err := NewEvaluator(cfg)
			if err != nil {
				t.Fatal(err)
			}
			r := auditRequest(t)
			got, err := e.Evaluate(context.Background(), r)
			if err != nil || got.Decision.Action != want || len(records) != 1 || got.Audit.Outcome() != audit.AppendCommitted {
				t.Fatal("classification/delivery", err)
			}
			bytes, err := audit.CanonicalJSON(records[0])
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := audit.ParseCanonicalJSON(bytes, audit.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			if parsed.Action() != "identity.risk.decide" || parsed.Context().TenantID() != r.Context.Tenant || parsed.Subject().ID() != r.Context.Attempt || parsed.Policy().Version != "3" || parsed.Policy().PolicyID != cfg.DecisionAudit.PolicyID || parsed.Attributes()["retention.class"] != "protected" || parsed.Attributes()["command.id"] != string(r.Attribution.CommandID) || len(parsed.Attributes()) != 3 || !parsed.OccurredAt().Equal(now) {
				t.Fatal("canonical attribution")
			}
			wantOutcome, wantReason := audit.OutcomeDenied, identity.SecurityRiskDenied
			switch want {
			case Allow:
				wantOutcome, wantReason = audit.OutcomeSucceeded, identity.SecurityCompleted
			case Throttle:
				wantReason = identity.SecurityRateLimited
			case StepUp:
				wantReason = identity.SecurityStepUpRequired
			}
			if parsed.Outcome() != wantOutcome || parsed.ReasonCode() != string(wantReason) {
				t.Fatal("persisted policy classification changed")
			}
			r.Context.Operation = "identity.account.access-token"
			got, err = e.Evaluate(context.Background(), r)
			if err != nil || got.Decision.Action != Deny || len(records) != 2 {
				t.Fatal("closed default unaudited", err)
			}
			if records[1].Outcome() != audit.OutcomeDenied || records[1].ReasonCode() != string(identity.SecurityRiskDenied) {
				t.Fatal("closed default audit classification changed")
			}
		})
	}
}

func TestDecisionAuditLossPreservesRestrictionAndOriginalRecord(t *testing.T) {
	for _, want := range []DecisionAction{Allow, Deny, Throttle, StepUp} {
		for _, outcome := range []audit.AppendOutcome{audit.AppendRejected, audit.AppendUnknown, audit.AppendCommitted} {
			now := testContext().Now
			calls, losses := 0, 0
			var submitted audit.Record
			r := auditRequest(t)
			cfg := auditedConfig(t, &now, func(_ context.Context, record audit.Record) (audit.AppendResult, error) {
				calls++
				submitted = record
				return audit.AppendResult{}, audit.NewAppendError(outcome, errors.New("private provider diagnostic"))
			})
			cfg.DecisionAudit.OnLoss = func(ctx context.Context, d DecisionDelivery) error {
				losses++
				if _, ok := ctx.Deadline(); !ok || d.Record().ID() == "" {
					t.Fatal("unbounded/lost recovery")
				}
				original, e1 := audit.CanonicalJSON(submitted)
				recovered, e2 := audit.CanonicalJSON(d.Record())
				if e1 != nil || e2 != nil || !bytes.Equal(original, recovered) || d.CommandID() != r.Attribution.CommandID || d.Outcome() != outcome {
					t.Fatal("recovery rebuilt original identity")
				}
				return errors.New("private loss callback")
			}
			cfg.Sources[0].Read = func(_ context.Context, c Context) (Signal, error) {
				s := testSignal(c, "status", SignalClean)
				switch want {
				case Deny:
					s.State = SignalDeny
				case Throttle:
					s.State = SignalThrottle
					s.RetryAfter = time.Second
				case StepUp:
					s.State = SignalStepUp
				}
				return s, nil
			}
			e, err := NewEvaluator(cfg)
			if err != nil {
				t.Fatal(err)
			}
			got, err := e.Evaluate(context.Background(), r)
			if !errors.Is(err, ErrDecisionAuditUnavailable) || calls != 1 || got.Audit.Outcome() != outcome || got.Audit.Record().ID() == "" || got.provenance != nil || strings.Contains(err.Error(), "private") {
				t.Fatal("loss classification", err)
			}
			original, e1 := audit.CanonicalJSON(submitted)
			returned, e2 := audit.CanonicalJSON(got.Audit.Record())
			if e1 != nil || e2 != nil || !bytes.Equal(original, returned) || got.Audit.CommandID() != r.Attribution.CommandID {
				t.Fatal("returned recovery rebuilt original identity")
			}
			if want == Allow {
				if got.Decision.Action != "" {
					t.Fatal("unaudited allow escaped")
				}
			} else if got.Decision.Action != want {
				t.Fatal("restriction erased")
			}
			if losses != (map[bool]int{true: 0, false: 1}[outcome == audit.AppendCommitted]) {
				t.Fatal("known commit treated as loss")
			}
		}
	}
}

func TestDecisionAuditAdmissionAndCancellationBeforeSources(t *testing.T) {
	now := testContext().Now
	cfg := auditedConfig(t, &now, func(context.Context, audit.Record) (audit.AppendResult, error) {
		t.Fatal("audit before admission")
		return audit.AppendResult{}, nil
	})
	for i := range cfg.Sources {
		cfg.Sources[i].Read = func(context.Context, Context) (Signal, error) {
			t.Fatal("source before admission")
			return Signal{}, nil
		}
	}
	e, err := NewEvaluator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*EvaluateRequest){func(r *EvaluateRequest) { r.Attribution = nil }, func(r *EvaluateRequest) { r.Attribution.SubjectID = "foreign" }, func(r *EvaluateRequest) { r.Attribution.CommandID = "" }, func(r *EvaluateRequest) { r.Phase = PhoneResetInitiation }, func(r *EvaluateRequest) { r.Context.Operation = "signin" }} {
		r := auditRequest(t)
		change(&r)
		if _, err := e.Evaluate(context.Background(), r); err == nil {
			t.Fatal("invalid attribution admitted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.Evaluate(ctx, auditRequest(t)); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
}

func TestDecisionAuditOriginalFactExpiryAndCancellationAfterAcknowledgment(t *testing.T) {
	for _, mode := range []string{"expiry", "cancel"} {
		now := testContext().Now
		ctx, cancel := context.WithCancel(context.Background())
		cfg := auditedConfig(t, &now, func(_ context.Context, r audit.Record) (audit.AppendResult, error) {
			if mode == "expiry" {
				now = now.Add(time.Second)
			} else {
				cancel()
			}
			return audit.AppendResult{RecordID: r.ID(), Status: audit.AppendAccepted}, nil
		})
		cfg.Sources[0].Read = func(_ context.Context, c Context) (Signal, error) {
			s := testSignal(c, "status", SignalClean)
			s.ExpiresAt = now.Add(time.Second)
			return s, nil
		}
		e, err := NewEvaluator(cfg)
		if err != nil {
			t.Fatal(err)
		}
		got, err := e.Evaluate(ctx, auditRequest(t))
		cancel()
		if err == nil || got.Decision.Action != "" || got.provenance != nil || got.Audit.Outcome() != audit.AppendCommitted {
			t.Fatal("stale/cancelled allow", err)
		}
	}
}

func TestDecisionAuditAlertOnlyRetainsAuthoritativeLoss(t *testing.T) {
	for _, outcome := range []audit.AppendOutcome{audit.AppendRejected, audit.AppendUnknown} {
		now := testContext().Now
		losses, alerts := 0, 0
		cfg := auditedConfig(t, &now, func(context.Context, audit.Record) (audit.AppendResult, error) {
			return audit.AppendResult{}, audit.NewAppendError(outcome, errors.New("private sink"))
		})
		cfg.DecisionAudit.Delivery.Mode = audit.DeliveryFailOpenWithAlert
		cfg.DecisionAudit.Delivery.RecoveryTimeout = time.Second
		cfg.DecisionAudit.Delivery.Alerter = audit.AlertFunc(func(_ context.Context, a audit.DeliveryAlert) error {
			alerts++
			if a.Outcome != outcome {
				t.Fatal("incorrect primary outcome")
			}
			return nil
		})
		cfg.DecisionAudit.OnLoss = func(_ context.Context, d DecisionDelivery) error {
			losses++
			if d.Outcome() != outcome {
				t.Fatal("authoritative loss classification erased")
			}
			return nil
		}
		e, err := NewEvaluator(cfg)
		if err != nil {
			t.Fatal(err)
		}
		got, err := e.Evaluate(context.Background(), auditRequest(t))
		if !errors.Is(err, ErrDecisionAuditUnavailable) || got.Decision.Action != "" || got.Audit.Outcome() != outcome || got.Audit.Disposition() != audit.DeliveryProceededAfterAlert || losses != 1 || alerts != 1 {
			t.Fatal("alert alone granted permission or lost outcome", err)
		}
	}
}

func TestDecisionAuditLateCommittedAcknowledgmentNeverAllows(t *testing.T) {
	for _, mode := range []string{"context", "clock"} {
		now := testContext().Now
		cfg := auditedConfig(t, &now, func(ctx context.Context, r audit.Record) (audit.AppendResult, error) {
			if mode == "context" {
				<-ctx.Done()
			} else {
				now = now.Add(time.Millisecond)
			}
			return audit.AppendResult{RecordID: r.ID(), Status: audit.AppendAccepted}, nil
		})
		cfg.DecisionAudit.Timeout = time.Millisecond
		cfg.DecisionAudit.OnLoss = func(context.Context, DecisionDelivery) error { t.Fatal("known commit treated as loss"); return nil }
		e, err := NewEvaluator(cfg)
		if err != nil {
			t.Fatal(err)
		}
		got, err := e.Evaluate(context.Background(), auditRequest(t))
		if !errors.Is(err, context.DeadlineExceeded) || got.Decision.Action != "" || got.Audit.Outcome() != audit.AppendCommitted || got.provenance != nil {
			t.Fatal("late audit acknowledgment allowed", err)
		}
	}
}

func TestDecisionAuditAttributionCopiedBeforeSourceCallbacks(t *testing.T) {
	now := testContext().Now
	r := auditRequest(t)
	original := *r.Attribution
	cfg := auditedConfig(t, &now, func(_ context.Context, record audit.Record) (audit.AppendResult, error) {
		if record.Subject().ID() != original.SubjectID || record.Attributes()["command.id"] != string(original.CommandID) {
			t.Fatal("caller mutation replaced audit scope")
		}
		return audit.AppendResult{RecordID: record.ID(), Status: audit.AppendAccepted}, nil
	})
	cfg.Sources[0].Read = func(_ context.Context, c Context) (Signal, error) {
		r.Attribution.CommandID = "changed"
		r.Attribution.SubjectID = "changed"
		return testSignal(c, "status", SignalClean), nil
	}
	e, err := NewEvaluator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.Evaluate(context.Background(), r); err != nil {
		t.Fatal(err)
	}
}

func TestDecisionAuditFailedBufferCannotErasePrimaryAmbiguity(t *testing.T) {
	for _, primary := range []audit.AppendOutcome{audit.AppendRejected, audit.AppendUnknown} {
		for _, fallback := range []audit.AppendOutcome{audit.AppendRejected, audit.AppendUnknown, audit.AppendCommitted} {
			now := testContext().Now
			want := fallback
			if primary == audit.AppendUnknown && fallback != audit.AppendCommitted {
				want = audit.AppendUnknown
			}
			losses := 0
			cfg := auditedConfig(t, &now, func(context.Context, audit.Record) (audit.AppendResult, error) {
				return audit.AppendResult{}, audit.NewAppendError(primary, errors.New("primary"))
			})
			cfg.DecisionAudit.Delivery.Mode = audit.DeliveryDurableBuffer
			cfg.DecisionAudit.Delivery.RecoveryTimeout = time.Second
			cfg.DecisionAudit.Delivery.Buffer = decisionBuffer{decisionSink(func(context.Context, audit.Record) (audit.AppendResult, error) {
				return audit.AppendResult{}, audit.NewAppendError(fallback, errors.New("buffer"))
			})}
			cfg.DecisionAudit.OnLoss = func(_ context.Context, d DecisionDelivery) error {
				losses++
				if d.Outcome() != want {
					t.Fatal("operational handoff erased primary ambiguity")
				}
				return nil
			}
			e, err := NewEvaluator(cfg)
			if err != nil {
				t.Fatal(err)
			}
			got, err := e.Evaluate(context.Background(), auditRequest(t))
			if !errors.Is(err, ErrDecisionAuditUnavailable) || got.Decision.Action != "" || got.Audit.Outcome() != want || got.provenance != nil {
				t.Fatal("failed buffer erased primary ambiguity", err)
			}
			if (want != audit.AppendCommitted && losses != 1) || (want == audit.AppendCommitted && losses != 0) {
				t.Fatal("incorrect reconciliation handoff")
			}
		}
	}
}

func TestDecisionAuditConcurrentBufferFailuresKeepPerInvocationOutcome(t *testing.T) {
	now := testContext().Now
	requests := make([]EvaluateRequest, 16)
	want := make(map[string]audit.AppendOutcome)
	for i := range requests {
		requests[i] = auditRequest(t)
		outcome := audit.AppendRejected
		if i%2 == 0 {
			outcome = audit.AppendUnknown
		}
		want[string(requests[i].Attribution.CommandID)] = outcome
	}
	cfg := auditedConfig(t, &now, func(_ context.Context, r audit.Record) (audit.AppendResult, error) {
		return audit.AppendResult{}, audit.NewAppendError(want[r.Attributes()["command.id"]], errors.New("primary"))
	})
	cfg.DecisionAudit.Delivery.Mode = audit.DeliveryDurableBuffer
	cfg.DecisionAudit.Delivery.RecoveryTimeout = time.Second
	cfg.DecisionAudit.Delivery.Buffer = decisionBuffer{decisionSink(func(context.Context, audit.Record) (audit.AppendResult, error) {
		return audit.AppendResult{}, audit.NewAppendError(audit.AppendRejected, errors.New("buffer"))
	})}
	// A diagnostic observer's failure cannot erase the native primary outcome.
	cfg.DecisionAudit.Delivery.Observer = audit.ObserverFunc(func(context.Context, audit.Observation) { panic("private observer") })
	cfg.DecisionAudit.OnLoss = func(_ context.Context, d DecisionDelivery) error {
		if d.Outcome() != want[string(d.CommandID())] {
			t.Error("cross-request primary classification")
		}
		return nil
	}
	e, err := NewEvaluator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for _, r := range requests {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := e.Evaluate(context.Background(), r)
			if !errors.Is(err, ErrDecisionAuditUnavailable) || got.Audit.Outcome() != want[string(r.Attribution.CommandID)] {
				t.Error("concurrent buffer result contaminated", err)
			}
		}()
	}
	wg.Wait()
}
