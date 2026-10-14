package session_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	"strings"
	"sync"
	"testing"
	"time"
)

type updateExecutor struct {
	execute func(context.Context, session.UpdateCommandRequest) (session.UpdateExecution, error)
	recover func(context.Context, session.UpdateCommandRequest) (identity.CommandResult, error)
}

func (e *updateExecutor) ExecuteUpdate(ctx context.Context, r session.UpdateCommandRequest) (session.UpdateExecution, error) {
	return e.execute(ctx, r)
}
func (e *updateExecutor) RecoverUpdate(ctx context.Context, r session.UpdateCommandRequest) (identity.CommandResult, error) {
	return e.recover(ctx, r)
}
func committedUpdate(r session.UpdateCommandRequest) session.UpdateExecution {
	c, _ := r.Command()
	u, _ := c.Update()
	s, _ := u.Source.Bindings()
	return session.UpdateExecution{Receipt: identity.CommandResult{Binding: u.Binding, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "audit", Feature: &identity.FeatureReceipt{Operation: session.UpdateOperation(), BeforeVersion: s.Version, AfterVersion: s.Version + 1}}, Session: u.Successor, DeviceLabel: u.DeviceLabel}
}
func updaterFixture(t *testing.T) (*session.SessionUpdater, session.UpdateCommandRequest, *updateExecutor, *mutableIssueClock, *session.SessionService) {
	return updaterDurationFixture(t, time.Second)
}
func updaterDurationFixture(t *testing.T, duration time.Duration) (*session.SessionUpdater, session.UpdateCommandRequest, *updateExecutor, *mutableIssueClock, *session.SessionService) {
	t.Helper()
	reader, input, clock, _, _, _ := validationFixture(t)
	caller, err := reader.Get(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	executor := &updateExecutor{execute: func(_ context.Context, r session.UpdateCommandRequest) (session.UpdateExecution, error) {
		return committedUpdate(r), nil
	}, recover: func(_ context.Context, r session.UpdateCommandRequest) (identity.CommandResult, error) {
		return committedUpdate(r).Receipt, nil
	}}
	service, err := session.NewSessionUpdater(reader, executor, session.UpdateConfig{PolicyID: "session-policy", PolicyVersion: 1, MaximumDuration: duration})
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := caller.Session.Bindings()
	request, err := service.Prepare(caller, session.UpdatePreparation{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", CorrelationID: "update", SessionID: spec.SessionID, ExpectedVersion: spec.Version, DeviceLabel: "My laptop"})
	if err != nil {
		t.Fatal(err)
	}
	return service, request, executor, clock, reader
}

func TestUpdaterDenialAndCancellationDoNotBecomeAmbiguousOrMetadataSuccess(t *testing.T) {
	for _, mode := range []string{"denied-before-reservation", "not-committed-cancellation", "committed-cancellation", "committed-expiry", "committed-ancillary-error", "committed-clock-panic", "panic"} {
		t.Run(mode, func(t *testing.T) {
			service, request, executor, clock, _ := updaterFixture(t)
			ctx, stop := context.WithCancel(context.Background())
			defer stop()
			executor.execute = func(_ context.Context, r session.UpdateCommandRequest) (session.UpdateExecution, error) {
				e := committedUpdate(r)
				switch mode {
				case "denied-before-reservation":
					return session.UpdateExecution{}, identity.ForbiddenError{}
				case "not-committed-cancellation":
					stop()
					e.Receipt.Outcome = identity.CommitOutcomeNotCommitted
					e.Receipt.AuditEventID = ""
					e.Receipt.Feature.BeforeVersion, e.Receipt.Feature.AfterVersion = 0, 0
					e.Session, e.DeviceLabel = session.Session{}, ""
					return e, context.Canceled
				case "committed-cancellation":
					stop()
				case "committed-expiry":
					clock.now = r.ValidUntil()
				case "committed-clock-panic":
					clock.panicNow = true
				case "committed-ancillary-error":
					e.Session, e.DeviceLabel = session.Session{}, ""
					return e, errors.New("private diagnostics")
				case "panic":
					panic("private panic")
				}
				return e, nil
			}
			got, err := service.Update(ctx, request)
			if err == nil || got.Session != (session.Session{}) || got.Device != (session.Device{}) || strings.Contains(err.Error(), "private") {
				t.Fatal("failure returned label success or diagnostics", err)
			}
			switch mode {
			case "denied-before-reservation":
				var denied identity.ForbiddenError
				if !errors.As(err, &denied) || got.CommitOutcome != identity.CommitOutcomeInvalid {
					t.Fatal("pre-reservation denial made ambiguous", err)
				}
			case "not-committed-cancellation":
				var cancelled identity.CancelledError
				if !errors.As(err, &cancelled) || got.CommitOutcome != identity.CommitOutcomeNotCommitted {
					t.Fatal("cancellation lost exact noncommit", err)
				}
			case "panic":
				var unknown identity.UnknownCommitError
				if !errors.As(err, &unknown) || got.CommitOutcome != identity.CommitOutcomeUnknown {
					t.Fatal("panic assumed rollback", err)
				}
			default:
				if got.CommitOutcome != identity.CommitOutcomeCommitted {
					t.Fatal("known commit erased", err)
				}
			}
		})
	}
}

func TestUpdaterReceiptOutcomesAndExactProjection(t *testing.T) {
	outcomes := []identity.CommitOutcome{identity.CommitOutcomeNotCommitted, identity.CommitOutcomeConflict, identity.CommitOutcomeUnknown, identity.CommitOutcomeInProgress}
	for _, outcome := range outcomes {
		service, request, executor, _, _ := updaterFixture(t)
		execution := committedUpdate(request)
		execution.Receipt.Outcome = outcome
		execution.Receipt.AuditEventID = ""
		execution.Receipt.Feature.BeforeVersion, execution.Receipt.Feature.AfterVersion = 0, 0
		execution.Session, execution.DeviceLabel = session.Session{}, ""
		if outcome == identity.CommitOutcomeInProgress {
			execution.Receipt.RetryAfter = time.Second
		}
		executor.execute = func(context.Context, session.UpdateCommandRequest) (session.UpdateExecution, error) {
			return execution, errors.New("private ancillary")
		}
		got, err := service.Update(context.Background(), request)
		if err == nil || got.CommitOutcome != outcome || got.RetryAfter != execution.Receipt.RetryAfter || got.Session != (session.Session{}) || got.Device != (session.Device{}) {
			t.Fatal("durable outcome or metadata changed", err)
		}
		switch outcome {
		case identity.CommitOutcomeNotCommitted:
			var want identity.NotCommittedError
			if !errors.As(err, &want) {
				t.Fatal("noncommit classification")
			}
		case identity.CommitOutcomeConflict:
			var want identity.ConflictError
			if !errors.As(err, &want) {
				t.Fatal("conflict classification")
			}
		case identity.CommitOutcomeUnknown:
			var want identity.UnknownCommitError
			if !errors.As(err, &want) {
				t.Fatal("unknown classification")
			}
		case identity.CommitOutcomeInProgress:
			var want identity.InProgressError
			if !errors.As(err, &want) || want.RetryAfter != time.Second {
				t.Fatal("retry classification")
			}
		}
	}
	for _, mode := range []string{"missing-receipt", "wrong-binding", "wrong-operation", "wrong-versions", "wrong-session", "wrong-label", "partial-metadata", "noncommit-metadata", "wrong-audit", "denied-partial"} {
		t.Run(mode, func(t *testing.T) {
			service, request, executor, _, _ := updaterFixture(t)
			executor.execute = func(_ context.Context, r session.UpdateCommandRequest) (session.UpdateExecution, error) {
				e := committedUpdate(r)
				switch mode {
				case "missing-receipt":
					e.Receipt = identity.CommandResult{}
				case "wrong-binding":
					e.Receipt.Binding.ActorID = "foreign"
				case "wrong-operation":
					e.Receipt.Feature.Operation = session.RotateOperation()
				case "wrong-versions":
					e.Receipt.Feature.BeforeVersion++
					e.Receipt.Feature.AfterVersion++
				case "wrong-session":
					c, _ := r.Command()
					u, _ := c.Update()
					e.Session = u.Source
				case "wrong-label":
					e.DeviceLabel = "different"
				case "partial-metadata":
					e.Session = session.Session{}
					return e, errors.New("private partial")
				case "noncommit-metadata":
					e.Receipt.Outcome = identity.CommitOutcomeNotCommitted
					e.Receipt.AuditEventID = ""
					e.Receipt.Feature.BeforeVersion, e.Receipt.Feature.AfterVersion = 0, 0
				case "wrong-audit":
					e.Receipt.AuditEventID = ""
				case "denied-partial":
					e.Receipt = identity.CommandResult{}
					return e, identity.ForbiddenError{}
				}
				return e, nil
			}
			got, err := service.Update(context.Background(), request)
			var unknown identity.UnknownCommitError
			if !errors.As(err, &unknown) || got.CommitOutcome != identity.CommitOutcomeUnknown || got.Session != (session.Session{}) || got.Device != (session.Device{}) {
				t.Fatal("malformed executor result accepted", err)
			}
		})
	}
}

func TestUpdaterCancellationBudgetsReplayAndRecoveryAreBounded(t *testing.T) {
	service, request, executor, clock, reader := updaterFixture(t)
	entered := false
	executor.execute = func(_ context.Context, r session.UpdateCommandRequest) (session.UpdateExecution, error) {
		entered = true
		e := committedUpdate(r)
		e.Replayed = true
		return e, nil
	}
	ctx, stop := context.WithCancel(context.Background())
	stop()
	got, err := service.Update(ctx, request)
	if err == nil || entered || got.CommitOutcome != identity.CommitOutcomeInvalid {
		t.Fatal("pre-cancelled call entered")
	}
	got, err = service.Update(context.Background(), request)
	if err != nil || !got.Replayed || got.Device.Label != "My laptop" {
		t.Fatal("exact replay changed projection", err)
	}
	clock.now = request.ValidUntil()
	entered = false
	got, err = service.Update(context.Background(), request)
	if err == nil || entered || got.CommitOutcome != identity.CommitOutcomeInvalid {
		t.Fatal("expired custody entered")
	}
	if request.Validate(reader, clock.now) == nil {
		t.Fatal("expired original became authenticated")
	}
	executor.recover = func(ctx context.Context, r session.UpdateCommandRequest) (identity.CommandResult, error) {
		if _, ok := ctx.Deadline(); !ok {
			t.Error("unbounded recovery")
		}
		return committedUpdate(r).Receipt, nil
	}
	got, err = service.Recover(context.Background(), request)
	if err != nil || got.CommitOutcome != identity.CommitOutcomeCommitted || !got.Replayed || got.Device != (session.Device{}) {
		t.Fatal("historical outcome recovery", err)
	}
	short, r, e, _, _ := updaterDurationFixture(t, 10*time.Millisecond)
	e.execute = func(ctx context.Context, _ session.UpdateCommandRequest) (session.UpdateExecution, error) {
		<-ctx.Done()
		return session.UpdateExecution{}, ctx.Err()
	}
	start := time.Now()
	got, err = short.Update(context.Background(), r)
	if err == nil || got.CommitOutcome != identity.CommitOutcomeUnknown || time.Since(start) > time.Second {
		t.Fatal("executor deadline assumed rollback or unbounded", err)
	}
	e.recover = func(ctx context.Context, _ session.UpdateCommandRequest) (identity.CommandResult, error) {
		<-ctx.Done()
		return identity.CommandResult{}, ctx.Err()
	}
	start = time.Now()
	got, err = short.Recover(context.Background(), r)
	if err == nil || got.CommitOutcome != identity.CommitOutcomeUnknown || time.Since(start) > time.Second {
		t.Fatal("recovery deadline guessed terminal state or unbounded", err)
	}
}

func TestUpdaterPrepareConfigForeignPolicyAndZeroValues(t *testing.T) {
	reader, input, clock, _, cfg, backend := validationFixture(t)
	caller, err := reader.Get(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	executor := &updateExecutor{}
	config := session.UpdateConfig{PolicyID: "policy", PolicyVersion: 1, MaximumDuration: time.Second}
	for _, mutate := range []func(*session.UpdateConfig){func(c *session.UpdateConfig) { c.PolicyID = "" }, func(c *session.UpdateConfig) { c.PolicyVersion = 0 }, func(c *session.UpdateConfig) { c.MaximumDuration = 0 }, func(c *session.UpdateConfig) { c.MaximumDuration = 31 * time.Second }} {
		c := config
		mutate(&c)
		if _, err := session.NewSessionUpdater(reader, executor, c); !errors.Is(err, session.ErrInvalidInput) {
			t.Fatal("invalid config", err)
		}
	}
	if _, err := session.NewSessionUpdater(nil, executor, config); !errors.Is(err, session.ErrInvalidInput) {
		t.Fatal("nil reader")
	}
	var nilExecutor *updateExecutor
	if _, err := session.NewSessionUpdater(reader, nilExecutor, config); !errors.Is(err, session.ErrInvalidInput) {
		t.Fatal("typed nil executor")
	}
	service, _ := session.NewSessionUpdater(reader, executor, config)
	spec, _ := caller.Session.Bindings()
	valid := session.UpdatePreparation{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", CorrelationID: "update", SessionID: spec.SessionID, ExpectedVersion: spec.Version, DeviceLabel: ""}
	request, err := service.Prepare(caller, valid)
	if err != nil {
		t.Fatal("clear label", err)
	}
	command, _ := request.Command()
	u, _ := command.Update()
	if u.DeviceLabel != "" {
		t.Fatal("clear changed")
	}
	for _, mode := range []string{"session", "version", "zero-version", "label", "command", "correlation", "forged", "clock-panic"} {
		in, source := valid, caller
		switch mode {
		case "session":
			in.SessionID = "foreign"
		case "version":
			in.ExpectedVersion++
		case "zero-version":
			in.ExpectedVersion = 0
		case "label":
			in.DeviceLabel = strings.Repeat("x", 129)
		case "command":
			in.CommandID = "bad"
		case "correlation":
			in.CorrelationID = ""
		case "forged":
			source = session.GetResult{Authenticated: true, Session: caller.Session}
		case "clock-panic":
			clock.panicNow = true
		}
		got, err := service.Prepare(source, in)
		clock.panicNow = false
		if err == nil {
			t.Fatal("invalid preparation admitted", mode)
		}
		if _, ok := got.Command(); ok {
			t.Fatal("partial preparation returned", mode)
		}
		if mode == "version" {
			var conflict identity.ConflictError
			if !errors.As(err, &conflict) {
				t.Fatal("CAS classification")
			}
		}
	}
	foreignReader, _ := session.NewSessionService(backend, cfg)
	foreign, _ := session.NewSessionUpdater(foreignReader, executor, config)
	wrongConfig := config
	wrongConfig.PolicyVersion++
	wrongPolicy, _ := session.NewSessionUpdater(reader, executor, wrongConfig)
	for _, s := range []*session.SessionUpdater{nil, {}, foreign, wrongPolicy} {
		if _, err := s.Update(context.Background(), request); !errors.Is(err, session.ErrInvalidInput) {
			t.Fatal("foreign service/policy execution")
		}
		if _, err := s.Recover(context.Background(), request); !errors.Is(err, session.ErrInvalidInput) {
			t.Fatal("foreign service/policy recovery")
		}
	}
	if _, err := service.Update(nil, request); !errors.Is(err, session.ErrInvalidInput) {
		t.Fatal("nil context")
	}
	if _, err := service.Update(context.Background(), session.UpdateCommandRequest{}); !errors.Is(err, session.ErrInvalidInput) {
		t.Fatal("zero request")
	}
	if _, err := service.Recover(nil, request); !errors.Is(err, session.ErrInvalidInput) {
		t.Fatal("nil recovery context")
	}
}

func TestUpdaterRedactionAndConcurrentCommittedCopies(t *testing.T) {
	service, request, _, _, _ := updaterFixture(t)
	result, err := service.Update(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []any{service, session.UpdateConfig{PolicyID: "privatepolicy"}, session.UpdatePreparation{DeviceLabel: "My laptop"}, result, committedUpdate(request)} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
			out := fmt.Sprintf(format, v)
			if strings.Contains(out, "My laptop") || strings.Contains(out, "privatepolicy") {
				t.Fatal("diagnostic disclosure")
			}
		}
		if _, err := json.Marshal(v); !errors.Is(err, session.ErrSecretSerialization) {
			t.Fatal("implicit JSON disclosure")
		}
	}
	if _, err := result.MarshalText(); !errors.Is(err, session.ErrSecretSerialization) {
		t.Fatal("result text disclosure")
	}
	if _, err := (session.UpdatePreparation{}).MarshalText(); !errors.Is(err, session.ErrSecretSerialization) {
		t.Fatal("input text disclosure")
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			got, err := service.Update(context.Background(), request)
			if err != nil || got.CommitOutcome != identity.CommitOutcomeCommitted || got.Device.Label != "My laptop" {
				t.Error("concurrent exact request", err)
			}
		})
	}
	wg.Wait()
}

func TestUpdaterOriginalAdmissionBudgetAndRecoveryFailures(t *testing.T) {
	service, request, executor, clock, _ := updaterFixture(t)
	clock.now = request.ValidUntil().Add(-5 * time.Millisecond)
	executor.execute = func(ctx context.Context, r session.UpdateCommandRequest) (session.UpdateExecution, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 5*time.Millisecond {
			t.Error("original validity did not clip executor budget")
		}
		<-ctx.Done()
		return committedUpdate(r), ctx.Err()
	}
	result, err := service.Update(context.Background(), request)
	var deadline identity.DeadlineExceededError
	if !errors.As(err, &deadline) || result.CommitOutcome != identity.CommitOutcomeCommitted || result.Session != (session.Session{}) || result.Device != (session.Device{}) {
		t.Fatal("expired context erased commitment or disclosed success", err)
	}
	for _, mode := range []string{"cancelled-before-entry", "denied", "panic", "malformed", "committed-error", "committed-cancelled", "conflict"} {
		t.Run(mode, func(t *testing.T) {
			service, r, e, _, _ := updaterFixture(t)
			entered := false
			ctx, stop := context.WithCancel(context.Background())
			defer stop()
			if mode == "cancelled-before-entry" {
				stop()
			}
			e.recover = func(_ context.Context, r session.UpdateCommandRequest) (identity.CommandResult, error) {
				entered = true
				receipt := committedUpdate(r).Receipt
				switch mode {
				case "denied":
					return identity.CommandResult{}, identity.ForbiddenError{}
				case "panic":
					panic("private panic")
				case "malformed":
					receipt.Binding.RecordID = "foreign"
				case "committed-error":
					return receipt, errors.New("private retention failure")
				case "committed-cancelled":
					stop()
					return receipt, context.Canceled
				case "conflict":
					receipt.Outcome = identity.CommitOutcomeConflict
					receipt.AuditEventID = ""
					receipt.Feature.BeforeVersion, receipt.Feature.AfterVersion = 0, 0
					return receipt, errors.New("private ancillary")
				}
				return receipt, nil
			}
			got, err := service.Recover(ctx, r)
			if err == nil || got.Device != (session.Device{}) || got.Session != (session.Session{}) || strings.Contains(err.Error(), "private") {
				t.Fatal("recovery disclosed success or diagnostics", err)
			}
			switch mode {
			case "cancelled-before-entry":
				if entered || got.CommitOutcome != identity.CommitOutcomeInvalid {
					t.Fatal("cancelled recovery entered")
				}
			case "denied":
				var forbidden identity.ForbiddenError
				if !errors.As(err, &forbidden) || got.CommitOutcome != identity.CommitOutcomeInvalid {
					t.Fatal("result access denial classified old command")
				}
			case "committed-error", "committed-cancelled":
				if got.CommitOutcome != identity.CommitOutcomeCommitted {
					t.Fatal("known historical commit erased")
				}
			case "conflict":
				var conflict identity.ConflictError
				if !errors.As(err, &conflict) || got.CommitOutcome != identity.CommitOutcomeConflict {
					t.Fatal("known conflict masked")
				}
			default:
				if got.CommitOutcome != identity.CommitOutcomeUnknown {
					t.Fatal("recovery inferred terminal state")
				}
			}
		})
	}
}
func TestUpdaterCommittedLabelAndHistoricalOutcomeRecovery(t *testing.T) {
	service, request, _, clock, _ := updaterFixture(t)
	result, err := service.Update(context.Background(), request)
	if err != nil || result.CommitOutcome != identity.CommitOutcomeCommitted || result.Device.Label != "My laptop" || !result.Device.Current || result.Device.Inactive || result.Session == (session.Session{}) {
		t.Fatal("update delivery", err)
	}
	original := request.ValidUntil()
	clock.now = original
	recovered, err := service.Recover(context.Background(), request)
	if err != nil || recovered.CommitOutcome != identity.CommitOutcomeCommitted || !recovered.Replayed || recovered.Session != (session.Session{}) || recovered.Device != (session.Device{}) || recovered.Recovery != result.Recovery {
		t.Fatal("historical recovery changed scope or delivered admission", err)
	}
	if !request.ValidUntil().Equal(original) {
		t.Fatal("recovery renewed deadline")
	}
}
