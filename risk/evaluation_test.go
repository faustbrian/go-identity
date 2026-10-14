package risk

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func cleanSource(name string) Source {
	return Source{Name: name, Timeout: time.Second, Read: func(_ context.Context, c Context) (Signal, error) {
		signal := testSignal(c, name, SignalClean)
		// Fits both the one-minute read profile and longer authentication profiles.
		signal.ExpiresAt = c.Now.Add(30 * time.Second)
		return signal, nil
	}}
}

func evaluatorConfig(t *testing.T) EvaluatorConfig {
	t.Helper()
	now := testContext().Now
	return EvaluatorConfig{Policy: testPolicy(t), Clock: func() time.Time { return now }, Timeout: 5 * time.Second, Sources: []Source{cleanSource("status"), cleanSource("captcha")}}
}

func TestEvaluatorRunsEveryMandatorySourceAndReturnsOnlySafeDecision(t *testing.T) {
	cfg := evaluatorConfig(t)
	calls := []string{}
	for i := range cfg.Sources {
		source := cfg.Sources[i]
		cfg.Sources[i].Read = func(ctx context.Context, c Context) (Signal, error) {
			if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > source.Timeout {
				t.Fatal("source was not deadline bounded")
			}
			calls = append(calls, source.Name)
			return source.Read(ctx, c)
		}
	}
	e, err := NewEvaluator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	got, err := e.Evaluate(context.Background(), EvaluateRequest{Context: testContext(), Phase: NonIssuing})
	if err != nil || got.Decision.Action != Allow || got.PolicyVersion != 3 || strings.Join(calls, ",") != "status,captcha" {
		t.Fatal("mandatory source evaluation", err)
	}
}

func TestEvaluatorRejectsMissingDuplicateAndUnboundedSourceConfiguration(t *testing.T) {
	for _, mutate := range []func(*EvaluatorConfig){
		func(c *EvaluatorConfig) { c.Policy = Policy{} },
		func(c *EvaluatorConfig) { c.Clock = nil },
		func(c *EvaluatorConfig) { c.Timeout = 0 },
		func(c *EvaluatorConfig) { c.Timeout = 61 * time.Second },
		func(c *EvaluatorConfig) { c.Sources = c.Sources[:1] },
		func(c *EvaluatorConfig) { c.Sources[1].Name = "status" },
		func(c *EvaluatorConfig) { c.Sources[1].Name = "extra" },
		func(c *EvaluatorConfig) { c.Sources[1].Read = nil },
		func(c *EvaluatorConfig) { c.Sources[1].Timeout = 0 },
		func(c *EvaluatorConfig) { c.Sources[1].Timeout = c.Timeout + time.Second },
	} {
		cfg := evaluatorConfig(t)
		mutate(&cfg)
		if _, err := NewEvaluator(cfg); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatal("unsafe source configuration admitted")
		}
	}
}

func TestEvaluatorAdmitsBeforeAnySourceAndRejectsIssuance(t *testing.T) {
	cfg := evaluatorConfig(t)
	for i := range cfg.Sources {
		cfg.Sources[i].Read = func(context.Context, Context) (Signal, error) {
			t.Fatal("source accessed before admission")
			return Signal{}, nil
		}
	}
	e, err := NewEvaluator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range []IssuancePhase{"", "caller-purpose", PhoneResetInitiation, PhoneResetCompletion} {
		_, err = e.Evaluate(context.Background(), EvaluateRequest{Context: testContext(), Phase: phase})
		if !errors.Is(err, ErrUnsupportedIssuance) {
			t.Fatal("unsupported phase admitted", err)
		}
	}
	c := testContext()
	c.Operation = "signin"
	if _, err = e.Evaluate(context.Background(), EvaluateRequest{Context: c, Phase: NonIssuing}); !errors.Is(err, ErrInvalidAction) {
		t.Fatal("alias admitted")
	}
	c.Operation = "identity.account.access-token"
	got, err := e.Evaluate(context.Background(), EvaluateRequest{Context: c, Phase: NonIssuing})
	if err != nil || got.Decision.Action != Deny {
		t.Fatal("closed fallback weakened")
	}
}

func TestEvaluatorRetainsUnavailableAndHintsAndSkipsOnlyExpensiveAfterDeny(t *testing.T) {
	for _, mode := range []string{"unavailable", "hint", "deny-expensive", "deny-required"} {
		cfg := evaluatorConfig(t)
		cfg.Sources[0].Read = func(_ context.Context, c Context) (Signal, error) {
			s := testSignal(c, "status", SignalClean)
			switch mode {
			case "unavailable":
				return s, errors.New("private provider payload")
			case "hint":
				s.Trust = RequestHint
			default:
				s.State = SignalDeny
			}
			return s, nil
		}
		called := false
		cfg.Sources[1].Expensive = mode == "deny-expensive"
		cfg.Sources[1].Read = func(_ context.Context, c Context) (Signal, error) {
			called = true
			return testSignal(c, "captcha", SignalClean), nil
		}
		e, err := NewEvaluator(cfg)
		if err != nil {
			t.Fatal(err)
		}
		got, err := e.Evaluate(context.Background(), EvaluateRequest{Context: testContext(), Phase: NonIssuing})
		if err != nil || got.Decision.Action != Deny || called != (mode != "deny-expensive") {
			t.Fatal("unavailable/deny policy", mode, err)
		}
	}
}

func TestEvaluatorOriginalFactExpiresDuringLaterProviderAndClockCannotMoveBackwards(t *testing.T) {
	for _, backwards := range []bool{false, true} {
		cfg := evaluatorConfig(t)
		now := testContext().Now
		cfg.Clock = func() time.Time { return now }
		cfg.Sources[0].Read = func(_ context.Context, c Context) (Signal, error) {
			s := testSignal(c, "status", SignalClean)
			s.ExpiresAt = now.Add(time.Second)
			return s, nil
		}
		cfg.Sources[1].Read = func(_ context.Context, c Context) (Signal, error) {
			if backwards {
				now = now.Add(-time.Second)
			} else {
				now = now.Add(2 * time.Second)
			}
			return testSignal(c, "captcha", SignalClean), nil
		}
		e, err := NewEvaluator(cfg)
		if err != nil {
			t.Fatal(err)
		}
		got, err := e.Evaluate(context.Background(), EvaluateRequest{Context: testContext(), Phase: NonIssuing})
		if err == nil || got.Decision.Action != "" {
			t.Fatal("expired/or backward clock returned decision")
		}
	}
}

func TestEvaluatorCancellationForeignFactsAndProviderErrorsAreSafe(t *testing.T) {
	for _, mode := range []string{"cancel", "foreign", "wrong-name", "late"} {
		cfg := evaluatorConfig(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		now := testContext().Now
		cfg.Clock = func() time.Time { return now }
		cfg.Sources[0].Read = func(_ context.Context, c Context) (Signal, error) {
			s := testSignal(c, "status", SignalClean)
			switch mode {
			case "cancel":
				cancel()
			case "foreign":
				s.Tenant = "other"
			case "wrong-name":
				s.Name = "captcha"
			case "late":
				now = now.Add(6 * time.Second)
			}
			return s, nil
		}
		e, err := NewEvaluator(cfg)
		if err != nil {
			t.Fatal(err)
		}
		got, err := e.Evaluate(ctx, EvaluateRequest{Context: testContext(), Phase: NonIssuing})
		var typed *EvaluateError
		if err == nil || !errors.As(err, &typed) || got.Decision.Action != "" {
			t.Fatal("unsafe source outcome accepted", mode)
		}
		if mode == "cancel" && !errors.Is(err, context.Canceled) {
			t.Fatal("cancellation hidden")
		}
		if strings.Contains(fmt.Sprintf("%#v", err), "other") {
			t.Fatal("source error disclosure")
		}
	}
}

func TestEvaluatorLowRiskStepUpRequiresConfiguredCurrentFactor(t *testing.T) {
	for _, mode := range []string{"request-only", "server", "server-error"} {
		cfg := evaluatorConfig(t)
		cfg.Sources[0].Read = func(context.Context, Context) (Signal, error) { return Signal{}, errors.New("private fact error") }
		if mode != "request-only" {
			cfg.IndependentFactor = func(ctx context.Context, c Context) (bool, error) {
				if _, ok := ctx.Deadline(); !ok || c.IndependentFactor {
					t.Fatal("unbounded or caller-selected factor resolver")
				}
				if mode == "server-error" {
					return true, errors.New("private factor error")
				}
				return true, nil
			}
		}
		e, err := NewEvaluator(cfg)
		if err != nil {
			t.Fatal(err)
		}
		c := testContext()
		c.Operation, c.IndependentFactor = "identity.profile.get", true
		got, err := e.Evaluate(context.Background(), EvaluateRequest{Context: c, Phase: NonIssuing})
		want := Deny
		if mode == "server" {
			want = StepUp
		}
		if err != nil || got.Decision.Action != want {
			t.Fatal("unverified factor bypassed failure policy", mode, err)
		}
	}
}

func TestEvaluatorSourceCannotClaimSkippedAndLateCleanBecomesUnavailable(t *testing.T) {
	for _, late := range []bool{false, true} {
		cfg := evaluatorConfig(t)
		now := testContext().Now
		cfg.Clock = func() time.Time { return now }
		cfg.Sources[0].Read = func(_ context.Context, c Context) (Signal, error) {
			s := testSignal(c, "status", SignalClean)
			if late {
				now = now.Add(time.Second)
			} else {
				s.State = SignalSkipped
			}
			return s, nil
		}
		e, err := NewEvaluator(cfg)
		if err != nil {
			t.Fatal(err)
		}
		got, err := e.Evaluate(context.Background(), EvaluateRequest{Context: testContext(), Phase: NonIssuing})
		if late {
			if err != nil || got.Decision.Action != Deny || got.assessment.Signals[0].State != SignalUnavailable {
				t.Fatal("late source renewed clean", err)
			}
		} else if !errors.Is(err, ErrInvalidSignal) || got.Decision.Action != "" {
			t.Fatal("source selected skip")
		}
	}
}

func TestEvaluatorCopiesSourcesAndSupportsConcurrentUse(t *testing.T) {
	cfg := evaluatorConfig(t)
	e, err := NewEvaluator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Sources[0].Read = nil
	cfg.Sources[0].Name = "changed"
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			got, err := e.Evaluate(context.Background(), EvaluateRequest{Context: testContext(), Phase: NonIssuing})
			if err != nil || got.Decision.Action != Allow {
				t.Error("source configuration or concurrent evaluation changed", err)
			}
		})
	}
	wg.Wait()
}

func TestEvaluatorRequestCannotSelectClockOrFactorAvailability(t *testing.T) {
	cfg := evaluatorConfig(t)
	for i := range cfg.Sources {
		name := cfg.Sources[i].Name
		cfg.Sources[i].Read = func(_ context.Context, c Context) (Signal, error) {
			if !c.Now.Equal(testContext().Now) || c.IndependentFactor {
				t.Fatal("request selected source clock or factor authority")
			}
			return testSignal(c, name, SignalClean), nil
		}
	}
	e, err := NewEvaluator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c := testContext()
	c.Now, c.IndependentFactor = c.Now.Add(time.Hour), true
	got, err := e.Evaluate(context.Background(), EvaluateRequest{Context: c, Phase: NonIssuing})
	if err != nil || got.Decision.Action != Allow {
		t.Fatal("request override altered server evaluation", err)
	}
}

func TestEvaluatorRejectsZeroNilCancelledAndInvalidClock(t *testing.T) {
	request := EvaluateRequest{Context: testContext(), Phase: NonIssuing}
	if _, err := (Evaluator{}).Evaluate(context.Background(), request); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatal("zero evaluator admitted")
	}
	e, err := NewEvaluator(evaluatorConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.Evaluate(nil, request); !errors.Is(err, ErrInvalidContext) {
		t.Fatal("nil context admitted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = e.Evaluate(ctx, request); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled context admitted")
	}
	request.Context.Tenant = ""
	if _, err = e.Evaluate(context.Background(), request); !errors.Is(err, ErrInvalidContext) {
		t.Fatal("empty scope admitted")
	}
	cfg := evaluatorConfig(t)
	cfg.Clock = func() time.Time { return time.Time{} }
	e, err = NewEvaluator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	request.Context = testContext()
	if _, err = e.Evaluate(context.Background(), request); !errors.Is(err, ErrInvalidContext) {
		t.Fatal("invalid clock admitted")
	}
	for _, value := range []any{request, &EvaluateError{cause: ErrInvalidSignal}} {
		for _, verb := range []string{"%v", "%#v", "%q", "%s"} {
			out := fmt.Sprintf(verb, value)
			if strings.Contains(out, "tenant") || strings.Contains(out, "attempt") {
				t.Fatal("evaluation metadata disclosure")
			}
		}
	}
}

func TestEvaluatorRealChildTimeoutCannotReturnCleanAndContextsAreClosed(t *testing.T) {
	cfg := evaluatorConfig(t)
	cfg.Clock, cfg.Timeout = time.Now, 100*time.Millisecond
	var children []context.Context
	for i := range cfg.Sources {
		name := cfg.Sources[i].Name
		cfg.Sources[i].Timeout = time.Millisecond
		cfg.Sources[i].Read = func(ctx context.Context, c Context) (Signal, error) {
			children = append(children, ctx)
			if name == "status" {
				<-ctx.Done()
			}
			return testSignal(c, name, SignalClean), nil
		}
	}
	e, err := NewEvaluator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	got, err := e.Evaluate(context.Background(), EvaluateRequest{Context: testContext(), Phase: NonIssuing})
	if err != nil || got.Decision.Action != Deny || got.assessment.Signals[0].State != SignalUnavailable {
		t.Fatal("timed-out source allowed", err)
	}
	for _, child := range children {
		if child.Err() == nil {
			t.Fatal("source child context retained live timer")
		}
	}
}
