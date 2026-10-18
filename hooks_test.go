package identity_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

type testHook struct {
	before func(context.Context, identity.BeforeHookInput) (identity.BeforeHookResult, error)
	after  func(context.Context, identity.AfterHookInput) error
}

func (h testHook) Before(ctx context.Context, in identity.BeforeHookInput) (identity.BeforeHookResult, error) {
	if h.before != nil {
		return h.before(ctx, in)
	}
	return identity.BeforeHookResult{Decision: identity.BeforeHookContinue}, nil
}
func (h testHook) After(ctx context.Context, in identity.AfterHookInput) error {
	if h.after != nil {
		return h.after(ctx, in)
	}
	return nil
}
func hookInput() identity.BeforeHookInput {
	return identity.BeforeHookInput{Context: identity.OperationContext{OperationID: "identity.email.verification-confirm", TenantID: "tenant", ActorID: "actor", CorrelationID: "verification"}, Fields: []identity.HookField{{Name: "identifier_id", Value: identity.AttributeScalar{Kind: identity.AttributeString, String: "identifier"}, Sensitivity: identity.SensitivitySensitive}}}
}
func hookConfig() identity.HookRunnerConfig {
	return identity.HookRunnerConfig{MaximumDuration: time.Second, Fields: []identity.HookFieldRegistration{{Name: "identifier_id", Kind: identity.AttributeString, Sensitivity: identity.SensitivitySensitive}, {Name: "annotation", Kind: identity.AttributeString, Sensitivity: identity.SensitivityPublic, Enrichment: true}}, Reasons: []identity.PolicyReason{"approved", "rejected"}}
}

func TestHookRunnerOrdersCopiesAndBoundsPreTransactionMetadata(t *testing.T) {
	var order []string
	input := hookInput()
	config := hookConfig()
	hooks := []identity.Hook{testHook{before: func(ctx context.Context, in identity.BeforeHookInput) (identity.BeforeHookResult, error) {
		order = append(order, "before-1")
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("callback unbounded")
		}
		in.Fields[0].Value.String = "cannot-mutate-original"
		return identity.BeforeHookResult{Decision: identity.BeforeHookContinue, Reasons: []identity.PolicyReason{"approved"}, Enrichments: []identity.HookEnrichment{{Fields: []identity.HookField{{Name: "annotation", Value: identity.AttributeScalar{Kind: identity.AttributeString, String: "approved"}, Sensitivity: identity.SensitivityPublic}}}}}, nil
	}}, testHook{before: func(_ context.Context, in identity.BeforeHookInput) (identity.BeforeHookResult, error) {
		order = append(order, "before-2")
		if in.Context != input.Context || len(in.Fields) != 2 || in.Fields[0].Value.String != "identifier" || in.Fields[1].Value.String != "approved" {
			t.Fatal("ordered input custody lost")
		}
		return identity.BeforeHookResult{Decision: identity.BeforeHookContinue}, nil
	}}}
	r, err := identity.NewHookRunner(hooks, config)
	if err != nil {
		t.Fatal(err)
	}
	hooks[1] = testHook{before: func(context.Context, identity.BeforeHookInput) (identity.BeforeHookResult, error) {
		t.Fatal("caller changed configured hooks")
		return identity.BeforeHookResult{}, nil
	}}
	config.Fields[0].Name = "other"
	out, err := r.Before(t.Context(), input)
	if err != nil || out.Decision != identity.BeforeHookContinue || len(out.Enrichments) != 1 || !reflect.DeepEqual(order, []string{"before-1", "before-2"}) || input.Fields[0].Value.String != "identifier" {
		t.Fatal("ordered bounded hook execution failed", err)
	}
}

func TestHookRunnerRejectsUnsafeResultsAndRedactsCallbackFailures(t *testing.T) {
	for _, variant := range []string{"reject", "error", "panic", "readonly", "unknown-field", "wrong-type", "secret", "unknown-reason", "oversized", "cancel"} {
		t.Run(variant, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			later := false
			h := testHook{before: func(context.Context, identity.BeforeHookInput) (identity.BeforeHookResult, error) {
				x := identity.BeforeHookResult{Decision: identity.BeforeHookContinue}
				switch variant {
				case "reject":
					x.Decision = identity.BeforeHookReject
					x.Reasons = []identity.PolicyReason{"rejected"}
				case "error":
					return x, errors.New("private callback diagnostic")
				case "panic":
					panic("private callback diagnostic")
				case "cancel":
					cancel()
				case "unknown-reason":
					x.Reasons = []identity.PolicyReason{"unregistered"}
				default:
					field := identity.HookField{Name: "annotation", Value: identity.AttributeScalar{Kind: identity.AttributeString, String: "accepted"}, Sensitivity: identity.SensitivityPublic}
					switch variant {
					case "readonly":
						field = hookInput().Fields[0]
					case "unknown-field":
						field.Name = "unregistered"
					case "wrong-type":
						field.Value.Kind = identity.AttributeBool
					case "secret":
						field.Sensitivity = identity.SensitivitySecret
					case "oversized":
						field.Value.String = strings.Repeat("a", 4097)
					}
					x.Enrichments = []identity.HookEnrichment{{Fields: []identity.HookField{field}}}
				}
				return x, nil
			}}
			r, err := identity.NewHookRunner([]identity.Hook{h, testHook{before: func(context.Context, identity.BeforeHookInput) (identity.BeforeHookResult, error) {
				later = true
				return identity.BeforeHookResult{Decision: identity.BeforeHookContinue}, nil
			}}}, hookConfig())
			if err != nil {
				t.Fatal(err)
			}
			out, err := r.Before(ctx, hookInput())
			if variant == "reject" {
				if err != nil || out.Decision != identity.BeforeHookReject {
					t.Fatal("valid rejection lost", err)
				}
			} else if err == nil || strings.Contains(err.Error(), "private") {
				t.Fatal("unsafe hook result admitted or disclosed", err)
			}
			if later {
				t.Fatal("invalid or rejected hook reached next callback")
			}
			if variant == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation lost", err)
			}
		})
	}
}

func TestHookRunnerRejectsCallbackReentryAndExpiredOperation(t *testing.T) {
	var runner *identity.HookRunner
	var nested error
	r, err := identity.NewHookRunner([]identity.Hook{testHook{before: func(ctx context.Context, in identity.BeforeHookInput) (identity.BeforeHookResult, error) {
		_, nested = runner.Before(ctx, in)
		return identity.BeforeHookResult{Decision: identity.BeforeHookContinue}, nil
	}}}, hookConfig())
	if err != nil {
		t.Fatal(err)
	}
	runner = r
	if _, err = r.Before(t.Context(), hookInput()); err != nil || nested == nil {
		t.Fatal("callback-context reentry permitted", err)
	}
	in := hookInput()
	in.Context.Deadline = time.Now().Add(-time.Second)
	if _, err = r.Before(t.Context(), in); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("expired original operation deadline renewed", err)
	}
}

func TestHookRunnerAfterIsOrderedAndConservesTerminalObservation(t *testing.T) {
	var order []int
	input := identity.AfterHookInput{Context: hookInput().Context, Observation: identity.HookObservation{Outcome: identity.AttemptedCommitOutcomeCommitted, Notes: []identity.PolicyReason{"approved"}}}
	r, err := identity.NewHookRunner([]identity.Hook{testHook{after: func(_ context.Context, in identity.AfterHookInput) error {
		order = append(order, 1)
		if in.Observation.Outcome != identity.AttemptedCommitOutcomeCommitted {
			t.Fatal("commit relabeled")
		}
		in.Observation.Notes[0] = "modified"
		return nil
	}}, testHook{after: func(_ context.Context, in identity.AfterHookInput) error {
		order = append(order, 2)
		if in.Observation.Notes[0] != "approved" {
			t.Fatal("observer mutated another input")
		}
		return errors.New("private observer diagnostic")
	}}}, hookConfig())
	if err != nil {
		t.Fatal(err)
	}
	if err = r.After(t.Context(), input); err == nil || strings.Contains(err.Error(), "private") || !reflect.DeepEqual(order, []int{1, 2}) || input.Observation.Outcome != identity.AttemptedCommitOutcomeCommitted || input.Observation.Notes[0] != "approved" {
		t.Fatal("observer failure corrupted outcome or disclosed diagnostic", err)
	}
}

func TestHookRunnerAfterRejectsNilNotesBeforeCallback(t *testing.T) {
	calls := 0
	r, err := identity.NewHookRunner([]identity.Hook{testHook{after: func(_ context.Context, in identity.AfterHookInput) error {
		calls++
		if in.Observation.Notes == nil {
			t.Fatal("explicit empty notes lost")
		}
		return nil
	}}}, hookConfig())
	if err != nil {
		t.Fatal(err)
	}
	in := identity.AfterHookInput{Context: hookInput().Context, Observation: identity.HookObservation{Outcome: identity.AttemptedCommitOutcomeCommitted}}
	if err := r.After(t.Context(), in); err == nil || calls != 0 {
		t.Fatal("nil observation notes reached callback")
	}
	in.Observation.Notes = []identity.PolicyReason{}
	if err := r.After(t.Context(), in); err != nil || calls != 1 {
		t.Fatal("explicit empty notes rejected", err)
	}
}

func TestHookRunnerRejectsMalformedRegistrationAndMetadata(t *testing.T) {
	for _, mutate := range []func(*identity.HookRunnerConfig){
		func(c *identity.HookRunnerConfig) { c.MaximumDuration = 0 },
		func(c *identity.HookRunnerConfig) { c.MaximumDuration = time.Minute + time.Nanosecond },
		func(c *identity.HookRunnerConfig) { c.Fields = append(c.Fields, c.Fields[0]) },
		func(c *identity.HookRunnerConfig) { c.Fields[0].Sensitivity = identity.SensitivitySecret },
		func(c *identity.HookRunnerConfig) { c.Fields[0].Kind = identity.AttributeStringList },
		func(c *identity.HookRunnerConfig) { c.Fields[0].Name = "id"; c.Fields[0].Enrichment = true },
		func(c *identity.HookRunnerConfig) { c.Reasons = []identity.PolicyReason{"same", "same"} },
		func(c *identity.HookRunnerConfig) { c.Reasons = []identity.PolicyReason{"private diagnostic"} },
	} {
		config := hookConfig()
		mutate(&config)
		if _, err := identity.NewHookRunner([]identity.Hook{testHook{}}, config); err == nil {
			t.Fatal("malformed hook policy admitted")
		}
	}
	var calls atomic.Int32
	r, err := identity.NewHookRunner([]identity.Hook{testHook{before: func(context.Context, identity.BeforeHookInput) (identity.BeforeHookResult, error) {
		calls.Add(1)
		return identity.BeforeHookResult{Decision: identity.BeforeHookContinue}, nil
	}}}, hookConfig())
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*identity.BeforeHookInput){
		func(x *identity.BeforeHookInput) { x.Context.TenantID = "" },
		func(x *identity.BeforeHookInput) { x.Context.CorrelationID = "unsafe\ncontext" },
		func(x *identity.BeforeHookInput) { x.Fields = append(x.Fields, x.Fields[0]) },
		func(x *identity.BeforeHookInput) { x.Fields[0].Value.String = strings.Repeat("a", 4097) },
		func(x *identity.BeforeHookInput) { x.Fields[0].Value.Bool = true },
	} {
		in := hookInput()
		mutate(&in)
		if _, err := r.Before(t.Context(), in); err == nil {
			t.Fatal("malformed metadata reached hooks")
		}
	}
	if calls.Load() != 0 {
		t.Fatal("malformed hook input invoked application callback")
	}
}

func TestHookRunnerConcurrentCallsHaveIndependentEnrichment(t *testing.T) {
	var calls atomic.Int32
	r, err := identity.NewHookRunner([]identity.Hook{testHook{before: func(context.Context, identity.BeforeHookInput) (identity.BeforeHookResult, error) {
		calls.Add(1)
		return identity.BeforeHookResult{Decision: identity.BeforeHookContinue}, nil
	}}}, hookConfig())
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 16 {
				if out, err := r.Before(t.Context(), hookInput()); err != nil || out.Decision != identity.BeforeHookContinue {
					t.Error("concurrent hook call failed", err)
				}
			}
		})
	}
	wg.Wait()
	if calls.Load() != 256 {
		t.Fatal("hook invocations were lost or duplicated")
	}
}

func FuzzHookRunnerBoundsTypedMetadata(f *testing.F) {
	f.Add("identifier", false)
	f.Add("\xff", false)
	f.Add("identifier", true)
	f.Fuzz(func(t *testing.T, value string, wrongArm bool) {
		if len(value) > 8192 {
			return
		}
		calls := 0
		r, err := identity.NewHookRunner([]identity.Hook{testHook{before: func(context.Context, identity.BeforeHookInput) (identity.BeforeHookResult, error) {
			calls++
			return identity.BeforeHookResult{Decision: identity.BeforeHookContinue}, nil
		}}}, hookConfig())
		if err != nil {
			t.Fatal(err)
		}
		in := hookInput()
		in.Fields[0].Value.String = value
		in.Fields[0].Value.Bool = wrongArm
		_, err = r.Before(t.Context(), in)
		if (len(value) > 4096 || wrongArm) && (err == nil || calls != 0) {
			t.Fatal("unbounded or mixed-arm metadata reached callback")
		}
		if err != nil && calls != 0 {
			t.Fatal("metadata rejected only after callback")
		}
	})
}
