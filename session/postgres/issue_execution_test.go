package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	authorization "github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func TestOwnedIssueExecutorRejectsIncompleteComposition(t *testing.T) {
	if executor, err := NewIssueExecutor(nil, IssueExecutorConfig{}); executor != nil || err == nil {
		t.Fatal("incomplete composition admitted")
	}
	var executor *IssueExecutor
	for _, run := range []func(context.Context, session.IssueRequest) (session.IssueExecution, error){executor.ExecuteIssue, executor.RecoverIssue} {
		if result, err := run(context.Background(), session.IssueRequest{}); err == nil || result.Receipt.Outcome != 0 {
			t.Fatal("zero executor gained an outcome")
		}
	}
}

func TestOwnedIssueRestartRecoveryRejectsZero(t *testing.T) {
	var executor *IssueExecutor
	result, err := executor.RecoverIssueCommand(context.Background(), identity.RecoveryQuery{}, authorization.DecisionContext{})
	if err == nil || result.Binding.CommandID != "" || result.Outcome != identity.CommitOutcomeInvalid {
		t.Fatal("zero recovery gained historical authority")
	}
}

func TestOwnedIssueExecutorRejectsTypedNilDependencies(t *testing.T) {
	var policy issueDecision
	var pointer *IssueExecutor
	for _, dependency := range []any{nil, policy, pointer} {
		if !nilIssueDependency(dependency) {
			t.Fatal("typed nil accepted")
		}
	}
}

type issueDecision func(context.Context, authorization.DecisionContext) (authorization.Decision, error)

func (f issueDecision) Decide(ctx context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
	return f(ctx, dc)
}

type issueTestClock struct {
	clock.Clock
	now      time.Time
	panicNow bool
}

func (c issueTestClock) Now() time.Time {
	if c.panicNow {
		panic("private")
	}
	return c.now
}

func TestOwnedIssueExecutorRejectsInvalidPolicyClock(t *testing.T) {
	for _, now := range []time.Time{{}, time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)} {
		calls := 0
		e := &IssueExecutor{clock: issueTestClock{now: now}, authorize: issueDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
			calls++
			return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
		})}
		if err := e.allow(context.Background(), authorization.DecisionContext{PolicyRevision: 1}); !errors.Is(err, session.ErrIssuerUnavailable) || calls != 0 {
			t.Fatal("invalid trusted time reached authorization", err)
		}
	}
}

func TestOwnedIssueExecutorPreservesCurrentPolicyFailures(t *testing.T) {
	for _, mode := range []string{"allow", "deny", "revision", "error", "panic", "clock-panic", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			ctx, stop := context.WithCancel(context.Background())
			defer stop()
			e := &IssueExecutor{clock: issueTestClock{now: time.Now(), panicNow: mode == "clock-panic"}, authorize: issueDecision(func(_ context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
				if dc.Request.Environment.Time.IsZero() {
					t.Fatal("trusted time omitted")
				}
				switch mode {
				case "deny":
					return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, nil
				case "revision":
					return authorization.Decision{Outcome: authorization.Allow, Revision: 2}, nil
				case "error":
					return authorization.Decision{}, errors.New("private")
				case "panic":
					panic("private")
				case "cancel":
					stop()
				}
				return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
			})}
			err := e.allow(ctx, authorization.DecisionContext{PolicyRevision: 1})
			switch mode {
			case "allow":
				if err != nil {
					t.Fatal(err)
				}
			case "deny", "revision":
				var denied identity.ForbiddenError
				if !errors.As(err, &denied) {
					t.Fatal("lost denial")
				}
			case "cancel":
				var cancelled identity.CancelledError
				if !errors.As(err, &cancelled) {
					t.Fatal("lost cancellation")
				}
			default:
				if !errors.Is(err, session.ErrIssuerUnavailable) {
					t.Fatal("private failure escaped")
				}
			}
		})
	}
}
