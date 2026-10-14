package session_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

type setExecutor func(context.Context, session.RevokeSetRequest) (session.RevokeSetExecutionResult, error)

func (f setExecutor) ExecuteRevokeSet(ctx context.Context, r session.RevokeSetRequest) (session.RevokeSetExecutionResult, error) {
	return f(ctx, r)
}

func TestRevokeSetReceiptTargetsVersionedSourceNotUser(t *testing.T) {
	reader, input, _, observed, _, _ := validationFixture(t)
	spec, _ := observed.Session.Bindings()
	vector, _ := spec.Authority.Bindings()
	config := session.SetRevocationConfig{PolicyID: "policy", PolicyVersion: 1, MaximumSessions: 100, MaximumDuration: time.Second}
	executor := setExecutor(func(_ context.Context, request session.RevokeSetRequest) (session.RevokeSetExecutionResult, error) {
		command, _ := request.Command()
		set, _ := command.RevokeSet()
		if set.Binding.RecordID != spec.SessionID || set.Binding.UserID != spec.UserID {
			t.Fatal("receipt versions must describe the bound source record, not a different user record")
		}
		return session.RevokeSetExecutionResult{Receipt: identity.CommandResult{Binding: set.Binding, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "audit", Feature: &identity.FeatureReceipt{Operation: session.RevokeOtherOperation(), BeforeVersion: spec.Version, AfterVersion: spec.Version + 1}}, SubjectVersion: vector.User.Version}, nil
	})
	service, e := session.NewSetRevocationService(reader, executor, config)
	if e != nil {
		t.Fatal(e)
	}
	out, e := service.RevokeOther(context.Background(), session.RevokeOtherInput{TenantID: input.TenantID, Credential: input.Credential, CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", CorrelationID: "correlation"})
	if e != nil || out.Recovery.RecordID != spec.SessionID || out.SessionVersion != spec.Version+1 {
		t.Fatal("source-bound receipt", e)
	}
}

func TestRevokeSetPreservesKnownCommitWhenMetadataReadFails(t *testing.T) {
	for _, mode := range []string{"other", "all-preserve", "all-include"} {
		t.Run(mode, func(t *testing.T) {
			reader, input, _, observed, _, _ := validationFixture(t)
			spec, _ := observed.Session.Bindings()
			vector, _ := spec.Authority.Bindings()
			all := mode != "other"
			b := setBinding(spec, all)
			op := session.RevokeOtherOperation()
			if all {
				op = session.RevokeAllOperation()
			}
			executor := setExecutor(func(context.Context, session.RevokeSetRequest) (session.RevokeSetExecutionResult, error) {
				return session.RevokeSetExecutionResult{Receipt: identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "audit", Feature: &identity.FeatureReceipt{Operation: op, BeforeVersion: spec.Version, AfterVersion: spec.Version + 1}}}, errors.New("private retained metadata read failure")
			})
			service, err := session.NewSetRevocationService(reader, executor, session.SetRevocationConfig{PolicyID: b.PolicyID, PolicyVersion: b.PolicyVersion, MaximumSessions: 100, MaximumDuration: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			var out session.RevokeSetResult
			if all {
				out, err = service.RevokeAll(context.Background(), session.RevokeAllInput{TenantID: input.TenantID, Credential: input.Credential, CommandID: b.CommandID, CorrelationID: b.CorrelationID, ExpectedSubjectVersion: vector.User.Version, IncludeCurrent: mode == "all-include"})
			} else {
				out, err = service.RevokeOther(context.Background(), session.RevokeOtherInput{TenantID: input.TenantID, Credential: input.Credential, CommandID: b.CommandID, CorrelationID: b.CorrelationID})
			}
			if !errors.Is(err, session.ErrUnavailable) || out.CommitOutcome != identity.CommitOutcomeCommitted || out.RevokedCount != 0 || out.SubjectVersion != 0 || out.SessionVersion != 0 || out.CurrentSessionRevoked || out.Recovery.RecordID != spec.SessionID || strings.Contains(err.Error(), "private") {
				t.Fatal("known commit lost or success metadata manufactured", out.CommitOutcome, err)
			}
		})
	}
}

func TestRevokeSetServiceAuthenticatesDerivesSourceAndConservesExactReceipt(t *testing.T) {
	for _, mode := range []string{"other", "all-preserve", "all-include"} {
		t.Run(mode, func(t *testing.T) {
			reader, input, clock, observed, _, _ := validationFixture(t)
			spec, _ := observed.Session.Bindings()
			vector, _ := spec.Authority.Bindings()
			all := mode != "other"
			include := mode == "all-include"
			b := setBinding(spec, all)
			calls := 0
			executor := setExecutor(func(ctx context.Context, r session.RevokeSetRequest) (session.RevokeSetExecutionResult, error) {
				calls++
				if r.Validate(reader, clock.now) != nil || r.Caller() != observed.Session {
					t.Fatal("source custody")
				}
				c, ok := r.Command()
				set, ok2 := c.RevokeSet()
				if !ok || !ok2 || set.Binding != b || set.IncludeCurrent != include || set.MaximumSessions != 100 {
					t.Fatal("source/disposition substituted")
				}
				op := session.RevokeOtherOperation()
				if all {
					op = session.RevokeAllOperation()
				}
				return session.RevokeSetExecutionResult{Receipt: identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "audit", Feature: &identity.FeatureReceipt{Operation: op, BeforeVersion: spec.Version, AfterVersion: spec.Version + 1}}, RevokedCount: 2, SubjectVersion: vector.User.Version, CurrentSessionRevoked: include}, nil
			})
			service, e := session.NewSetRevocationService(reader, executor, session.SetRevocationConfig{PolicyID: b.PolicyID, PolicyVersion: b.PolicyVersion, MaximumSessions: 100, MaximumDuration: time.Second})
			if e != nil {
				t.Fatal(e)
			}
			var out session.RevokeSetResult
			if all {
				out, e = service.RevokeAll(context.Background(), session.RevokeAllInput{TenantID: input.TenantID, Credential: input.Credential, CommandID: b.CommandID, CorrelationID: b.CorrelationID, IncludeCurrent: include, ExpectedSubjectVersion: vector.User.Version})
			} else {
				out, e = service.RevokeOther(context.Background(), session.RevokeOtherInput{TenantID: input.TenantID, Credential: input.Credential, CommandID: b.CommandID, CorrelationID: b.CorrelationID})
			}
			if e != nil || calls != 1 || out.CommitOutcome != identity.CommitOutcomeCommitted || out.RevokedCount != 2 || out.SubjectVersion != vector.User.Version || out.SessionVersion != spec.Version+1 || out.CurrentSessionRevoked != include || out.Recovery.UserID != spec.UserID || out.Recovery.RecordID != spec.SessionID {
				t.Fatal("exact result", e)
			}
		})
	}
}

func TestRevokeSetServiceRejectsMalformedOrUnknownExecutionWithoutSuccess(t *testing.T) {
	for _, mode := range []string{"receipt-absent", "wrong-binding", "wrong-operation", "wrong-version", "count", "subject", "disposition", "unknown", "panic", "cancel", "missing-metadata", "partial-metadata-error", "missing-metadata-error-wrong-version"} {
		t.Run(mode, func(t *testing.T) {
			reader, input, _, observed, _, _ := validationFixture(t)
			spec, _ := observed.Session.Bindings()
			b := setBinding(spec, false)
			v, _ := spec.Authority.Bindings()
			ctx, stop := context.WithCancel(context.Background())
			defer stop()
			executor := setExecutor(func(context.Context, session.RevokeSetRequest) (session.RevokeSetExecutionResult, error) {
				r := session.RevokeSetExecutionResult{Receipt: identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "audit", Feature: &identity.FeatureReceipt{Operation: session.RevokeOtherOperation(), BeforeVersion: spec.Version, AfterVersion: spec.Version + 1}}, RevokedCount: 2, SubjectVersion: v.User.Version}
				var cause error
				switch mode {
				case "receipt-absent":
					r.Receipt = identity.CommandResult{}
				case "wrong-binding":
					r.Receipt.Binding.UserID = "foreign"
				case "wrong-operation":
					r.Receipt.Feature.Operation = session.RevokeAllOperation()
				case "wrong-version":
					r.Receipt.Feature.BeforeVersion++
					r.Receipt.Feature.AfterVersion++
				case "count":
					r.RevokedCount = 101
				case "subject":
					r.SubjectVersion++
				case "disposition":
					r.CurrentSessionRevoked = true
				case "unknown":
					r = session.RevokeSetExecutionResult{Receipt: identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeUnknown, Feature: &identity.FeatureReceipt{Operation: session.RevokeOtherOperation()}}}
				case "panic":
					panic("dependency")
				case "cancel":
					stop()
				case "missing-metadata":
					r.RevokedCount, r.SubjectVersion = 0, 0
				case "partial-metadata-error":
					r.SubjectVersion = 0
					cause = errors.New("metadata failed")
				case "missing-metadata-error-wrong-version":
					r.RevokedCount, r.SubjectVersion = 0, 0
					r.Receipt.Feature.BeforeVersion++
					r.Receipt.Feature.AfterVersion++
					cause = errors.New("metadata failed")
				}
				return r, cause
			})
			service, e := session.NewSetRevocationService(reader, executor, session.SetRevocationConfig{PolicyID: b.PolicyID, PolicyVersion: b.PolicyVersion, MaximumSessions: 100, MaximumDuration: time.Second})
			if e != nil {
				t.Fatal(e)
			}
			out, e := service.RevokeOther(ctx, session.RevokeOtherInput{TenantID: input.TenantID, Credential: input.Credential, CommandID: b.CommandID, CorrelationID: b.CorrelationID})
			if e == nil || out.RevokedCount != 0 || out.CurrentSessionRevoked || out.SessionVersion != 0 {
				t.Fatal("invalid execution became success", mode, e)
			}
		})
	}
}

func TestRevokeSetServiceDeniedBeforeExecutionAndPreservesKnownNoncommit(t *testing.T) {
	reader, input, _, observed, _, _ := validationFixture(t)
	spec, _ := observed.Session.Bindings()
	b := setBinding(spec, false)
	calls := 0
	executor := setExecutor(func(context.Context, session.RevokeSetRequest) (session.RevokeSetExecutionResult, error) {
		calls++
		return session.RevokeSetExecutionResult{}, identity.ForbiddenError{}
	})
	service, e := session.NewSetRevocationService(reader, executor, session.SetRevocationConfig{PolicyID: b.PolicyID, PolicyVersion: b.PolicyVersion, MaximumSessions: 100, MaximumDuration: time.Second})
	if e != nil {
		t.Fatal(e)
	}
	request := session.RevokeOtherInput{TenantID: input.TenantID, Credential: input.Credential, CommandID: b.CommandID, CorrelationID: b.CorrelationID}
	if _, e = service.RevokeOther(context.Background(), request); e == nil || calls != 1 {
		t.Fatal("policy denial ignored")
	}
	observed.Active = false
	if _, e = service.RevokeOther(context.Background(), request); !errors.Is(e, session.ErrUnauthenticated) || calls != 1 {
		t.Fatal("inactive caller reached execution", e)
	}
	if _, e = service.RevokeOther(nil, request); !errors.Is(e, session.ErrInvalidInput) {
		t.Fatal("nil context")
	}
}

func TestRevokeSetServicePreservesNoncommittedOutcomesAndRecovery(t *testing.T) {
	for _, outcome := range []identity.CommitOutcome{identity.CommitOutcomeNotCommitted, identity.CommitOutcomeConflict, identity.CommitOutcomeInProgress, identity.CommitOutcomeUnknown} {
		t.Run(fmt.Sprint(uint8(outcome)), func(t *testing.T) {
			reader, input, _, observed, _, _ := validationFixture(t)
			spec, _ := observed.Session.Bindings()
			b := setBinding(spec, false)
			retry := time.Duration(0)
			if outcome == identity.CommitOutcomeInProgress {
				retry = time.Second
			}
			executor := setExecutor(func(context.Context, session.RevokeSetRequest) (session.RevokeSetExecutionResult, error) {
				return session.RevokeSetExecutionResult{Receipt: identity.CommandResult{Binding: b, Outcome: outcome, RetryAfter: retry, Feature: &identity.FeatureReceipt{Operation: session.RevokeOtherOperation()}}}, nil
			})
			service, e := session.NewSetRevocationService(reader, executor, session.SetRevocationConfig{PolicyID: b.PolicyID, PolicyVersion: b.PolicyVersion, MaximumSessions: 100, MaximumDuration: time.Second})
			if e != nil {
				t.Fatal(e)
			}
			out, e := service.RevokeOther(context.Background(), session.RevokeOtherInput{TenantID: input.TenantID, Credential: input.Credential, CommandID: b.CommandID, CorrelationID: b.CorrelationID})
			if e == nil || out.CommitOutcome != outcome || out.RetryAfter != retry || out.Recovery.RecordID != spec.SessionID || out.RevokedCount != 0 || out.SubjectVersion != 0 || out.SessionVersion != 0 || out.CurrentSessionRevoked {
				t.Fatal("durable noncommit changed", e)
			}
			var notCommitted identity.NotCommittedError
			var conflict identity.ConflictError
			var inProgress identity.InProgressError
			var unknown identity.UnknownCommitError
			if outcome == identity.CommitOutcomeNotCommitted && !errors.As(e, &notCommitted) || outcome == identity.CommitOutcomeConflict && !errors.As(e, &conflict) || outcome == identity.CommitOutcomeInProgress && !errors.As(e, &inProgress) || outcome == identity.CommitOutcomeUnknown && !errors.As(e, &unknown) {
				t.Fatal("wrong error classification", e)
			}
		})
	}
}

func TestRevokeSetServiceSubjectCASDeniesWithoutMutation(t *testing.T) {
	reader, input, _, observed, _, _ := validationFixture(t)
	spec, _ := observed.Session.Bindings()
	vector, _ := spec.Authority.Bindings()
	b := setBinding(spec, true)
	executor := setExecutor(func(context.Context, session.RevokeSetRequest) (session.RevokeSetExecutionResult, error) {
		t.Fatal("mismatched subject CAS reached mutation")
		return session.RevokeSetExecutionResult{}, nil
	})
	service, e := session.NewSetRevocationService(reader, executor, session.SetRevocationConfig{PolicyID: b.PolicyID, PolicyVersion: b.PolicyVersion, MaximumSessions: 100, MaximumDuration: time.Second})
	if e != nil {
		t.Fatal(e)
	}
	for _, version := range []uint64{0, vector.User.Version + 1} {
		out, e := service.RevokeAll(context.Background(), session.RevokeAllInput{TenantID: input.TenantID, Credential: input.Credential, CommandID: b.CommandID, CorrelationID: b.CorrelationID, ExpectedSubjectVersion: version})
		var conflict identity.ConflictError
		if version == 0 && !errors.Is(e, session.ErrInvalidInput) || version != 0 && !errors.As(e, &conflict) || out.CommitOutcome != identity.CommitOutcomeInvalid || out.Recovery != (identity.RecoveryQuery{}) {
			t.Fatal("subject mismatch became reserved", e)
		}
	}
}

func TestRevokeSetServiceRedactsDependencyErrorsAndKeepsReceiptClassification(t *testing.T) {
	for _, mode := range []string{"denied", "freshness", "notcommitted", "conflict", "inprogress", "unknown", "cancelled", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			reader, input, _, observed, _, _ := validationFixture(t)
			spec, _ := observed.Session.Bindings()
			b := setBinding(spec, false)
			outcome := identity.CommitOutcomeNotCommitted
			var cause error = errors.New("private dependency detail")
			switch mode {
			case "denied":
				cause = fmt.Errorf("private dependency detail: %w", identity.ForbiddenError{})
				outcome = identity.CommitOutcomeInvalid
			case "freshness":
				cause = fmt.Errorf("private dependency detail: %w", session.ErrFreshnessRequired)
				outcome = identity.CommitOutcomeInvalid
			case "conflict":
				outcome = identity.CommitOutcomeConflict
			case "inprogress":
				outcome = identity.CommitOutcomeInProgress
			case "unknown":
				outcome = identity.CommitOutcomeUnknown
			case "cancelled":
				cause = fmt.Errorf("private dependency detail: %w", context.Canceled)
			case "deadline":
				cause = fmt.Errorf("private dependency detail: %w", context.DeadlineExceeded)
			}
			retry := time.Duration(0)
			if outcome == identity.CommitOutcomeInProgress {
				retry = time.Second
			}
			executor := setExecutor(func(context.Context, session.RevokeSetRequest) (session.RevokeSetExecutionResult, error) {
				if outcome == identity.CommitOutcomeInvalid {
					return session.RevokeSetExecutionResult{}, cause
				}
				return session.RevokeSetExecutionResult{Receipt: identity.CommandResult{Binding: b, Outcome: outcome, RetryAfter: retry, Feature: &identity.FeatureReceipt{Operation: session.RevokeOtherOperation()}}}, cause
			})
			service, e := session.NewSetRevocationService(reader, executor, session.SetRevocationConfig{PolicyID: b.PolicyID, PolicyVersion: b.PolicyVersion, MaximumSessions: 100, MaximumDuration: time.Second})
			if e != nil {
				t.Fatal(e)
			}
			out, e := service.RevokeOther(context.Background(), session.RevokeOtherInput{TenantID: input.TenantID, Credential: input.Credential, CommandID: b.CommandID, CorrelationID: b.CorrelationID})
			if e == nil || strings.Contains(e.Error(), "private dependency detail") || out.CommitOutcome != outcome || out.RetryAfter != retry {
				t.Fatal("dependency disclosure or receipt changed", e)
			}
			var forbidden identity.ForbiddenError
			var notCommitted identity.NotCommittedError
			var conflict identity.ConflictError
			var inProgress identity.InProgressError
			var unknown identity.UnknownCommitError
			var cancelled identity.CancelledError
			var deadline identity.DeadlineExceededError
			if mode == "denied" && !errors.As(e, &forbidden) || mode == "freshness" && !errors.Is(e, session.ErrFreshnessRequired) || mode == "notcommitted" && !errors.As(e, &notCommitted) || mode == "conflict" && !errors.As(e, &conflict) || mode == "inprogress" && (!errors.As(e, &inProgress) || inProgress.RetryAfter != retry || inProgress.CommandID != b.CommandID) || mode == "unknown" && !errors.As(e, &unknown) || mode == "cancelled" && !errors.As(e, &cancelled) || mode == "deadline" && !errors.As(e, &deadline) {
				t.Fatal("lost error classification", e)
			}
			if errors.Is(e, cause) {
				t.Fatal("private cause retained")
			}
		})
	}
}
