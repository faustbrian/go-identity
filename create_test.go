package identity

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
)

type creationMemoryOwner struct {
	mu              sync.Mutex
	commands        map[CommandID]CreateUserCommand
	results         map[CommandID]CommandResult
	users           map[string]User
	audits          map[CommandID]string
	loseCommitReply bool
}

func (m *creationMemoryOwner) Execute(ctx context.Context, command Command) (CommandResult, error) {
	if _, ok := ctx.Deadline(); !ok {
		panic("unbounded execute")
	}
	spec, ok := command.CreateUser()
	if !ok {
		panic("invalid command")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if old, ok := m.commands[spec.Binding.CommandID]; ok {
		if !reflect.DeepEqual(old, spec) {
			return CommandResult{Binding: spec.Binding, Outcome: CommitOutcomeConflict}, nil
		}
		return m.results[spec.Binding.CommandID], nil
	}
	key := string(spec.Binding.TenantID) + "/" + string(spec.Binding.UserID)
	if _, ok := m.users[key]; ok {
		return CommandResult{Binding: spec.Binding, Outcome: CommitOutcomeConflict}, nil
	}
	user := User{ID: spec.Binding.UserID, TenantID: spec.Binding.TenantID, Status: spec.Status, Version: 1}
	result := CommandResult{Binding: spec.Binding, Outcome: CommitOutcomeCommitted, User: user, AuditEventID: "audit-event-1"}
	// One synchronization owner models the core's atomic seam only. These maps
	// do not prove PostgreSQL reservation, crash recovery, CBOR or durable audit.
	m.users[key] = user
	m.commands[spec.Binding.CommandID] = spec
	m.results[spec.Binding.CommandID] = result
	m.audits[spec.Binding.CommandID] = result.AuditEventID
	if m.loseCommitReply {
		return CommandResult{Binding: spec.Binding, Outcome: CommitOutcomeUnknown}, errors.New("sensitive transport error")
	}
	return result, nil
}

func (m *creationMemoryOwner) Recover(ctx context.Context, q RecoveryQuery) (CommandResult, error) {
	if _, ok := ctx.Deadline(); !ok {
		panic("unbounded recovery")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.results[q.CommandID]
	if !ok {
		return CommandResult{Binding: CommandBinding{CommandID: q.CommandID, TenantID: q.TenantID, UserID: q.UserID, ActorID: q.ActorID, ActorKind: q.ActorKind, OperationID: "identity.user.create", PolicyID: "identity-read", PolicyVersion: 1, SchemaID: "profile", SchemaVersion: 1, CorrelationID: string(q.CommandID)}, Outcome: CommitOutcomeNotCommitted}, nil
	}
	if r.Binding.TenantID != q.TenantID || r.Binding.UserID != q.UserID || r.Binding.ActorID != q.ActorID || r.Binding.ActorKind != q.ActorKind {
		return CommandResult{}, errors.New("foreign command")
	}
	return r, nil
}

func creationFixture(t *testing.T) (*UserCreationService, *creationMemoryOwner, UserCreateRequest) {
	t.Helper()
	f := newQueryFixture(t)
	field := attributeField("display_name", AttributeString)
	field.WriteAuthorization = FieldWriteAdministrator
	store := &creationMemoryOwner{commands: make(map[CommandID]CreateUserCommand), results: make(map[CommandID]CommandResult), users: make(map[string]User), audits: make(map[CommandID]string)}
	s, err := NewUserCreationService(store, f.service.authorize, queryRedact, UserCreationConfig{
		Query: f.service.config, Schema: AttributeSchema{ID: "profile", Version: 1, Fields: []FieldPolicy{field}},
		Normalize: func(context.Context, NormalizationPolicy, AttributeScalar) (AttributeScalar, error) {
			panic("NormalizeNone should not call normalizer")
		},
		ValidateValue: func(context.Context, FieldPolicy, AttributeValue) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	req := UserCreateRequest{CommandID: CommandID("AQEBAQEBAQEBAQEBAQEBAQ"), TenantID: "tenant-a", UserID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", SchemaVersion: 1, Fields: []AttributeUpdate{{Name: "display_name", Value: attributeString("public-example")}}, ActorScope: f.request.Context}
	req.ActorScope.Request.Action = "identity.user.create"
	return s, store, req
}

func TestUserCreateReplaysOneOwnedUserAndAuditAndConflictsOnChangedInput(t *testing.T) {
	s, store, req := creationFixture(t)
	first, err := s.UserCreate(context.Background(), req)
	if err != nil || first.CommitOutcome != CommitOutcomeCommitted || first.User.ID != req.UserID || first.User.Version != 1 {
		t.Fatalf("create = %+v, %v", first, err)
	}
	again, err := s.UserCreate(context.Background(), req)
	if err != nil || again != first || len(store.users) != 1 || len(store.audits) != 1 {
		t.Fatal("same command did not replay a single effect")
	}
	req.Fields[0].Value = attributeString("changed")
	got, err := s.UserCreate(context.Background(), req)
	var conflict ConflictError
	if !errors.As(err, &conflict) || got.CommitOutcome != CommitOutcomeConflict || got.User != (User{}) || len(store.audits) != 1 {
		t.Fatal("changed command did not conflict without another effect")
	}
}

func TestUserCreateRecoversLostCommitReplyWithoutCreatingAgain(t *testing.T) {
	s, store, req := creationFixture(t)
	store.loseCommitReply = true
	got, err := s.UserCreate(context.Background(), req)
	var unknown UnknownCommitError
	if !errors.As(err, &unknown) || got.CommitOutcome != CommitOutcomeUnknown || got.User != (User{}) || len(store.users) != 1 {
		t.Fatal("ambiguous commit was reported as rollback or success")
	}
	recovered, err := s.RecoverUserCreate(context.Background(), UserCreateRecoveryRequest{CommandID: req.CommandID, TenantID: req.TenantID, UserID: req.UserID, ActorScope: req.ActorScope})
	if err != nil || recovered.CommitOutcome != CommitOutcomeCommitted || recovered.User.ID != req.UserID || len(store.audits) != 1 {
		t.Fatalf("recovery = %+v %v", recovered, err)
	}
}

type creationOwnerFunc struct {
	execute func(context.Context, Command) (CommandResult, error)
	recover func(context.Context, RecoveryQuery) (CommandResult, error)
}

func (f creationOwnerFunc) Execute(ctx context.Context, c Command) (CommandResult, error) {
	return f.execute(ctx, c)
}
func (f creationOwnerFunc) Recover(ctx context.Context, q RecoveryQuery) (CommandResult, error) {
	return f.recover(ctx, q)
}

func TestUserCreateWithholdsOutputButPreservesKnownCommitAfterCancellation(t *testing.T) {
	s, store, req := creationFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.uow = creationOwnerFunc{execute: func(ctx context.Context, c Command) (CommandResult, error) {
		r, e := store.Execute(ctx, c)
		cancel()
		return r, e
	}, recover: store.Recover}
	got, err := s.UserCreate(ctx, req)
	if got.CommitOutcome != CommitOutcomeCommitted || got.User != (User{}) || !errors.Is(err, context.Canceled) || len(store.audits) != 1 {
		t.Fatal("cancellation was confused with authoritative rollback")
	}
}

func TestUserCreatePanicDuringExecutionRemainsUnknownAndRecoverable(t *testing.T) {
	s, store, req := creationFixture(t)
	s.uow = creationOwnerFunc{execute: func(ctx context.Context, c Command) (CommandResult, error) {
		_, _ = store.Execute(ctx, c)
		panic("sensitive after-commit failure")
	}, recover: store.Recover}
	got, err := s.UserCreate(context.Background(), req)
	var unknown UnknownCommitError
	if got.CommitOutcome != CommitOutcomeUnknown || got.User != (User{}) || !errors.As(err, &unknown) || strings.Contains(err.Error(), "sensitive") {
		t.Fatal("panic falsely classified a possible commit")
	}
	got, err = s.RecoverUserCreate(context.Background(), UserCreateRecoveryRequest{CommandID: req.CommandID, TenantID: req.TenantID, UserID: req.UserID, ActorScope: req.ActorScope})
	if err != nil || got.CommitOutcome != CommitOutcomeCommitted || len(store.audits) != 1 {
		t.Fatal("panic outcome not recovered through same command")
	}
}

func TestUserCreateSamplesOneClockAndNeverWritesAfterDeniedFields(t *testing.T) {
	s, store, req := creationFixture(t)
	samples := 0
	s.policy.config.Clock = attributeClockFunc(func() time.Time { samples++; return (queryClock{}).Now() })
	if _, err := s.UserCreate(context.Background(), req); err != nil || samples != 1 {
		t.Fatalf("clock samples=%d error=%v", samples, err)
	}
	s, store, req = creationFixture(t)
	s.policy.authorize = attributeDecisionFunc(func(ctx context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
		return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, nil
	})
	s.attributes.authorize = s.policy.authorize
	got, err := s.UserCreate(context.Background(), req)
	if err == nil || got.CommitOutcome != CommitOutcomeInvalid || len(store.users) != 0 || len(store.audits) != 0 {
		t.Fatal("denied field reached mutation or asserted a durable outcome")
	}
}

func TestUserCreateRechecksRedactionOnCommittedReplay(t *testing.T) {
	s, store, req := creationFixture(t)
	if _, err := s.UserCreate(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	s.policy.redact = func(context.Context, RedactionPolicyInput) (RedactionPolicyDecision, error) {
		return RedactionPolicyDecision{}, errors.New("private detail")
	}
	got, err := s.UserCreate(context.Background(), req)
	var forbidden ForbiddenError
	if !errors.As(err, &forbidden) || got.CommitOutcome != CommitOutcomeCommitted || got.User != (User{}) || len(store.audits) != 1 || strings.Contains(err.Error(), "private") {
		t.Fatal("replay disclosed stale-policy output or lost commit classification")
	}
}

func TestUserCreateCommandCopiesPayloadAndRedactsEveryFormattingPath(t *testing.T) {
	s, store, req := creationFixture(t)
	var captured Command
	s.uow = creationOwnerFunc{execute: func(ctx context.Context, c Command) (CommandResult, error) {
		captured = c
		return store.Execute(ctx, c)
	}, recover: store.Recover}
	if _, err := s.UserCreate(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	spec, ok := captured.CreateUser()
	if !ok {
		t.Fatal("missing command variant")
	}
	spec.Attributes[0].Value.Scalar.String = "mutated"
	again, _ := captured.CreateUser()
	if again.Attributes[0].Value.Scalar.String != "public-example" {
		t.Fatal("command accessor aliases retained values")
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%x"} {
		if strings.Contains(fmt.Sprintf(format, captured), "public-example") {
			t.Fatal("command formatting exposes field content")
		}
	}
	if _, err := json.Marshal(captured); err == nil {
		t.Fatal("opaque command silently serialized")
	}
	if _, ok := (Command{}).CreateUser(); ok {
		t.Fatal("zero command is usable")
	}
}

func TestUserCreateRejectsScopeAndInvalidInputBeforeStorage(t *testing.T) {
	for name, change := range map[string]func(*UserCreateRequest){
		"tenant":          func(r *UserCreateRequest) { r.TenantID = "foreign" },
		"target":          func(r *UserCreateRequest) { r.UserID = "foreign" },
		"command":         func(r *UserCreateRequest) { r.CommandID = "" },
		"padded command":  func(r *UserCreateRequest) { r.CommandID += "=" },
		"schema":          func(r *UserCreateRequest) { r.SchemaVersion = 2 },
		"fields":          func(r *UserCreateRequest) { r.Fields[0].Name = "unknown" },
		"too many fields": func(r *UserCreateRequest) { r.Fields = make([]AttributeUpdate, 65) },
		"action":          func(r *UserCreateRequest) { r.ActorScope.Request.Action = "identity.user.get" },
	} {
		t.Run(name, func(t *testing.T) {
			s, store, r := creationFixture(t)
			change(&r)
			got, err := s.UserCreate(context.Background(), r)
			if err == nil || got.User != (User{}) || got.CommitOutcome != CommitOutcomeInvalid || len(store.users) != 0 {
				t.Fatal("invalid input reached storage")
			}
		})
	}
}

func TestUserCreatePostCommitProjectionPanicPreservesKnownCommit(t *testing.T) {
	s, store, req := creationFixture(t)
	s.policy.redact = func(context.Context, RedactionPolicyInput) (RedactionPolicyDecision, error) {
		panic("private projection failure")
	}
	got, err := s.UserCreate(context.Background(), req)
	if got.CommitOutcome != CommitOutcomeCommitted || got.User != (User{}) || err == nil || len(store.audits) != 1 {
		t.Fatal("post-commit projection panic erased authoritative commit")
	}
}

func TestUserCreateDeniedReplayDoesNotClaimOriginalCommandRolledBack(t *testing.T) {
	s, store, req := creationFixture(t)
	if _, err := s.UserCreate(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	s.attributes.authorize = attributeDecisionFunc(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
		return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, nil
	})
	got, err := s.UserCreate(context.Background(), req)
	if err == nil || got.CommitOutcome != CommitOutcomeInvalid || len(store.users) != 1 || len(store.audits) != 1 {
		t.Fatal("denied replay inferred rollback without an authoritative observation")
	}
}

func TestUserCreateCannotSpoofRecoveryAdmission(t *testing.T) {
	s, store, req := creationFixture(t)
	req.ActorScope.Request.Resource.Attributes = authorization.Attributes{"identity.command.recovery": authorization.BoolValue(true)}
	s.attributes.authorize = attributeDecisionFunc(func(ctx context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
		recovery, _ := dc.Request.Resource.Attributes["identity.command.recovery"].Bool()
		if recovery {
			return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
		}
		return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, nil
	})
	got, err := s.UserCreate(context.Background(), req)
	if err == nil || got.User != (User{}) || len(store.users) != 0 {
		t.Fatal("creation was admitted with forged recovery metadata")
	}
}

func TestUserCreateConcurrentReplayHasOneMutationAndAudit(t *testing.T) {
	s, store, req := creationFixture(t)
	var group sync.WaitGroup
	for i := 0; i < 20; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			got, err := s.UserCreate(context.Background(), req)
			if err != nil || got.CommitOutcome != CommitOutcomeCommitted || got.User.ID != req.UserID {
				t.Error("concurrent replay failed")
			}
		}()
	}
	group.Wait()
	if len(store.users) != 1 || len(store.audits) != 1 || len(store.commands) != 1 {
		t.Fatal("concurrent command produced multiple effects")
	}
}

func TestUserCreateRecoveryUsesCurrentPolicyAndOriginalActorScope(t *testing.T) {
	s, store, req := creationFixture(t)
	if _, err := s.UserCreate(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	recovery := UserCreateRecoveryRequest{CommandID: req.CommandID, TenantID: req.TenantID, UserID: req.UserID, ActorScope: req.ActorScope.Clone()}
	s.policy.config.PolicyVersion = 2
	recovery.ActorScope.PolicyRevision = 2
	s.policy.authorize = attributeDecisionFunc(func(ctx context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
		if dc.PolicyRevision != 2 {
			t.Fatal("historic decision reused")
		}
		flag, _ := dc.Request.Resource.Attributes["identity.command.recovery"].Bool()
		if !flag {
			t.Fatal("missing current recovery admission")
		}
		return authorization.Decision{Outcome: authorization.Allow, Revision: 2}, nil
	})
	s.policy.redact = func(ctx context.Context, in RedactionPolicyInput) (RedactionPolicyDecision, error) {
		if in.PolicyVersion != 2 {
			t.Fatal("historic redaction reused")
		}
		return RedactionPolicyDecision{VisibleFields: in.Fields, PolicyID: "identity-read", PolicyVersion: 2, Reason: "projection-visible"}, nil
	}
	got, err := s.RecoverUserCreate(context.Background(), recovery)
	if err != nil || got.CommitOutcome != CommitOutcomeCommitted || store.results[req.CommandID].Binding.PolicyVersion != 1 {
		t.Fatal("current disclosure mutated historic command or prevented valid recovery")
	}
	recovery.ActorScope.Request.Subject.ID = "another-actor"
	got, err = s.RecoverUserCreate(context.Background(), recovery)
	if err == nil || got.User != (User{}) || got.CommitOutcome != CommitOutcomeUnknown {
		t.Fatal("foreign actor received command result")
	}
	s.policy.authorize = attributeDecisionFunc(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
		return authorization.Decision{Outcome: authorization.Deny, Revision: 2}, nil
	})
	got, err = s.RecoverUserCreate(context.Background(), recovery)
	if err == nil || got.CommitOutcome != CommitOutcomeInvalid {
		t.Fatal("denied recovery claimed an authoritative outcome")
	}
}

func TestUserCreatePreservesEveryValidOutcomeAndRejectsMalformedReceipts(t *testing.T) {
	for _, outcome := range []CommitOutcome{CommitOutcomeNotCommitted, CommitOutcomeConflict, CommitOutcomeUnknown, CommitOutcomeInProgress} {
		s, store, req := creationFixture(t)
		s.uow = creationOwnerFunc{execute: func(ctx context.Context, c Command) (CommandResult, error) {
			spec, _ := c.CreateUser()
			r := CommandResult{Binding: spec.Binding, Outcome: outcome}
			if outcome == CommitOutcomeInProgress {
				r.RetryAfter = time.Second
			}
			return r, nil
		}, recover: store.Recover}
		got, err := s.UserCreate(context.Background(), req)
		if err == nil || got.CommitOutcome != outcome || got.User != (User{}) {
			t.Fatal("durable outcome collapsed")
		}
	}
	for name, change := range map[string]func(*CommandResult){
		"tenant":           func(r *CommandResult) { r.Binding.TenantID = "foreign" },
		"actor":            func(r *CommandResult) { r.Binding.ActorID = "foreign" },
		"policy":           func(r *CommandResult) { r.Binding.PolicyVersion++ },
		"user":             func(r *CommandResult) { r.User.ID = "foreign" },
		"version":          func(r *CommandResult) { r.User.Version = 2 },
		"status":           func(r *CommandResult) { r.User.Status = StatusBanned },
		"audit":            func(r *CommandResult) { r.AuditEventID = "" },
		"outcome":          func(r *CommandResult) { r.Outcome = CommitOutcomeInvalid },
		"progress payload": func(r *CommandResult) { r.Outcome = CommitOutcomeInProgress; r.RetryAfter = time.Second },
	} {
		t.Run(name, func(t *testing.T) {
			s, store, req := creationFixture(t)
			s.uow = creationOwnerFunc{execute: func(ctx context.Context, c Command) (CommandResult, error) {
				r, e := store.Execute(ctx, c)
				change(&r)
				return r, e
			}, recover: store.Recover}
			got, err := s.UserCreate(context.Background(), req)
			var unknown UnknownCommitError
			if got.User != (User{}) || got.CommitOutcome != CommitOutcomeUnknown || !errors.As(err, &unknown) {
				t.Fatal("malformed receipt became a durable claim")
			}
		})
	}
}

func TestUserCreateDeadlineDuringAttemptStaysUnknownAndIsRedacted(t *testing.T) {
	s, store, req := creationFixture(t)
	s.policy.config.MaximumDuration = time.Millisecond
	s.uow = creationOwnerFunc{execute: func(ctx context.Context, c Command) (CommandResult, error) {
		<-ctx.Done()
		return CommandResult{}, errors.New("sensitive driver detail")
	}, recover: store.Recover}
	got, err := s.UserCreate(context.Background(), req)
	var unknown UnknownCommitError
	if got.CommitOutcome != CommitOutcomeUnknown || !errors.As(err, &unknown) || !errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "sensitive") {
		t.Fatal("deadline proved rollback or leaked dependency details")
	}
}

func TestCreationCommandRejectsInvalidBindingAndReservedFields(t *testing.T) {
	s, store, req := creationFixture(t)
	if _, err := s.UserCreate(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	base := store.commands[req.CommandID]
	for _, modify := range []func(*CreateUserCommand){
		func(c *CreateUserCommand) { c.Binding.CommandID = "bad" },
		func(c *CreateUserCommand) { c.Binding.TenantID = "" },
		func(c *CreateUserCommand) { c.Binding.ActorKind = authorization.SubjectKind("anonymous") },
		func(c *CreateUserCommand) { c.Binding.PolicyVersion = 0 },
		func(c *CreateUserCommand) { c.Binding.OperationID = "identity.user.delete" },
		func(c *CreateUserCommand) { c.Status = StatusDeleted },
		func(c *CreateUserCommand) { c.Attributes = append(c.Attributes, c.Attributes[0]) },
		func(c *CreateUserCommand) { c.Attributes[0].Name = "status" },
	} {
		spec := base
		spec.Attributes = cloneUpdates(base.Attributes)
		modify(&spec)
		if _, err := NewUserCreationCommand(spec); err == nil {
			t.Fatal("invalid or reserved command input accepted")
		}
	}
}

func TestCommandIDGenerationAndCanonicalReconstruction(t *testing.T) {
	id, err := NewCommandID()
	if err != nil || len(id) != 22 {
		t.Fatal("command entropy unavailable")
	}
	parsed, err := ParseCommandID(string(id))
	if err != nil || parsed != id {
		t.Fatal("command ID not canonical")
	}
	for _, raw := range []string{"", string(id) + "=", "AAAAAAAAAAAAAAAAAAAAAA", "invalid-sensitive-value"} {
		if got, err := ParseCommandID(raw); got != "" || !errors.Is(err, ErrInvalidCommandID) || strings.Contains(err.Error(), raw) && raw != "" {
			t.Fatal("malformed command ID admitted or retained")
		}
	}
}

func TestUserCreateRecoveryCancellationAndProjectionPanicKeepOutcome(t *testing.T) {
	s, store, req := creationFixture(t)
	if _, err := s.UserCreate(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	r := UserCreateRecoveryRequest{CommandID: req.CommandID, TenantID: req.TenantID, UserID: req.UserID, ActorScope: req.ActorScope}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.uow = creationOwnerFunc{execute: store.Execute, recover: func(ctx context.Context, q RecoveryQuery) (CommandResult, error) {
		receipt, e := store.Recover(ctx, q)
		cancel()
		return receipt, e
	}}
	got, err := s.RecoverUserCreate(ctx, r)
	if got.CommitOutcome != CommitOutcomeCommitted || got.User != (User{}) || !errors.Is(err, context.Canceled) {
		t.Fatal("known recovery lost its commit after cancellation")
	}
	s.uow = store
	s.policy.redact = func(context.Context, RedactionPolicyInput) (RedactionPolicyDecision, error) { panic("private") }
	got, err = s.RecoverUserCreate(context.Background(), r)
	if got.CommitOutcome != CommitOutcomeCommitted || got.User != (User{}) || err == nil {
		t.Fatal("known recovery lost its commit after projection panic")
	}
	s.uow = creationOwnerFunc{execute: store.Execute, recover: func(context.Context, RecoveryQuery) (CommandResult, error) { panic("private") }}
	got, err = s.RecoverUserCreate(context.Background(), r)
	var unknown UnknownCommitError
	if got.CommitOutcome != CommitOutcomeUnknown || !errors.As(err, &unknown) {
		t.Fatal("recovery panic became authoritative rollback")
	}
}

func TestUserCreateUnattemptedFailuresMakeNoDurableClaim(t *testing.T) {
	for _, cause := range []string{"cancel", "nil context", "zero clock", "canonical error", "canonical panic", "stale policy", "bad correlation"} {
		t.Run(cause, func(t *testing.T) {
			s, store, req := creationFixture(t)
			ctx := context.Background()
			switch cause {
			case "cancel":
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			case "nil context":
				ctx = nil
			case "zero clock":
				s.policy.config.Clock = attributeClockFunc(func() time.Time { return time.Time{} })
			case "canonical error":
				s.attributes.config.ValidateCanonicalUserID = func(context.Context, UserID) error { return errors.New("private") }
			case "canonical panic":
				s.attributes.config.ValidateCanonicalUserID = func(context.Context, UserID) error { panic("private") }
			case "stale policy":
				s.attributes.authorize = attributeDecisionFunc(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
					return authorization.Decision{Outcome: authorization.Allow, Revision: 2}, nil
				})
			case "bad correlation":
				req.CorrelationID = "bad correlation"
			}
			got, err := s.UserCreate(ctx, req)
			if err == nil || got.User != (User{}) || got.CommitOutcome != CommitOutcomeInvalid || len(store.users) != 0 {
				t.Fatal("unattempted failure returned data or invented a durable outcome")
			}
		})
	}
	var nilService *UserCreationService
	if got, err := nilService.UserCreate(context.Background(), UserCreateRequest{}); err == nil || got != (UserCreateResult{}) {
		t.Fatal("nil creation service accepted")
	}
}

func TestUserCreateConfigurationAndRecoveryInputAdmission(t *testing.T) {
	s, store, req := creationFixture(t)
	if _, err := NewUserCreationService(nil, s.policy.authorize, s.policy.redact, UserCreationConfig{}); err == nil {
		t.Fatal("nil unit of work accepted")
	}
	var typedNil *creationMemoryOwner
	if _, err := NewUserCreationService(typedNil, s.policy.authorize, s.policy.redact, UserCreationConfig{}); err == nil {
		t.Fatal("typed nil unit of work accepted")
	}
	if _, err := NewUserCreationService(store, nil, s.policy.redact, UserCreationConfig{}); err == nil {
		t.Fatal("nil authorization accepted")
	}
	if _, err := NewUserCreationService(store, s.policy.authorize, s.policy.redact, UserCreationConfig{Query: s.policy.config}); err == nil {
		t.Fatal("missing schema/callbacks accepted")
	}
	r := UserCreateRecoveryRequest{CommandID: req.CommandID, TenantID: req.TenantID, UserID: req.UserID, ActorScope: req.ActorScope}
	for _, modify := range []func(*UserCreateRecoveryRequest){func(r *UserCreateRecoveryRequest) { r.CommandID = "" }, func(r *UserCreateRecoveryRequest) { r.TenantID = "foreign" }, func(r *UserCreateRecoveryRequest) { r.UserID = "foreign" }, func(r *UserCreateRecoveryRequest) { r.ActorScope.Request.Action = "identity.user.get" }} {
		query := r
		query.ActorScope = r.ActorScope.Clone()
		modify(&query)
		got, err := s.RecoverUserCreate(context.Background(), query)
		if err == nil || got.User != (User{}) || got.CommitOutcome != CommitOutcomeInvalid {
			t.Fatal("invalid recovery made an outcome claim")
		}
	}
	got, err := s.RecoverUserCreate(context.Background(), r)
	var absent NotCommittedError
	if got.CommitOutcome != CommitOutcomeNotCommitted || !errors.As(err, &absent) {
		t.Fatal("authoritative absence was not retained")
	}
}

func FuzzCommandIDAdmission(f *testing.F) {
	for _, s := range []string{"", "AQEBAQEBAQEBAQEBAQEBAQ", "AAAAAAAAAAAAAAAAAAAAAA", "AQEBAQEBAQEBAQEBAQEBAQ=", "\nAQEBAQEBAQEBAQEBAQEBAQ"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 4096 {
			t.Skip()
		}
		id, err := ParseCommandID(raw)
		if err != nil {
			if id != "" || !errors.Is(err, ErrInvalidCommandID) {
				t.Fatal("invalid command ID exposed")
			}
			return
		}
		decoded, e := base64.RawURLEncoding.Strict().DecodeString(raw)
		if e != nil || len(decoded) != 16 || bytes.Equal(decoded, make([]byte, 16)) || base64.RawURLEncoding.EncodeToString(decoded) != raw || string(id) != raw {
			t.Fatal("noncanonical command ID admitted")
		}
	})
}
