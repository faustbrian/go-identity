package identity

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
)

// This owner exercises the public atomic command seam, not PostgreSQL or
// asynchronous revocation. No acknowledgement is synthesized by admission.
type statusMemoryOwner struct {
	mu            sync.Mutex
	record        UserStatusRecord
	commands      map[CommandID]UserStatusCommand
	results       map[CommandID]CommandResult
	loseReply     bool
	reads, writes int
}

func (m *statusMemoryOwner) GetStatus(ctx context.Context, q UserStatusQuery) (UserStatusRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reads++
	if q.TenantID != m.record.User.TenantID || q.UserID != m.record.User.ID {
		return UserStatusRecord{}, ErrUserAbsent
	}
	return m.record, nil
}

func (m *statusMemoryOwner) Execute(ctx context.Context, command Command) (CommandResult, error) {
	spec, ok := command.UserStatus()
	if !ok {
		panic("invalid status command")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if old, ok := m.commands[spec.Binding.CommandID]; ok {
		if !reflect.DeepEqual(old, spec) {
			return CommandResult{Binding: spec.Binding, Outcome: CommitOutcomeConflict}, nil
		}
		return m.results[spec.Binding.CommandID], nil
	}
	if spec.ExpectedVersion != m.record.User.Version || spec.ExpectedAuthorityVersion != m.record.AuthorityVersion || m.record.AuthorityVersion == ^uint64(0) {
		return CommandResult{Binding: spec.Binding, Outcome: CommitOutcomeConflict}, nil
	}
	m.record.User.Status = spec.TargetStatus
	m.record.User.Version++
	m.record.AuthorityVersion++
	revocation := RevocationOutcome{CascadeID: CascadeID("AgICAgICAgICAgICAgICAg"), Generation: 1, Status: RevocationPending, AuthorityVersion: m.record.AuthorityVersion}
	for _, owner := range spec.RequiredConsumers() {
		revocation.Owners = append(revocation.Owners, RevocationOwnerReceipt{Owner: owner, Status: RevocationPending})
	}
	result := CommandResult{Binding: spec.Binding, Outcome: CommitOutcomeCommitted, User: m.record.User, ExpectedVersion: spec.ExpectedVersion, AuditEventID: "audit-status", Revocation: &revocation}
	m.commands[spec.Binding.CommandID] = spec
	m.results[spec.Binding.CommandID] = result
	m.writes++
	if m.loseReply {
		return CommandResult{Binding: spec.Binding, Outcome: CommitOutcomeUnknown}, errors.New("sensitive transport failure")
	}
	return result, nil
}

func (m *statusMemoryOwner) Recover(ctx context.Context, q RecoveryQuery) (CommandResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.results[q.CommandID]
	if !ok || r.Binding.TenantID != q.TenantID || r.Binding.UserID != q.UserID || r.Binding.ActorID != q.ActorID || r.Binding.ActorKind != q.ActorKind {
		return CommandResult{}, errors.New("foreign receipt")
	}
	return r, nil
}

func statusFixture(t *testing.T) (*UserStatusService, *statusMemoryOwner, UserStatusRequest) {
	t.Helper()
	f := newQueryFixture(t)
	m := &statusMemoryOwner{record: UserStatusRecord{User: f.repo.user, AuthorityVersion: 7}, commands: make(map[CommandID]UserStatusCommand), results: make(map[CommandID]CommandResult)}
	s, err := NewUserStatusService(m, m, f.service.authorize, queryRedact, UserStatusConfig{Query: f.service.config, PolicyVersion: 1, Reasons: []string{"abuse"}, Policy: StatusPolicy{AllowedTransitions: []StatusTransition{{From: StatusActive, To: StatusSuspended, ReasonRequired: true}, {From: StatusActive, To: StatusBanned, ReasonRequired: true}, {From: StatusSuspended, To: StatusActive}, {From: StatusBanned, To: StatusActive}}, MaximumSuspension: time.Hour, BanRequiresReason: true}})
	if err != nil {
		t.Fatal(err)
	}
	r := UserStatusRequest{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", TenantID: m.record.User.TenantID, UserID: m.record.User.ID, ExpectedVersion: m.record.User.Version, ExpectedAuthorityVersion: 7, Reason: "abuse", ActorScope: f.request.Context}
	r.ActorScope.Request.Action = "identity.user.suspend"
	return s, m, r
}

func TestUserStatusSuspendAdmitsPendingCascadeAndReplays(t *testing.T) {
	s, m, r := statusFixture(t)
	r.ExpiresAt = queryClock{}.Now().Add(time.Minute)
	first, err := s.UserSuspend(context.Background(), r)
	if err != nil || first.CommitOutcome != CommitOutcomeCommitted || first.User.Status != StatusSuspended || first.User.Status.AllowsAuthentication() || first.Revocation.Status != RevocationPending || first.Revocation.Generation != 1 || first.Revocation.AuthorityVersion != 8 || first.Revocation.CascadeID == "" {
		t.Fatalf("suspend = %+v, %v", first, err)
	}
	again, err := s.UserSuspend(context.Background(), r)
	if err != nil || !reflect.DeepEqual(first, again) || m.writes != 1 {
		t.Fatal("replay changed admission")
	}
	r.Reason = "unregistered"
	if _, err := s.UserSuspend(context.Background(), r); err == nil || m.writes != 1 {
		t.Fatal("unregistered reason admitted")
	}
}

func TestUserStatusRestoreAndUnbanAdvanceAuthorityWithoutRestoringOldVersion(t *testing.T) {
	for _, ban := range []bool{false, true} {
		s, m, r := statusFixture(t)
		var first UserStatusResult
		var err error
		if ban {
			r.ActorScope.Request.Action = "identity.admin.user-ban"
			first, err = s.AdminUserBan(context.Background(), r)
		} else {
			first, err = s.UserSuspend(context.Background(), r)
		}
		if err != nil {
			t.Fatal(err)
		}
		r.CommandID = "AwMDAwMDAwMDAwMDAwMDAw"
		r.ExpectedVersion = first.User.Version
		r.ExpectedAuthorityVersion = first.Revocation.AuthorityVersion
		r.Reason = ""
		var restored UserStatusResult
		if ban {
			r.ActorScope.Request.Action = "identity.admin.user-unban"
			restored, err = s.AdminUserUnban(context.Background(), r)
		} else {
			r.ActorScope.Request.Action = "identity.user.restore"
			restored, err = s.UserRestore(context.Background(), r)
		}
		if err != nil || restored.User.Status != StatusActive || restored.Revocation.AuthorityVersion != 9 || restored.Revocation.Status != RevocationPending || m.writes != 2 {
			t.Fatalf("restore = %+v, %v", restored, err)
		}
	}
}

func TestUserStatusFutureAndTerminalVersionsNeverExecute(t *testing.T) {
	for _, status := range []Status{StatusActive, StatusDeleted, StatusAnonymized} {
		s, m, r := statusFixture(t)
		m.record.User.Status = status
		if status == StatusActive {
			r.ExpectedVersion++
		}
		got, err := s.UserSuspend(context.Background(), r)
		if err == nil || got.CommitOutcome != CommitOutcomeInvalid || m.writes != 0 {
			t.Fatal("future/terminal command executed")
		}
	}
}

func TestUserStatusUnknownReplyRecoversOriginalPendingAdmission(t *testing.T) {
	s, m, r := statusFixture(t)
	m.loseReply = true
	got, err := s.UserSuspend(context.Background(), r)
	var unknown UnknownCommitError
	if got.CommitOutcome != CommitOutcomeUnknown || !errors.As(err, &unknown) || got.User != (User{}) {
		t.Fatal("lost reply fabricated rollback")
	}
	recovered, err := s.RecoverUserStatus(context.Background(), UserStatusRecoveryRequest{CommandID: r.CommandID, TenantID: r.TenantID, UserID: r.UserID, ActorScope: r.ActorScope})
	if err != nil || recovered.CommitOutcome != CommitOutcomeCommitted || recovered.Revocation.Status != RevocationPending || recovered.User.Status != StatusSuspended || m.writes != 1 {
		t.Fatal("recovery mutated or lost pending receipt")
	}
}

func TestUserStatusCurrentAuthorizationDeniesBeforeRead(t *testing.T) {
	s, m, r := statusFixture(t)
	s.policy.authorize = queryDecisionFunc(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
		return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, nil
	})
	got, err := s.UserSuspend(context.Background(), r)
	var forbidden ForbiddenError
	if !errors.As(err, &forbidden) || got.CommitOutcome != CommitOutcomeInvalid || m.reads != 0 || m.writes != 0 {
		t.Fatal("denial accessed authority")
	}
}

func TestUserStatusRejectsInvalidExpiryReasonScopeAndAuthority(t *testing.T) {
	for _, change := range []func(*statusMemoryOwner, *UserStatusRequest){
		func(_ *statusMemoryOwner, r *UserStatusRequest) { r.Reason = "" },
		func(_ *statusMemoryOwner, r *UserStatusRequest) { r.Reason = "unregistered" },
		func(_ *statusMemoryOwner, r *UserStatusRequest) { r.ExpiresAt = queryClock{}.Now() },
		func(_ *statusMemoryOwner, r *UserStatusRequest) {
			r.ExpiresAt = queryClock{}.Now().Add(time.Hour + time.Microsecond)
		},
		func(_ *statusMemoryOwner, r *UserStatusRequest) {
			r.ExpiresAt = queryClock{}.Now().Add(time.Nanosecond)
		},
		func(_ *statusMemoryOwner, r *UserStatusRequest) { r.ActorScope.Request.Tenant = "foreign" },
		func(_ *statusMemoryOwner, r *UserStatusRequest) {
			r.ActorScope.Request.Action = "identity.admin.user-ban"
		},
		func(_ *statusMemoryOwner, r *UserStatusRequest) { r.ActorScope.PolicyRevision++ },
		func(_ *statusMemoryOwner, r *UserStatusRequest) { r.ExpectedAuthorityVersion-- },
		func(_ *statusMemoryOwner, r *UserStatusRequest) { r.ExpectedAuthorityVersion++ },
		func(m *statusMemoryOwner, r *UserStatusRequest) {
			m.record.AuthorityVersion = ^uint64(0)
			r.ExpectedAuthorityVersion = ^uint64(0)
		},
	} {
		s, m, r := statusFixture(t)
		change(m, &r)
		got, err := s.UserSuspend(context.Background(), r)
		if err == nil || got.CommitOutcome != CommitOutcomeInvalid || m.writes != 0 {
			t.Fatal("invalid request admitted")
		}
	}
}

func TestUserStatusPostReadPolicyUsesOwnedStateAndDeniesMutation(t *testing.T) {
	s, m, r := statusFixture(t)
	r.ActorScope.Request.Resource.Attributes = authorization.Attributes{"identity.user.status": authorization.StringValue("forged"), "identity.command.recovery": authorization.BoolValue(true)}
	decisions := 0
	s.policy.authorize = queryDecisionFunc(func(_ context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
		decisions++
		if decisions == 1 {
			if _, ok := dc.Request.Resource.Attributes["identity.user.status"]; ok {
				t.Fatal("caller status survived admission")
			}
			return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
		}
		if !reflect.DeepEqual(dc.Request.Resource.Attributes["identity.user.status"], authorization.StringValue(string(m.record.User.Status))) || !reflect.DeepEqual(dc.Request.Resource.Attributes["identity.user.authority-version"], authorization.StringValue("7")) {
			t.Fatal("policy did not receive primary state")
		}
		return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, nil
	})
	got, err := s.UserSuspend(context.Background(), r)
	if err == nil || got.CommitOutcome != CommitOutcomeInvalid || m.writes != 0 || decisions != 2 {
		t.Fatal("post-read denial mutated")
	}
}

func TestUserStatusConcurrentSameCommandAndStaleNewCommand(t *testing.T) {
	s, m, r := statusFixture(t)
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			got, err := s.UserSuspend(context.Background(), r)
			if err != nil || got.CommitOutcome != CommitOutcomeCommitted {
				t.Error("same command not replayed")
			}
		})
	}
	wg.Wait()
	if m.writes != 1 || m.record.AuthorityVersion != 8 {
		t.Fatal("duplicate effect")
	}
	r.CommandID = "AwMDAwMDAwMDAwMDAwMDAw"
	got, err := s.UserSuspend(context.Background(), r)
	var conflict ConflictError
	if !errors.As(err, &conflict) || got.CommitOutcome != CommitOutcomeConflict || m.writes != 1 {
		t.Fatal("stale new command did not conflict")
	}
}

func TestUserStatusReplayAfterExpiryIsNotANewTransition(t *testing.T) {
	s, m, r := statusFixture(t)
	r.ExpiresAt = queryClock{}.Now().Add(time.Minute)
	first, err := s.UserSuspend(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	s.policy.config.Clock = queryClockFunc(func() time.Time { return queryClock{}.Now().Add(2 * time.Minute) })
	got, err := s.UserSuspend(context.Background(), r)
	if err != nil || !reflect.DeepEqual(first, got) || m.writes != 1 || m.record.User.Status.AllowsAuthentication() {
		t.Fatal("expiry replay reapplied or restored authority")
	}
}

func TestUserStatusRestorationPurposeCannotBeSubstituted(t *testing.T) {
	for _, wrong := range []bool{false, true} {
		s, m, r := statusFixture(t)
		m.record.User.Status = StatusBanned
		r.Reason = ""
		r.ActorScope.Request.Action = "identity.user.restore"
		if wrong {
			m.record.User.Status = StatusSuspended
			r.ActorScope.Request.Action = "identity.admin.user-unban"
		}
		var err error
		if wrong {
			_, err = s.AdminUserUnban(context.Background(), r)
		} else {
			_, err = s.UserRestore(context.Background(), r)
		}
		if err == nil || m.writes != 0 {
			t.Fatal("restore crossed original status purpose")
		}
	}
}

func TestUserStatusKnownCommitSurvivesDisclosureFailure(t *testing.T) {
	for _, failure := range []string{"deny", "panic", "cancel", "dependency"} {
		s, m, r := statusFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		if failure == "dependency" {
			s.uow = creationOwnerFunc{execute: func(ctx context.Context, c Command) (CommandResult, error) {
				receipt, _ := m.Execute(ctx, c)
				return receipt, errors.New("sensitive dependency")
			}}
		} else {
			s.policy.redact = func(ctx context.Context, in RedactionPolicyInput) (RedactionPolicyDecision, error) {
				switch failure {
				case "panic":
					panic("sensitive panic")
				case "cancel":
					cancel()
					return queryRedact(ctx, in)
				default:
					return RedactionPolicyDecision{}, nil
				}
			}
		}
		got, err := s.UserSuspend(ctx, r)
		cancel()
		if err == nil || got.CommitOutcome != CommitOutcomeCommitted || got.User != (User{}) || got.Revocation.Status != 0 || m.writes != 1 || strings.Contains(err.Error(), "sensitive") {
			t.Fatal("known commit was erased or disclosed")
		}
	}
}

func TestUserStatusMalformedAndCompletedAdmissionRemainUnknown(t *testing.T) {
	for _, mutate := range []func(*CommandResult){
		func(r *CommandResult) { r.User.Status = StatusActive },
		func(r *CommandResult) { r.ExpectedVersion++ },
		func(r *CommandResult) { r.Binding.TenantID = "foreign" },
		func(r *CommandResult) { r.Revocation = nil },
		func(r *CommandResult) { v := *r.Revocation; v.Status = RevocationCompleted; r.Revocation = &v },
		func(r *CommandResult) { v := *r.Revocation; v.AuthorityVersion++; r.Revocation = &v },
		func(r *CommandResult) { v := *r.Revocation; v.CascadeID = "bad"; r.Revocation = &v },
		func(r *CommandResult) { v := *r.Revocation; v.Generation = 2; r.Revocation = &v },
		func(r *CommandResult) {
			v := *r.Revocation
			v.Owners = []RevocationOwnerReceipt{{Owner: "audit", Status: RevocationCompleted}}
			r.Revocation = &v
		},
	} {
		s, m, req := statusFixture(t)
		s.uow = creationOwnerFunc{execute: func(ctx context.Context, c Command) (CommandResult, error) {
			r, err := m.Execute(ctx, c)
			mutate(&r)
			return r, err
		}}
		got, err := s.UserSuspend(context.Background(), req)
		var unknown UnknownCommitError
		if !errors.As(err, &unknown) || got.CommitOutcome != CommitOutcomeUnknown || got.User != (User{}) {
			t.Fatal("invalid receipt implied a known outcome")
		}
	}
}

func TestUserStatusRecoveryDeniesWrongPurposeActorAndCurrentPolicy(t *testing.T) {
	for _, which := range []string{"purpose", "actor", "deny"} {
		s, m, r := statusFixture(t)
		if _, err := s.UserSuspend(context.Background(), r); err != nil {
			t.Fatal(err)
		}
		q := UserStatusRecoveryRequest{CommandID: r.CommandID, TenantID: r.TenantID, UserID: r.UserID, ActorScope: r.ActorScope}
		switch which {
		case "purpose":
			q.ActorScope.Request.Action = "identity.admin.user-ban"
		case "actor":
			q.ActorScope.Request.Subject.ID = "other-actor"
		case "deny":
			s.policy.authorize = queryDecisionFunc(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
				return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, nil
			})
		}
		got, err := s.RecoverUserStatus(context.Background(), q)
		if err == nil || got.User != (User{}) || got.Revocation.Status != 0 || m.writes != 1 {
			t.Fatal("recovery crossed current scope")
		}
	}
}

func TestUserStatusRecoverySeparatesCurrentPolicyFromHistoricalReceipt(t *testing.T) {
	s, m, r := statusFixture(t)
	first, err := s.UserSuspend(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	// The original immutable receipt remains at revision 1. Current policy and
	// redaction explicitly allow the exact actor to recover it at revision 2.
	s.policy.config.PolicyID = "identity-new-policy"
	s.policy.config.PolicyVersion = 2
	s.policy.authorize = queryDecisionFunc(func(_ context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
		if dc.PolicyRevision != 2 {
			t.Fatal("historical policy used for recovery")
		}
		return authorization.Decision{Outcome: authorization.Allow, Revision: 2}, nil
	})
	s.policy.redact = func(ctx context.Context, in RedactionPolicyInput) (RedactionPolicyDecision, error) {
		if in.PolicyVersion != 2 {
			t.Fatal("historical redaction used")
		}
		return RedactionPolicyDecision{VisibleFields: in.Fields, PolicyID: "identity-new-policy", PolicyVersion: 2, Reason: "projection-visible"}, nil
	}
	r.ActorScope.PolicyRevision = 2
	got, err := s.RecoverUserStatus(context.Background(), UserStatusRecoveryRequest{CommandID: r.CommandID, TenantID: r.TenantID, UserID: r.UserID, ActorScope: r.ActorScope})
	if err != nil || !reflect.DeepEqual(got, first) || m.writes != 1 || m.results[r.CommandID].Binding.PolicyVersion != 1 {
		t.Fatalf("current-policy recovery lost original commitment: %+v, %v", got, err)
	}
}

func TestUserStatusCommandsAreCopiedRedactedAndClosed(t *testing.T) {
	s, m, r := statusFixture(t)
	if _, err := s.UserSuspend(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	spec := m.commands[r.CommandID]
	c, err := NewUserStatusCommand(spec)
	if err != nil {
		t.Fatal(err)
	}
	spec.Reason = "changed"
	got, ok := c.UserStatus()
	if !ok || got.Reason != "abuse" {
		t.Fatal("command not immutable")
	}
	if _, ok := c.CreateUser(); ok {
		t.Fatal("status masquerades as create")
	}
	if _, ok := c.UpdateUser(); ok {
		t.Fatal("status masquerades as update")
	}
	if _, ok := c.UpdateProfile(); ok {
		t.Fatal("status masquerades as profile")
	}
	if strings.Contains(fmt.Sprintf("%#v", c), "abuse") {
		t.Fatal("command leaked")
	}
	if _, err := c.MarshalJSON(); err == nil {
		t.Fatal("command JSON exposed")
	}
	if _, ok := (Command{}).UserStatus(); ok {
		t.Fatal("zero command valid")
	}
}

func TestUserStatusConfigurationIsValidatedAndFrozen(t *testing.T) {
	s, m, _ := statusFixture(t)
	config := s.config
	config.Reasons = []string{"abuse"}
	copyService, err := NewUserStatusService(m, m, s.policy.authorize, queryRedact, config)
	if err != nil {
		t.Fatal(err)
	}
	config.Reasons[0] = "changed"
	config.Policy.AllowedTransitions[0].To = StatusDeleted
	if copyService.config.Reasons[0] != "abuse" || copyService.config.Policy.AllowedTransitions[0].To == StatusDeleted {
		t.Fatal("configuration aliased")
	}
	for _, reasons := range [][]string{nil, {""}, {"abuse", "abuse"}, {"bad reason"}, {"bad\u2000reason"}, {"bad\u0085reason"}, {strings.Repeat("x", 513)}, make([]string, 33)} {
		config = s.config
		config.Reasons = reasons
		if got, err := NewUserStatusService(m, m, s.policy.authorize, queryRedact, config); err == nil || got != nil {
			t.Fatal("invalid registration accepted")
		}
	}
}

func TestUserStatusClockIsSampledOnceAndExactManifestCopied(t *testing.T) {
	s, m, r := statusFixture(t)
	calls := 0
	s.policy.config.Clock = queryClockFunc(func() time.Time { calls++; return queryClock{}.Now() })
	got, err := s.UserSuspend(context.Background(), r)
	if err != nil || calls != 1 {
		t.Fatal("clock not sampled once")
	}
	expected := []string{"identity/session", "identity/session/valkey", "identity/impersonation", "identity/apikey", "identity/apikey/valkey", "oauth-server", "oauth-server/device", "oauth-server/oidc", "authorization", "authorization/valkey", "identity/risk", "audit"}
	spec := m.commands[r.CommandID]
	if !reflect.DeepEqual(spec.RequiredConsumers(), expected) || len(got.Revocation.Owners) != len(expected) {
		t.Fatal("manifest incomplete")
	}
	for i, owner := range got.Revocation.Owners {
		if owner.Owner != expected[i] || owner.Status != RevocationPending {
			t.Fatal("consumer fabricated acknowledgement")
		}
	}
	got.Revocation.Owners[0].Owner = "changed"
	manifest := spec.RequiredConsumers()
	manifest[0] = "changed"
	again, err := s.UserSuspend(context.Background(), r)
	if err != nil || again.Revocation.Owners[0].Owner != expected[0] || spec.RequiredConsumers()[0] != expected[0] {
		t.Fatal("public slices alias owner")
	}
}

func TestUserStatusZeroContextMissingAuthorityAndUnavailableCallbacks(t *testing.T) {
	for _, which := range []string{"zero-clock", "clock-panic", "canonical-panic", "absent", "invalid-record", "cancel", "execute-panic"} {
		s, m, r := statusFixture(t)
		ctx := context.Background()
		switch which {
		case "zero-clock":
			s.policy.config.Clock = queryClockFunc(func() time.Time { return time.Time{} })
		case "clock-panic":
			s.policy.config.Clock = queryClockFunc(func() time.Time { panic("sensitive") })
		case "canonical-panic":
			s.policy.config.ValidateCanonicalUserID = func(context.Context, UserID) error { panic("sensitive") }
		case "absent":
			m.record.User.ID = "other-user"
		case "invalid-record":
			m.record.AuthorityVersion = 0
		case "cancel":
			c, cancel := context.WithCancel(ctx)
			cancel()
			ctx = c
		case "execute-panic":
			s.uow = creationOwnerFunc{execute: func(context.Context, Command) (CommandResult, error) { panic("sensitive") }}
		}
		got, err := s.UserSuspend(ctx, r)
		if err == nil || got.User != (User{}) || got.Revocation.Status != 0 || strings.Contains(err.Error(), "sensitive") {
			t.Fatal("unavailable authority disclosed state")
		}
		if which == "execute-panic" {
			if got.CommitOutcome != CommitOutcomeUnknown {
				t.Fatal("execute panic fabricated rollback")
			}
		} else if got.CommitOutcome != CommitOutcomeInvalid {
			t.Fatal("pre-execute failure fabricated outcome")
		}
	}
	s, _, r := statusFixture(t)
	if _, err := s.UserSuspend(nil, r); err == nil {
		t.Fatal("nil context admitted")
	}
	var missing *UserStatusService
	if _, err := missing.UserSuspend(context.Background(), r); err == nil {
		t.Fatal("nil service admitted")
	}
}

func FuzzUserStatusCommand(f *testing.F) {
	f.Add("AQEBAQEBAQEBAQEBAQEBAQ", "identity.user.suspend", "abuse", uint64(1), uint64(7))
	f.Add("bad", "identity.user.restore", "", uint64(0), uint64(0))
	f.Fuzz(func(t *testing.T, id, operation, reason string, version, authority uint64) {
		spec := UserStatusCommand{Binding: CommandBinding{CommandID: CommandID(id), TenantID: "tenant-a", UserID: "user-a", ActorID: "actor-a", ActorKind: authorization.SubjectUser, OperationID: operation, PolicyID: "policy-a", PolicyVersion: 1, SchemaID: "identity-lifecycle", SchemaVersion: 1, CorrelationID: "request-a"}, ExpectedVersion: version, ExpectedAuthorityVersion: authority, StatusPolicyVersion: 1, TargetStatus: statusTarget(operation), Reason: reason}
		c, err := NewUserStatusCommand(spec)
		if err != nil {
			if _, ok := c.UserStatus(); ok {
				t.Fatal("failed constructor returned command")
			}
			return
		}
		got, ok := c.UserStatus()
		if !ok || got != spec || version == 0 || version == ^uint64(0) || authority == 0 || authority == ^uint64(0) || len(got.RequiredConsumers()) == 0 {
			t.Fatal("invalid command accepted")
		}
	})
}
