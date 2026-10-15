package identity

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/faustbrian/go-authorization/v3"
)

// One synchronization owner models the core port's durable contract only.
// It does not prove SQL reservation, crash recovery, audit or canonical HMAC.
type updateMemoryOwner struct {
	mu        sync.Mutex
	user      User
	fields    []AttributeUpdate
	commands  map[CommandID]UpdateUserCommand
	results   map[CommandID]CommandResult
	audits    int
	loseReply bool
}

func (m *updateMemoryOwner) Get(ctx context.Context, q GetUserQuery) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if q.UserID != m.user.ID || q.TenantID != m.user.TenantID {
		return User{}, ErrUserAbsent
	}
	return m.user, nil
}
func (m *updateMemoryOwner) Execute(ctx context.Context, c Command) (CommandResult, error) {
	if _, ok := ctx.Deadline(); !ok {
		panic("unbounded update")
	}
	spec, ok := c.UpdateUser()
	if !ok {
		panic("invalid update")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if prior, ok := m.commands[spec.Binding.CommandID]; ok {
		if !reflect.DeepEqual(prior, spec) {
			return CommandResult{Binding: spec.Binding, Outcome: CommitOutcomeConflict}, nil
		}
		return m.results[spec.Binding.CommandID], nil
	}
	if m.user.ID != spec.Binding.UserID || m.user.TenantID != spec.Binding.TenantID || m.user.Version != spec.ExpectedVersion || m.user.Status == StatusDeleted || m.user.Status == StatusAnonymized {
		return CommandResult{Binding: spec.Binding, Outcome: CommitOutcomeConflict}, nil
	}
	m.user.Version++
	for _, change := range spec.Attributes {
		replaced := false
		for i, old := range m.fields {
			if old.Name == change.Name {
				m.fields[i] = cloneUpdates([]AttributeUpdate{change})[0]
				replaced = true
				break
			}
		}
		if !replaced {
			m.fields = append(m.fields, cloneUpdates([]AttributeUpdate{change})[0])
		}
	}
	m.audits++
	result := CommandResult{Binding: spec.Binding, Outcome: CommitOutcomeCommitted, User: m.user, ExpectedVersion: spec.ExpectedVersion, AuditEventID: "audit-update-1"}
	m.commands[spec.Binding.CommandID] = spec
	m.results[spec.Binding.CommandID] = result
	if m.loseReply {
		return CommandResult{Binding: spec.Binding, Outcome: CommitOutcomeUnknown}, errors.New("private response loss")
	}
	return result, nil
}
func (m *updateMemoryOwner) Recover(ctx context.Context, q RecoveryQuery) (CommandResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.results[q.CommandID]
	if !ok {
		return CommandResult{}, errors.New("private absence")
	}
	if r.Binding.TenantID != q.TenantID || r.Binding.UserID != q.UserID || r.Binding.ActorID != q.ActorID || r.Binding.ActorKind != q.ActorKind {
		return CommandResult{}, errors.New("private foreign command")
	}
	return r, nil
}

func updateFixture(t *testing.T) (*UserUpdateAdminService, *updateMemoryOwner, UserUpdateAdminRequest) {
	t.Helper()
	create, _, creation := creationFixture(t)
	store := &updateMemoryOwner{user: User{ID: creation.UserID, TenantID: creation.TenantID, Status: StatusActive, Version: 2}, commands: make(map[CommandID]UpdateUserCommand), results: make(map[CommandID]CommandResult)}
	config := UserCreationConfig{Query: create.policy.config, Schema: create.attributes.schema, Normalize: create.attributes.normalize, ValidateValue: create.attributes.config.ValidateValue}
	service, err := NewUserUpdateAdminService(store, store, create.policy.authorize, queryRedact, config)
	if err != nil {
		t.Fatal(err)
	}
	scope := creation.ActorScope.Clone()
	scope.Request.Action = "identity.user.update-admin"
	return service, store, UserUpdateAdminRequest{CommandID: creation.CommandID, TenantID: creation.TenantID, UserID: creation.UserID, ExpectedVersion: 2, SchemaVersion: 1, Fields: creation.Fields, ActorScope: scope}
}

func TestUserUpdateAdminReplaysBeforeExpectedVersionConflict(t *testing.T) {
	s, store, req := updateFixture(t)
	first, err := s.UserUpdateAdmin(context.Background(), req)
	if err != nil || first.CommitOutcome != CommitOutcomeCommitted || first.User.Version != 3 {
		t.Fatalf("update = %+v %v", first, err)
	}
	again, err := s.UserUpdateAdmin(context.Background(), req)
	if err != nil || again != first || store.user.Version != 3 || store.audits != 1 {
		t.Fatal("same command did not replay exactly one version/audit")
	}
	req.CommandID = CommandID("AgICAgICAgICAgICAgICAg")
	got, err := s.UserUpdateAdmin(context.Background(), req)
	var conflict ConflictError
	if !errors.As(err, &conflict) || got.CommitOutcome != CommitOutcomeConflict || got.User != (User{}) || store.audits != 1 {
		t.Fatal("new stale-version command did not conflict")
	}
}

func TestUserUpdateAdminRecoversLostReplyWithoutAnotherVersion(t *testing.T) {
	s, store, req := updateFixture(t)
	store.loseReply = true
	got, err := s.UserUpdateAdmin(context.Background(), req)
	var unknown UnknownCommitError
	if !errors.As(err, &unknown) || got.CommitOutcome != CommitOutcomeUnknown || store.user.Version != 3 {
		t.Fatal("lost update reply reported rollback")
	}
	recovered, err := s.RecoverUserUpdateAdmin(context.Background(), UserUpdateAdminRecoveryRequest{CommandID: req.CommandID, TenantID: req.TenantID, UserID: req.UserID, ActorScope: req.ActorScope})
	if err != nil || recovered.CommitOutcome != CommitOutcomeCommitted || recovered.User.Version != 3 || store.audits != 1 {
		t.Fatal("recovery re-executed or lost committed version")
	}
}

func TestUserUpdateAdminRejectsScopeOrForbiddenFieldWithoutMutation(t *testing.T) {
	for _, mode := range []string{"scope", "field", "zero-version", "overflow", "empty"} {
		t.Run(mode, func(t *testing.T) {
			s, store, req := updateFixture(t)
			switch mode {
			case "scope":
				req.ActorScope.Request.Tenant = "foreign"
			case "field":
				req.Fields[0].Name = "status"
			case "zero-version":
				req.ExpectedVersion = 0
			case "overflow":
				req.ExpectedVersion = ^uint64(0)
			case "empty":
				req.Fields = nil
			}
			got, err := s.UserUpdateAdmin(context.Background(), req)
			if err == nil || got.CommitOutcome != CommitOutcomeInvalid || got.User != (User{}) || store.audits != 0 || store.user.Version != 2 {
				t.Fatal("invalid update reached mutation")
			}
		})
	}
}

func TestUserUpdateAdminCurrentAuthorizationRemainsExactUpstream(t *testing.T) {
	s, store, req := updateFixture(t)
	deny := queryDecisionFunc(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
		return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, nil
	})
	var err error
	s, err = NewUserUpdateAdminService(store, store, deny, queryRedact, UserCreationConfig{Query: s.creation.policy.config, Schema: s.creation.attributes.schema, Normalize: s.creation.attributes.normalize, ValidateValue: s.creation.attributes.config.ValidateValue})
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.UserUpdateAdmin(context.Background(), req)
	var forbidden ForbiddenError
	if !errors.As(err, &forbidden) || got.CommitOutcome != CommitOutcomeInvalid || store.audits != 0 {
		t.Fatal("denied actor updated identity")
	}
}

func TestUserUpdateAdminConcurrentNewCommandsFenceOneVersion(t *testing.T) {
	s, store, req := updateFixture(t)
	start := make(chan struct{})
	results := make(chan UserUpdateAdminResult, 2)
	var workers sync.WaitGroup
	for _, id := range []CommandID{req.CommandID, "AgICAgICAgICAgICAgICAg"} {
		workers.Add(1)
		go func(id CommandID) {
			defer workers.Done()
			<-start
			r := req
			r.CommandID = id
			result, _ := s.UserUpdateAdmin(context.Background(), r)
			results <- result
		}(id)
	}
	close(start)
	workers.Wait()
	close(results)
	committed, conflicted := 0, 0
	for r := range results {
		switch r.CommitOutcome {
		case CommitOutcomeCommitted:
			committed++
		case CommitOutcomeConflict:
			conflicted++
		default:
			t.Fatal("race did not settle as a known commit/conflict")
		}
	}
	if committed != 1 || conflicted != 1 || store.user.Version != 3 || store.audits != 1 {
		t.Fatal("competing expected-version commands both mutated")
	}
}

func TestUserUpdateAdminChangedIntentCannotReplayPriorCommand(t *testing.T) {
	s, store, req := updateFixture(t)
	if _, err := s.UserUpdateAdmin(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	req.Fields[0].Value = attributeString("changed")
	got, err := s.UserUpdateAdmin(context.Background(), req)
	var conflict ConflictError
	if !errors.As(err, &conflict) || got.CommitOutcome != CommitOutcomeConflict || store.user.Version != 3 || store.audits != 1 {
		t.Fatal("changed intent replayed or mutated")
	}
}

func TestUserUpdateAdminReplacesOwnedMetadataAndSamplesClockOnce(t *testing.T) {
	s, store, req := updateFixture(t)
	samples := 0
	clock := queryClockFunc(func() time.Time { samples++; return time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC) })
	s.creation.policy.config.Clock = clock
	s.creation.attributes.config.Clock = clock
	req.ActorScope.Request.Resource.Attributes = authorization.Attributes{"identity.command.recovery": authorization.BoolValue(true), "identity.command.read-admission": authorization.BoolValue(false), "identity.user.status": authorization.StringValue("fake"), "identity.user.version": authorization.StringValue("999")}
	decisions := 0
	original := s.creation.attributes.authorize
	check := queryDecisionFunc(func(ctx context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
		decisions++
		recovery, _ := dc.Request.Resource.Attributes["identity.command.recovery"].Bool()
		if recovery {
			t.Fatal("spoofed recovery metadata accepted")
		}
		admission, _ := dc.Request.Resource.Attributes["identity.command.read-admission"].Bool()
		if admission {
			if dc.Request.Resource.Attributes["identity.user.status"].Kind() != authorization.ValueMissing || dc.Request.Resource.Attributes["identity.user.version"].Kind() != authorization.ValueMissing {
				t.Fatal("unread caller status/version reached admission policy")
			}
		} else {
			status, _ := dc.Request.Resource.Attributes["identity.user.status"].String()
			version, _ := dc.Request.Resource.Attributes["identity.user.version"].String()
			if status != "active" || version != "2" {
				t.Fatal("apply policy did not see authoritative row metadata")
			}
		}
		return original.Decide(ctx, dc)
	})
	s.creation.attributes.authorize = check
	s.creation.policy.authorize = check
	result, err := s.UserUpdateAdmin(context.Background(), req)
	if err != nil || samples != 1 || decisions < 3 || result.User.Version != 3 || store.audits != 1 {
		t.Fatal("trusted time or phased operation changed")
	}
}

func TestUserUpdateAdminMalformedReceiptCannotBecomeSuccess(t *testing.T) {
	for _, mode := range []string{"tenant", "actor", "purpose", "expected", "version", "status", "audit", "policy", "noncommit-payload"} {
		t.Run(mode, func(t *testing.T) {
			s, store, req := updateFixture(t)
			s.creation.uow = creationOwnerFunc{execute: func(ctx context.Context, c Command) (CommandResult, error) {
				r, err := store.Execute(ctx, c)
				switch mode {
				case "tenant":
					r.Binding.TenantID = "foreign"
				case "actor":
					r.Binding.ActorID = "foreign"
				case "purpose":
					r.Binding.OperationID = "identity.user.create"
				case "expected":
					r.ExpectedVersion = 3
					r.User.Version = 4
				case "version":
					r.User.Version = 4
				case "status":
					r.User.Status = StatusDeleted
				case "audit":
					r.AuditEventID = ""
				case "policy":
					r.Binding.PolicyVersion = 2
				case "noncommit-payload":
					r.Outcome = CommitOutcomeConflict
				}
				return r, err
			}}
			got, err := s.UserUpdateAdmin(context.Background(), req)
			var unknown UnknownCommitError
			if !errors.As(err, &unknown) || got.CommitOutcome != CommitOutcomeUnknown || got.User != (User{}) || got.Version != 0 {
				t.Fatal("malformed receipt exposed success or rollback")
			}
		})
	}
}

func TestUserUpdateAdminKnownCommitSurvivesOutputFailures(t *testing.T) {
	for _, mode := range []string{"cancel", "panic", "deny", "dependency"} {
		t.Run(mode, func(t *testing.T) {
			s, store, req := updateFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "cancel", "dependency":
				s.creation.uow = creationOwnerFunc{execute: func(ctx context.Context, c Command) (CommandResult, error) {
					r, err := store.Execute(ctx, c)
					if mode == "cancel" {
						cancel()
					} else {
						err = errors.New("private driver error")
					}
					return r, err
				}}
			case "panic":
				s.creation.policy.redact = func(context.Context, RedactionPolicyInput) (RedactionPolicyDecision, error) {
					panic("private policy detail")
				}
			case "deny":
				s.creation.policy.redact = func(context.Context, RedactionPolicyInput) (RedactionPolicyDecision, error) {
					return RedactionPolicyDecision{}, nil
				}
			}
			got, err := s.UserUpdateAdmin(ctx, req)
			if err == nil || strings.Contains(err.Error(), "private") || got.CommitOutcome != CommitOutcomeCommitted || got.User != (User{}) || got.Version != 0 || store.audits != 1 {
				t.Fatal("known update commit was lost or disclosed after output failure")
			}
		})
	}
}

func TestUserUpdateAdminPreAttemptFailureMakesNoOutcomeClaim(t *testing.T) {
	for _, mode := range []string{"cancel", "missing", "foreign-user", "malformed", "terminal", "panic-read", "panic-execute"} {
		t.Run(mode, func(t *testing.T) {
			s, store, req := updateFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "cancel":
				cancel()
			case "missing":
				s.repo = queryReadFunc(func(context.Context, GetUserQuery) (User, error) { return User{}, ErrUserAbsent })
			case "foreign-user":
				s.repo = queryReadFunc(func(context.Context, GetUserQuery) (User, error) { u := store.user; u.ID = "foreign"; return u, nil })
			case "malformed":
				store.user.Version = 0
			case "terminal":
				store.user.Status = StatusAnonymized
			case "panic-read":
				s.repo = queryReadFunc(func(context.Context, GetUserQuery) (User, error) { panic("private read detail") })
			case "panic-execute":
				s.creation.uow = creationOwnerFunc{execute: func(context.Context, Command) (CommandResult, error) { panic("private execute detail") }}
			}
			got, err := s.UserUpdateAdmin(ctx, req)
			expected := CommitOutcomeInvalid
			if mode == "panic-execute" {
				expected = CommitOutcomeUnknown
			}
			if err == nil || got.CommitOutcome != expected || got.User != (User{}) || store.audits != 0 || strings.Contains(err.Error(), "private") {
				t.Fatal("failure inferred rollback or mutated")
			}
		})
	}
}

func TestCreationAndUpdateRecoveryRejectOtherPurpose(t *testing.T) {
	update, store, req := updateFixture(t)
	if _, err := update.UserUpdateAdmin(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	creation := update.creation
	scope := req.ActorScope.Clone()
	scope.Request.Action = "identity.user.create"
	got, err := creation.RecoverUserCreate(context.Background(), UserCreateRecoveryRequest{CommandID: req.CommandID, TenantID: req.TenantID, UserID: req.UserID, ActorScope: scope})
	var unknown UnknownCommitError
	if !errors.As(err, &unknown) || got.CommitOutcome != CommitOutcomeUnknown || got.User != (User{}) {
		t.Fatal("creation recovered an update-purpose command")
	}
	store.mu.Lock()
	r := store.results[req.CommandID]
	r.Binding.OperationID = "identity.user.create"
	r.ExpectedVersion = 0
	r.User.Version = 1
	store.results[req.CommandID] = r
	store.mu.Unlock()
	result, err := update.RecoverUserUpdateAdmin(context.Background(), UserUpdateAdminRecoveryRequest{CommandID: req.CommandID, TenantID: req.TenantID, UserID: req.UserID, ActorScope: req.ActorScope})
	if !errors.As(err, &unknown) || result.CommitOutcome != CommitOutcomeUnknown || result.User != (User{}) {
		t.Fatal("update recovered a creation-purpose command")
	}
}

func TestUserUpdateAdminRechecksCurrentPolicyForReplayAndRecovery(t *testing.T) {
	s, store, req := updateFixture(t)
	if _, err := s.UserUpdateAdmin(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	deny := queryDecisionFunc(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
		return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, nil
	})
	denied, err := NewUserUpdateAdminService(store, store, deny, queryRedact, UserCreationConfig{Query: s.creation.policy.config, Schema: s.creation.attributes.schema, Normalize: s.creation.attributes.normalize, ValidateValue: s.creation.attributes.config.ValidateValue})
	if err != nil {
		t.Fatal(err)
	}
	denied.repo = queryReadFunc(func(context.Context, GetUserQuery) (User, error) {
		t.Fatal("denied actor read authoritative state")
		return User{}, nil
	})
	got, err := denied.UserUpdateAdmin(context.Background(), req)
	var forbidden ForbiddenError
	if !errors.As(err, &forbidden) || got.CommitOutcome != CommitOutcomeInvalid || got.User != (User{}) {
		t.Fatal("denied replay inferred old outcome or disclosed user")
	}
	recovered, err := denied.RecoverUserUpdateAdmin(context.Background(), UserUpdateAdminRecoveryRequest{CommandID: req.CommandID, TenantID: req.TenantID, UserID: req.UserID, ActorScope: req.ActorScope})
	if !errors.As(err, &forbidden) || recovered.CommitOutcome != CommitOutcomeInvalid || recovered.User != (User{}) || store.audits != 1 {
		t.Fatal("denied recovery disclosed or re-executed")
	}
}

func TestUserUpdateAdminRecoveryPreservesHistoricVersionAndCurrentRedaction(t *testing.T) {
	s, store, req := updateFixture(t)
	if _, err := s.UserUpdateAdmin(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	recovery := UserUpdateAdminRecoveryRequest{CommandID: req.CommandID, TenantID: req.TenantID, UserID: req.UserID, ActorScope: req.ActorScope}
	for _, mode := range []string{"deny", "panic", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			copyService := *s
			copyCreation := *s.creation
			copyPolicy := *s.creation.policy
			copyCreation.policy = &copyPolicy
			copyService.creation = &copyCreation
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			copyPolicy.redact = func(ctx context.Context, in RedactionPolicyInput) (RedactionPolicyDecision, error) {
				if in.OperationID != "identity.user.update-admin" {
					t.Fatal("recovery changed redaction purpose")
				}
				switch mode {
				case "panic":
					panic("private projection detail")
				case "cancel":
					cancel()
				}
				return RedactionPolicyDecision{}, nil
			}
			got, err := copyService.RecoverUserUpdateAdmin(ctx, recovery)
			if err == nil || got.CommitOutcome != CommitOutcomeCommitted || got.User != (User{}) || got.Version != 0 || store.audits != 1 {
				t.Fatal("recovery output failure lost historical commit")
			}
		})
	}
	recovery.ActorScope.Request.Subject.ID = "foreign"
	got, err := s.RecoverUserUpdateAdmin(context.Background(), recovery)
	var unknown UnknownCommitError
	if !errors.As(err, &unknown) || got.User != (User{}) || got.CommitOutcome != CommitOutcomeUnknown {
		t.Fatal("foreign actor recovered historical update")
	}
}

func TestUserUpdateCommandIsClosedBoundedAndCopiesPayload(t *testing.T) {
	s, _, req := updateFixture(t)
	binding := CommandBinding{CommandID: req.CommandID, TenantID: req.TenantID, UserID: req.UserID, ActorID: ActorID(req.ActorScope.Request.Subject.ID), ActorKind: req.ActorScope.Request.Subject.Kind, OperationID: "identity.user.update-admin", PolicyID: s.creation.policy.config.PolicyID, PolicyVersion: 1, SchemaID: "profile", SchemaVersion: 1, CorrelationID: string(req.CommandID)}
	spec := UpdateUserCommand{Binding: binding, ExpectedVersion: 2, Attributes: []AttributeUpdate{{Name: "labels", Value: AttributeValue{Kind: AttributeStringList, List: []AttributeScalar{{Kind: AttributeString, String: "first"}}}}}}
	command, err := NewUserUpdateCommand(spec)
	if err != nil {
		t.Fatal(err)
	}
	spec.Attributes[0].Value.List[0].String = "changed"
	a, ok := command.UpdateUser()
	if !ok || a.Attributes[0].Value.List[0].String != "first" {
		t.Fatal("update command aliases caller input")
	}
	a.Attributes[0].Value.List[0].String = "accessor"
	b, _ := command.UpdateUser()
	if b.Attributes[0].Value.List[0].String != "first" {
		t.Fatal("update accessor exposes retained storage")
	}
	if _, ok := command.CreateUser(); ok {
		t.Fatal("update command exposed creation variant")
	}
	if _, ok := (Command{}).UpdateUser(); ok {
		t.Fatal("zero command exposed update")
	}
	for _, mode := range []string{"purpose", "zero-version", "overflow", "empty", "too-many", "reserved", "duplicate", "mixed", "budget"} {
		t.Run(mode, func(t *testing.T) {
			bad := UpdateUserCommand{Binding: binding, ExpectedVersion: 2, Attributes: cloneUpdates(req.Fields)}
			switch mode {
			case "purpose":
				bad.Binding.OperationID = "identity.user.create"
			case "zero-version":
				bad.ExpectedVersion = 0
			case "overflow":
				bad.ExpectedVersion = ^uint64(0)
			case "empty":
				bad.Attributes = nil
			case "too-many":
				bad.Attributes = make([]AttributeUpdate, 65)
			case "reserved":
				bad.Attributes[0].Name = "version"
			case "duplicate":
				bad.Attributes = append(bad.Attributes, bad.Attributes[0])
			case "mixed":
				bad.Attributes[0].Value.Scalar.Bool = true
			case "budget":
				bad.Attributes[0].Value = AttributeValue{Kind: AttributeStringList, List: make([]AttributeScalar, 64)}
				for i := range bad.Attributes[0].Value.List {
					bad.Attributes[0].Value.List[i] = AttributeScalar{Kind: AttributeString, String: strings.Repeat("a", 4096)}
				}
				bad.Attributes = append(bad.Attributes, AttributeUpdate{Name: "another", Value: attributeString("over")})
			}
			c, err := NewUserUpdateCommand(bad)
			if err == nil || c.update != nil || c.create != nil {
				t.Fatal("invalid update payload returned a command")
			}
		})
	}
	createSpec := CreateUserCommand{Binding: binding, Status: StatusActive}
	if _, err := NewUserCreationCommand(createSpec); err == nil {
		t.Fatal("creation constructor accepted update purpose")
	}
}

func TestUserUpdateAdminDoesNotApplyCreateDefaultsOrReplaceOtherFields(t *testing.T) {
	s, store, req := updateFixture(t)
	extra := attributeField("unchanged", AttributeString)
	extra.WriteAuthorization = FieldWriteAdministrator
	extra.Default = attributeString("create-only-default")
	schema := s.creation.attributes.schema
	schema.Fields = append(schema.Fields, extra)
	config := UserCreationConfig{Query: s.creation.policy.config, Schema: schema, Normalize: s.creation.attributes.normalize, ValidateValue: s.creation.attributes.config.ValidateValue}
	updated, err := NewUserUpdateAdminService(store, store, s.creation.policy.authorize, queryRedact, config)
	if err != nil {
		t.Fatal(err)
	}
	store.fields = []AttributeUpdate{{Name: "unchanged", Value: attributeString("existing-value")}}
	if _, err := updated.UserUpdateAdmin(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	spec := store.commands[req.CommandID]
	if len(spec.Attributes) != 1 || spec.Attributes[0].Name != "display_name" {
		t.Fatal("update command re-applied omitted creation defaults")
	}
	if len(store.fields) != 2 || store.fields[0].Value.Scalar.String != "existing-value" {
		t.Fatal("port model discarded untouched fields")
	}
}

func TestUserUpdateAdminFutureVersionCannotAuthorizeAgainstOlderState(t *testing.T) {
	s, store, req := updateFixture(t)
	req.ExpectedVersion = 3
	original := s.creation.attributes.authorize
	check := queryDecisionFunc(func(ctx context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
		admission, _ := dc.Request.Resource.Attributes["identity.command.read-admission"].Bool()
		status, _ := dc.Request.Resource.Attributes["identity.user.status"].String()
		if !admission && status != "active" {
			return authorization.Decision{}, nil
		}
		return original.Decide(ctx, dc)
	})
	s.creation.attributes.authorize = check
	s.creation.policy.authorize = check
	s.creation.uow = creationOwnerFunc{execute: func(ctx context.Context, c Command) (CommandResult, error) {
		store.mu.Lock()
		store.user.Status = StatusBanned
		store.user.Version = 3
		store.mu.Unlock()
		return store.Execute(ctx, c)
	}}
	got, err := s.UserUpdateAdmin(context.Background(), req)
	var conflict ConflictError
	if !errors.As(err, &conflict) || got.CommitOutcome != CommitOutcomeInvalid || got.User != (User{}) || store.audits != 0 || store.user.Version != 2 {
		t.Fatalf("future-version request crossed older-state authorization: outcome=%v version=%d audits=%d error=%v", got.CommitOutcome, store.user.Version, store.audits, err)
	}
}

func TestUserUpdateAdminStatusChangedAfterReadMustBeFencedByDurableOwner(t *testing.T) {
	s, store, req := updateFixture(t)
	s.creation.uow = creationOwnerFunc{execute: func(ctx context.Context, c Command) (CommandResult, error) {
		store.mu.Lock()
		store.user.Status = StatusDeleted
		store.user.Version++
		store.mu.Unlock()
		return store.Execute(ctx, c)
	}}
	got, err := s.UserUpdateAdmin(context.Background(), req)
	var conflict ConflictError
	if !errors.As(err, &conflict) || got.CommitOutcome != CommitOutcomeConflict || got.User != (User{}) || store.audits != 0 || store.user.Status != StatusDeleted {
		t.Fatal("update raced through terminal-state/version fence")
	}
}

func FuzzUserUpdateCommandAdmission(f *testing.F) {
	f.Add("display_name", "public-example", uint64(2))
	f.Add("status", "active", uint64(1))
	f.Add("label", "", ^uint64(0))
	f.Add("label", "\xff", uint64(1))
	f.Fuzz(func(t *testing.T, name, value string, version uint64) {
		if len(name) > 5000 || len(value) > 5000 {
			return
		}
		binding := CommandBinding{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", TenantID: "tenant-a", UserID: "user-a", ActorID: "actor-a", ActorKind: authorization.SubjectUser, OperationID: "identity.user.update-admin", PolicyID: "policy", PolicyVersion: 1, SchemaID: "profile", SchemaVersion: 1, CorrelationID: "correlation"}
		command, err := NewUserUpdateCommand(UpdateUserCommand{Binding: binding, ExpectedVersion: version, Attributes: []AttributeUpdate{{Name: name, Value: attributeString(value)}}})
		if err != nil {
			if _, ok := command.UpdateUser(); ok {
				t.Fatal("rejected update retained a usable command")
			}
			return
		}
		nameValid := len(name) > 0 && len(name) <= 128
		for i := 0; i < len(name); i++ {
			c := name[i]
			if !(c >= 'a' && c <= 'z' || i > 0 && (c >= '0' && c <= '9' || c == '_')) {
				nameValid = false
			}
		}
		if !nameValid || name == "id" || name == "tenant_id" || name == "status" || name == "version" || version == 0 || version == ^uint64(0) || !utf8.ValidString(value) || len(value) > 4096 {
			t.Fatal("accepted update violated independent wire bounds")
		}
		spec, ok := command.UpdateUser()
		if !ok || spec.ExpectedVersion != version || spec.Binding != binding || len(spec.Attributes) != 1 || spec.Attributes[0].Name != name || spec.Attributes[0].Value.Scalar.String != value {
			t.Fatal("command changed admitted intent")
		}
	})
}
