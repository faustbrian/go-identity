package identity

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
)

// A locked port model proves core semantics, not PostgreSQL durability.
type profileOwner struct {
	mu            sync.Mutex
	record        ProfileRecord
	commands      map[CommandID]ProfileUpdateCommand
	results       map[CommandID]CommandResult
	audits, reads int
	loseReply     bool
}

func (o *profileOwner) GetProfile(ctx context.Context, q ProfileQuery) (ProfileRecord, error) {
	if _, ok := ctx.Deadline(); !ok {
		panic("unbounded profile read")
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.reads++
	if q.TenantID != o.record.User.TenantID || q.UserID != o.record.User.ID {
		return ProfileRecord{}, ErrUserAbsent
	}
	r := o.record
	r.Profile.AdditionalFields = cloneUpdates(r.Profile.AdditionalFields)
	return r, nil
}

func (o *profileOwner) Execute(ctx context.Context, command Command) (CommandResult, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	spec, ok := command.UpdateProfile()
	if !ok {
		panic("wrong command")
	}
	if prior, ok := o.commands[spec.Binding.CommandID]; ok {
		if !reflect.DeepEqual(prior, spec) {
			return CommandResult{Binding: spec.Binding, Outcome: CommitOutcomeConflict}, nil
		}
		return o.results[spec.Binding.CommandID], nil
	}
	if o.record.User.Version != spec.ExpectedVersion || o.record.User.Status != StatusActive {
		return CommandResult{Binding: spec.Binding, Outcome: CommitOutcomeConflict}, nil
	}
	o.record.User.Version++
	o.record.Profile.Version = o.record.User.Version
	if spec.Name != "" {
		o.record.Profile.Name = spec.Name
	}
	if spec.Image != "" {
		o.record.Profile.Image = spec.Image
	}
	for _, field := range spec.AdditionalFields {
		found := false
		for i, old := range o.record.Profile.AdditionalFields {
			if old.Name == field.Name {
				o.record.Profile.AdditionalFields[i] = cloneUpdates([]AttributeUpdate{field})[0]
				found = true
				break
			}
		}
		if !found {
			o.record.Profile.AdditionalFields = append(o.record.Profile.AdditionalFields, cloneUpdates([]AttributeUpdate{field})[0])
		}
	}
	o.audits++
	profile := o.record.Profile
	profile.AdditionalFields = cloneUpdates(profile.AdditionalFields)
	r := CommandResult{Binding: spec.Binding, Outcome: CommitOutcomeCommitted, User: o.record.User, Profile: &profile, ExpectedVersion: spec.ExpectedVersion, AuditEventID: "profile-audit"}
	o.commands[spec.Binding.CommandID] = spec
	o.results[spec.Binding.CommandID] = r
	if o.loseReply {
		return CommandResult{Binding: spec.Binding, Outcome: CommitOutcomeUnknown}, errors.New("private lost reply")
	}
	return r, nil
}

func (o *profileOwner) Recover(ctx context.Context, q RecoveryQuery) (CommandResult, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	r, ok := o.results[q.CommandID]
	if !ok || r.Binding.TenantID != q.TenantID || r.Binding.UserID != q.UserID || r.Binding.ActorID != q.ActorID || r.Binding.ActorKind != q.ActorKind {
		return CommandResult{}, errors.New("private absent")
	}
	return r, nil
}

func profileFixture(t *testing.T) (*ProfileService, *profileOwner, ProfileGetRequest, ProfileUpdateRequest) {
	t.Helper()
	create, _, creation := creationFixture(t)
	schema := create.attributes.schema
	schema.Fields[0].WriteAuthorization = FieldWriteSelf
	owner := &profileOwner{record: ProfileRecord{User: User{ID: creation.UserID, TenantID: creation.TenantID, Status: StatusActive, Version: 2}, Profile: UserProfile{ID: creation.UserID, TenantID: creation.TenantID, Name: "example", Image: "https://images.example/a.png", Version: 2}}, commands: make(map[CommandID]ProfileUpdateCommand), results: make(map[CommandID]CommandResult)}
	config := ProfileConfig{Fields: UserCreationConfig{Query: create.policy.config, Schema: schema, Normalize: create.attributes.normalize, ValidateValue: create.attributes.config.ValidateValue}, AllowedImageOrigins: []string{"https://images.example"}}
	service, err := NewProfileService(owner, owner, create.policy.authorize, queryRedact, config)
	if err != nil {
		t.Fatal(err)
	}
	scope := creation.ActorScope.Clone()
	scope.Request.Subject.ID = authorization.SubjectID(creation.UserID)
	scope.Request.Action = "identity.profile.get"
	get := ProfileGetRequest{TenantID: creation.TenantID, Context: scope}
	scope = scope.Clone()
	scope.Request.Action = "identity.profile.update"
	update := ProfileUpdateRequest{TenantID: creation.TenantID, Context: scope, CommandID: creation.CommandID, SchemaVersion: 1, ExpectedVersion: 2, Name: "changed", Image: "https://images.example/b.png", AdditionalFields: creation.Fields}
	return service, owner, get, update
}

func TestProfileGetAndUpdateUseSafeSelfProjectionAndReplay(t *testing.T) {
	s, owner, get, req := profileFixture(t)
	got, err := s.ProfileGet(context.Background(), get)
	if err != nil || got.User.ID != owner.record.User.ID || got.Version != 2 || got.User.Name != "example" {
		t.Fatalf("profile read: %+v %v", got, err)
	}
	updated, err := s.ProfileUpdate(context.Background(), req)
	if err != nil || updated.CommitOutcome != CommitOutcomeCommitted || updated.InvalidationVersion != 3 || updated.User.Name != "changed" || updated.User.Image != "https://images.example/b.png" || len(updated.User.AdditionalFields) != 1 {
		t.Fatalf("profile update: %+v %v", updated, err)
	}
	again, err := s.ProfileUpdate(context.Background(), req)
	if err != nil || !reflect.DeepEqual(again, updated) || owner.audits != 1 || owner.record.User.Version != 3 {
		t.Fatal("profile replay repeated write/audit")
	}
}

func TestProfileGetRejectsForeignTargetOrNonhumanBeforeRead(t *testing.T) {
	for _, kind := range []string{"target", "tenant", "apikey", "service"} {
		t.Run(kind, func(t *testing.T) {
			s, owner, get, _ := profileFixture(t)
			switch kind {
			case "target":
				get.Context.Request.Resource.ID = "other"
			case "tenant":
				get.Context.Request.Tenant = "other"
			case "apikey":
				get.Context.Request.Subject.Kind = authorization.SubjectAPIKey
			case "service":
				get.Context.Request.Subject.Kind = authorization.SubjectServiceAccount
			}
			got, err := s.ProfileGet(context.Background(), get)
			if err == nil || !reflect.DeepEqual(got, ProfileGetResult{}) || owner.reads != 0 {
				t.Fatal("foreign/nonhuman profile read reached store")
			}
		})
	}
}

func TestProfileUpdateLostReplyRecoveryDoesNotExecuteAgain(t *testing.T) {
	s, owner, _, req := profileFixture(t)
	owner.loseReply = true
	got, err := s.ProfileUpdate(context.Background(), req)
	var unknown UnknownCommitError
	if !errors.As(err, &unknown) || got.CommitOutcome != CommitOutcomeUnknown || owner.audits != 1 {
		t.Fatal("lost reply inferred rollback")
	}
	recovered, err := s.RecoverProfileUpdate(context.Background(), ProfileRecoveryRequest{TenantID: req.TenantID, CommandID: req.CommandID, Context: req.Context})
	if err != nil || recovered.CommitOutcome != CommitOutcomeCommitted || recovered.InvalidationVersion != 3 || owner.audits != 1 {
		t.Fatal("recovery lost or repeated profile commit")
	}
}

type profileReadFunc func(context.Context, ProfileQuery) (ProfileRecord, error)

func (f profileReadFunc) GetProfile(ctx context.Context, q ProfileQuery) (ProfileRecord, error) {
	return f(ctx, q)
}

func TestProfileUpdateAdmissionRejectsInvalidOrPrivilegedFields(t *testing.T) {
	for _, mode := range []string{"empty", "name", "image-size", "image-origin", "image-http", "image-userinfo", "image-fragment", "empty-fragment", "image-port", "utf8", "email", "status", "roles", "name-field", "zero-version", "future-version", "overflow", "schema", "admin-field", "input-denied", "unknown", "duplicate", "too-many"} {
		t.Run(mode, func(t *testing.T) {
			s, owner, _, req := profileFixture(t)
			switch mode {
			case "empty":
				req.Name = ""
				req.Image = ""
				req.AdditionalFields = nil
			case "name":
				req.Name = strings.Repeat("x", 257)
			case "image-size":
				req.Image = "https://images.example/" + strings.Repeat("a", 2048)
			case "image-origin":
				req.Image = "https://evil.example/a"
			case "image-http":
				req.Image = "http://images.example/a"
			case "image-userinfo":
				req.Image = "https://user@images.example/a"
			case "image-fragment":
				req.Image = "https://images.example/a#fragment"
			case "empty-fragment":
				req.Image = "https://images.example/a#"
			case "image-port":
				req.Image = "https://images.example:443/a"
			case "utf8":
				req.Name = "\xff"
			case "email", "status", "roles":
				req.AdditionalFields[0].Name = mode
			case "name-field":
				req.AdditionalFields[0].Name = "name"
			case "zero-version":
				req.ExpectedVersion = 0
			case "future-version":
				req.ExpectedVersion = 3
			case "overflow":
				req.ExpectedVersion = ^uint64(0)
			case "schema":
				req.SchemaVersion = 2
			case "admin-field":
				s.creation.attributes.schema.Fields[0].WriteAuthorization = FieldWriteAdministrator
			case "input-denied":
				s.creation.attributes.schema.Fields[0].InputPermission = FieldDenied
			case "unknown":
				req.AdditionalFields[0].Name = "unknown"
			case "duplicate":
				req.AdditionalFields = append(req.AdditionalFields, req.AdditionalFields[0])
			case "too-many":
				req.AdditionalFields = make([]AttributeUpdate, 65)
			}
			got, err := s.ProfileUpdate(context.Background(), req)
			if err == nil || got.CommitOutcome != CommitOutcomeInvalid || got.User.ID != "" || owner.audits != 0 || owner.record.User.Version != 2 {
				t.Fatal("invalid profile request mutated or claimed durable outcome")
			}
		})
	}
}

func TestProfileReadFailsClosedOnInvalidRecordAndDependencyFailure(t *testing.T) {
	for _, mode := range []string{"absent", "error", "foreign", "version", "blocked", "deleted", "bad-field", "field-type", "duplicate", "image", "panic", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			s, owner, get, _ := profileFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s.repo = profileReadFunc(func(ctx context.Context, q ProfileQuery) (ProfileRecord, error) {
				if len(q.Fields) < 5 {
					t.Fatal("missing safe projection")
				}
				for _, f := range q.Fields {
					if f.Value == "status" || f.Value == "email" || f.Value == "roles" {
						t.Fatal("privileged data requested in profile")
					}
				}
				r := owner.record
				switch mode {
				case "absent":
					return ProfileRecord{}, ErrUserAbsent
				case "error":
					return r, errors.New("private driver")
				case "foreign":
					r.Profile.TenantID = "foreign"
				case "version":
					r.Profile.Version++
				case "blocked":
					r.User.Status = StatusBanned
				case "deleted":
					r.User.Status = StatusDeleted
				case "bad-field":
					r.Profile.AdditionalFields = []AttributeUpdate{{Name: "email", Value: attributeString("forbidden")}}
				case "field-type":
					r.Profile.AdditionalFields = []AttributeUpdate{{Name: "display_name", Value: AttributeValue{Kind: AttributeBool, Scalar: AttributeScalar{Kind: AttributeBool, Bool: true}}}}
				case "duplicate":
					r.Profile.AdditionalFields = []AttributeUpdate{{Name: "display_name", Value: attributeString("a")}, {Name: "display_name", Value: attributeString("b")}}
				case "image":
					r.Profile.Image = "https://evil.example/a"
				case "panic":
					panic("private read")
				case "cancel":
					cancel()
				}
				return r, nil
			})
			got, err := s.ProfileGet(ctx, get)
			if err == nil || !reflect.DeepEqual(got, ProfileGetResult{}) || strings.Contains(err.Error(), "private") {
				t.Fatal("invalid record produced public output")
			}
		})
	}
}

func TestProfileOutputPermissionsAndRedactionFilterCopies(t *testing.T) {
	s, owner, get, _ := profileFixture(t)
	owner.record.Profile.AdditionalFields = []AttributeUpdate{{Name: "display_name", Value: attributeString("stored")}}
	s.creation.policy.redact = func(ctx context.Context, in RedactionPolicyInput) (RedactionPolicyDecision, error) {
		visible := []FieldName{{"id"}, {"tenant_id"}, {"version"}, {"display_name"}}
		return RedactionPolicyDecision{VisibleFields: visible, RedactedFields: []FieldName{{"name"}, {"image"}}, PolicyID: "identity-read", PolicyVersion: 1, Reason: "projection-visible"}, nil
	}
	got, err := s.ProfileGet(context.Background(), get)
	if err != nil || got.User.Name != "" || got.User.Image != "" || len(got.User.AdditionalFields) != 1 {
		t.Fatal("valid redaction was not applied")
	}
	got.User.AdditionalFields[0].Value = attributeString("changed output")
	if owner.record.Profile.AdditionalFields[0].Value.Scalar.String != "stored" {
		t.Fatal("profile output aliases store")
	}
	s.creation.attributes.schema.Fields[0].OutputPermission = FieldDenied
	s.creation.policy.redact = queryRedact
	got, err = s.ProfileGet(context.Background(), get)
	if err != nil || len(got.User.AdditionalFields) != 0 {
		t.Fatal("non-readable additional field escaped output policy")
	}
}

func TestProfileRejectsMalformedRedactionPartitions(t *testing.T) {
	for _, mode := range []string{"missing", "duplicate", "foreign", "policy", "reason", "mandatory", "panic", "error"} {
		t.Run(mode, func(t *testing.T) {
			s, _, get, _ := profileFixture(t)
			s.creation.policy.redact = func(ctx context.Context, in RedactionPolicyInput) (RedactionPolicyDecision, error) {
				d, _ := queryRedact(ctx, in)
				switch mode {
				case "missing":
					d.VisibleFields = d.VisibleFields[1:]
				case "duplicate":
					d.VisibleFields[1] = d.VisibleFields[0]
				case "foreign":
					d.VisibleFields[1] = FieldName{"status"}
				case "policy":
					d.PolicyVersion++
				case "reason":
					d.Reason = "unknown"
				case "mandatory":
					d.RedactedFields = d.VisibleFields[:1]
					d.VisibleFields = d.VisibleFields[1:]
				case "panic":
					panic("private callback")
				case "error":
					return d, errors.New("private callback")
				}
				return d, nil
			}
			got, err := s.ProfileGet(context.Background(), get)
			if err == nil || !reflect.DeepEqual(got, ProfileGetResult{}) {
				t.Fatal("malformed redaction disclosed profile")
			}
		})
	}
}

func TestProfileKnownCommitSurvivesOutputFailureAndRecoveryDenial(t *testing.T) {
	for _, mode := range []string{"deny", "panic", "cancel", "dependency"} {
		t.Run(mode, func(t *testing.T) {
			s, owner, _, req := profileFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "dependency" {
				s.creation.uow = creationOwnerFunc{execute: func(ctx context.Context, c Command) (CommandResult, error) {
					r, _ := owner.Execute(ctx, c)
					return r, errors.New("private dependency")
				}}
			} else {
				s.creation.policy.redact = func(context.Context, RedactionPolicyInput) (RedactionPolicyDecision, error) {
					if mode == "panic" {
						panic("private projection")
					}
					if mode == "cancel" {
						cancel()
					}
					return RedactionPolicyDecision{}, nil
				}
			}
			got, err := s.ProfileUpdate(ctx, req)
			if err == nil || got.CommitOutcome != CommitOutcomeCommitted || got.User.ID != "" || got.InvalidationVersion != 0 || owner.audits != 1 {
				t.Fatal("output failure lost known commit or exposed output")
			}
		})
	}
	s, owner, _, req := profileFixture(t)
	if _, err := s.ProfileUpdate(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	s.creation.policy.redact = func(context.Context, RedactionPolicyInput) (RedactionPolicyDecision, error) {
		return RedactionPolicyDecision{}, nil
	}
	got, err := s.RecoverProfileUpdate(context.Background(), ProfileRecoveryRequest{req.TenantID, req.CommandID, req.Context})
	if err == nil || got.CommitOutcome != CommitOutcomeCommitted || got.User.ID != "" || owner.audits != 1 {
		t.Fatal("recovery denial lost commit")
	}
}

func TestProfileFencesConcurrentWritesAndChangedIntent(t *testing.T) {
	s, owner, _, req := profileFixture(t)
	other := req
	other.CommandID = "AgICAgICAgICAgICAgICAg"
	start := make(chan struct{})
	results := make(chan ProfileUpdateResult, 2)
	var wg sync.WaitGroup
	for _, request := range []ProfileUpdateRequest{req, other} {
		wg.Add(1)
		go func(request ProfileUpdateRequest) {
			defer wg.Done()
			<-start
			got, _ := s.ProfileUpdate(context.Background(), request)
			results <- got
		}(request)
	}
	close(start)
	wg.Wait()
	close(results)
	commits, conflicts := 0, 0
	for got := range results {
		if got.CommitOutcome == CommitOutcomeCommitted {
			commits++
		}
		if got.CommitOutcome == CommitOutcomeConflict {
			conflicts++
		}
	}
	if commits != 1 || conflicts != 1 || owner.audits != 1 || owner.record.User.Version != 3 {
		t.Fatal("profile concurrent CAS failed")
	}
	for id := range owner.commands {
		req.CommandID = id
	}
	req.Name = "different intent"
	got, err := s.ProfileUpdate(context.Background(), req)
	var conflict ConflictError
	if !errors.As(err, &conflict) || got.CommitOutcome != CommitOutcomeConflict || owner.audits != 1 {
		t.Fatal("same command changed intent was accepted")
	}
}

func TestProfileCurrentStateAndTimeAreTrustedAndFenced(t *testing.T) {
	s, owner, _, req := profileFixture(t)
	samples := 0
	s.creation.policy.config.Clock = queryClockFunc(func() time.Time { samples++; return queryClock{}.Now() })
	req.Context.Request.Resource.Attributes = authorization.Attributes{"identity.user.status": authorization.StringValue("forged"), "identity.user.version": authorization.StringValue("999"), "identity.command.recovery": authorization.BoolValue(true)}
	original := s.creation.attributes.authorize
	check := queryDecisionFunc(func(ctx context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
		admission, _ := dc.Request.Resource.Attributes["identity.command.read-admission"].Bool()
		if !admission {
			status, _ := dc.Request.Resource.Attributes["identity.user.status"].String()
			version, _ := dc.Request.Resource.Attributes["identity.user.version"].String()
			if status != "active" || version != "2" {
				t.Fatal("caller state reached apply policy")
			}
		}
		return original.Decide(ctx, dc)
	})
	s.creation.attributes.authorize = check
	s.creation.uow = creationOwnerFunc{execute: func(ctx context.Context, c Command) (CommandResult, error) {
		owner.mu.Lock()
		owner.record.User.Status = StatusBanned
		owner.record.User.Version++
		owner.record.Profile.Version++
		owner.mu.Unlock()
		return owner.Execute(ctx, c)
	}}
	got, err := s.ProfileUpdate(context.Background(), req)
	var conflict ConflictError
	if !errors.As(err, &conflict) || got.CommitOutcome != CommitOutcomeConflict || samples != 1 || owner.audits != 0 {
		t.Fatal("profile status race escaped CAS or sampled extra time")
	}
}

func TestProfileCommandIsClosedAndCopiesTypedValues(t *testing.T) {
	s, owner, _, req := profileFixture(t)
	if _, err := s.ProfileUpdate(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	spec := owner.commands[req.CommandID]
	spec.AdditionalFields = []AttributeUpdate{{Name: "labels", Value: AttributeValue{Kind: AttributeStringList, List: []AttributeScalar{{Kind: AttributeString, String: "first"}}}}}
	c, err := NewProfileUpdateCommand(spec)
	if err != nil {
		t.Fatal(err)
	}
	spec.AdditionalFields[0].Value.List[0].String = "changed"
	a, ok := c.UpdateProfile()
	if !ok || a.AdditionalFields[0].Value.List[0].String != "first" {
		t.Fatal("command aliases input")
	}
	a.AdditionalFields[0].Value.List[0].String = "changed accessor"
	b, _ := c.UpdateProfile()
	if b.AdditionalFields[0].Value.List[0].String != "first" {
		t.Fatal("command accessor aliases internal values")
	}
	if _, ok := c.CreateUser(); ok {
		t.Fatal("profile exposed create variant")
	}
	if _, ok := c.UpdateUser(); ok {
		t.Fatal("profile exposed admin variant")
	}
	if _, ok := (Command{}).UpdateProfile(); ok {
		t.Fatal("zero profile command accepted")
	}
	spec.Binding.ActorID = "foreign"
	if _, err := NewProfileUpdateCommand(spec); err == nil {
		t.Fatal("foreign actor command accepted")
	}
}

func TestProfileGetPolicySeesAuthoritativeStateBeforeDisclosure(t *testing.T) {
	s, _, get, _ := profileFixture(t)
	original := s.creation.attributes.authorize
	observed := false
	s.creation.attributes.authorize = queryDecisionFunc(func(ctx context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
		admission, _ := dc.Request.Resource.Attributes["identity.command.read-admission"].Bool()
		if !admission {
			observed = true
			status, _ := dc.Request.Resource.Attributes["identity.user.status"].String()
			version, _ := dc.Request.Resource.Attributes["identity.user.version"].String()
			if status != "active" || version != "2" {
				t.Fatal("read disclosure used untrusted state")
			}
			return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, nil
		}
		return original.Decide(ctx, dc)
	})
	got, err := s.ProfileGet(context.Background(), get)
	var forbidden ForbiddenError
	if !observed || !errors.As(err, &forbidden) || got.User.ID != "" {
		t.Fatal("profile get skipped authoritative-state policy")
	}
}

func TestProfileMalformedReceiptsRemainUnknownAndPurposeFenced(t *testing.T) {
	for _, mode := range []string{"nil-profile", "profile-id", "profile-version", "profile-field", "profile-image", "expected", "actor", "purpose", "audit", "noncommit-profile", "panic-execute"} {
		t.Run(mode, func(t *testing.T) {
			s, owner, _, req := profileFixture(t)
			s.creation.uow = creationOwnerFunc{execute: func(ctx context.Context, c Command) (CommandResult, error) {
				if mode == "panic-execute" {
					panic("private execute")
				}
				r, _ := owner.Execute(ctx, c)
				profile := *r.Profile
				r.Profile = &profile
				switch mode {
				case "nil-profile":
					r.Profile = nil
				case "profile-id":
					r.Profile.ID = "foreign"
				case "profile-version":
					r.Profile.Version++
				case "profile-field":
					r.Profile.AdditionalFields = []AttributeUpdate{{Name: "status", Value: attributeString("active")}}
				case "profile-image":
					r.Profile.Image = "https://evil.example/a"
				case "expected":
					r.ExpectedVersion++
				case "actor":
					r.Binding.ActorID = "foreign"
				case "purpose":
					r.Binding.OperationID = "identity.user.update-admin"
				case "audit":
					r.AuditEventID = ""
				case "noncommit-profile":
					r.Outcome = CommitOutcomeConflict
				}
				return r, nil
			}}
			got, err := s.ProfileUpdate(context.Background(), req)
			if mode == "profile-image" {
				if err == nil || got.CommitOutcome != CommitOutcomeCommitted || got.User.ID != "" {
					t.Fatal("known commit lost after projection validation failure")
				}
				return
			}
			var unknown UnknownCommitError
			if !errors.As(err, &unknown) || got.CommitOutcome != CommitOutcomeUnknown || got.User.ID != "" {
				t.Fatal("malformed/ambiguous receipt became known or disclosed")
			}
		})
	}
}

func TestProfileRecoveryPanicRemainsUnknownAndCurrentDenyPreventsLookup(t *testing.T) {
	s, owner, _, req := profileFixture(t)
	if _, err := s.ProfileUpdate(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	s.creation.uow = creationOwnerFunc{recover: func(context.Context, RecoveryQuery) (CommandResult, error) { panic("private recovery") }}
	got, err := s.RecoverProfileUpdate(context.Background(), ProfileRecoveryRequest{req.TenantID, req.CommandID, req.Context})
	var unknown UnknownCommitError
	if !errors.As(err, &unknown) || got.CommitOutcome != CommitOutcomeUnknown || got.User.ID != "" {
		t.Fatal("recovery panic claimed rollback or known result")
	}
	s.creation.attributes.authorize = queryDecisionFunc(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
		return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, nil
	})
	got, err = s.RecoverProfileUpdate(context.Background(), ProfileRecoveryRequest{req.TenantID, req.CommandID, req.Context})
	var forbidden ForbiddenError
	if !errors.As(err, &forbidden) || got.CommitOutcome != CommitOutcomeInvalid || owner.audits != 1 {
		t.Fatal("current denial reached recovery owner")
	}
}

func TestProfileConfigurationIsBoundedAndSnapshotOwned(t *testing.T) {
	s, owner, _, req := profileFixture(t)
	config := ProfileConfig{Fields: UserCreationConfig{Query: s.creation.policy.config, Schema: s.creation.attributes.schema, Normalize: s.creation.attributes.normalize, ValidateValue: s.creation.attributes.config.ValidateValue}, AllowedImageOrigins: []string{"https://images.example"}}
	for _, origins := range [][]string{nil, {}, {"https://:443"}, {"https://images.example:"}, {"https://images.example/"}, {"https://images.example#"}, {"https://images.example?"}, {"http://images.example"}, {"https://user@images.example"}, {"https://images.example", "https://images.example"}, {strings.Repeat("a", 2049)}, make([]string, 33)} {
		bad := config
		bad.AllowedImageOrigins = origins
		if got, err := NewProfileService(owner, owner, s.creation.attributes.authorize, queryRedact, bad); got != nil || err == nil {
			t.Fatal("invalid image configuration accepted")
		}
	}
	copyService, err := NewProfileService(owner, owner, s.creation.attributes.authorize, queryRedact, config)
	if err != nil {
		t.Fatal(err)
	}
	config.AllowedImageOrigins[0] = "https://evil.example"
	if _, err := copyService.ProfileUpdate(context.Background(), req); err != nil {
		t.Fatal("origin config aliased caller slice")
	}
	if got := fmt.Sprintf("%#v", owner.record.Profile); strings.Contains(got, "changed") || strings.Contains(got, "https://") {
		t.Fatal("implicit profile formatting exposed contents")
	}
}

func TestProfileNameOnlyPreservesOmittedFieldsAndImage(t *testing.T) {
	s, owner, _, req := profileFixture(t)
	req.Image = ""
	req.AdditionalFields = nil
	got, err := s.ProfileUpdate(context.Background(), req)
	if err != nil || got.User.Name != "changed" || got.User.Image != "https://images.example/a.png" || len(got.User.AdditionalFields) != 0 || owner.audits != 1 {
		t.Fatal("name-only command lost omitted fields or applied creation defaults")
	}
}

func FuzzProfileImageAdmission(f *testing.F) {
	for _, seed := range []string{"https://images.example/a", "https://images.example#", "https://images.example.evil/a", "https://user@images.example/a", "https://:443", "https://images.example:/a", "data:image/png;base64,AAAA", "\xff"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 4096 {
			return
		}
		s := ProfileService{origins: []string{"https://images.example"}}
		got, err := s.image(raw)
		if err != nil {
			if got != "" {
				t.Fatal("invalid image returned output")
			}
			return
		}
		if raw == "" {
			if got != "" {
				t.Fatal("omitted image changed")
			}
			return
		}
		u, err := url.Parse(got)
		if err != nil || u.Scheme != "https" || u.Host != "images.example" || u.User != nil || strings.Contains(raw, "#") || len(raw) > 2048 {
			t.Fatal("image escaped independent origin/bounds oracle")
		}
	})
}
