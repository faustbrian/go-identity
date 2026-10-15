package session_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestUpdatePreservesAllSecurityStateAndOriginalAdmission(t *testing.T) {
	service, input, clock, _, _, _ := validationFixture(t)
	caller, err := service.Get(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	original, _ := caller.Session.Bindings()
	b := issueBinding(original)
	op := session.UpdateOperation()
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	command, err := session.NewUpdateCommand(b, caller.Session, "Personal laptop")
	if err != nil {
		t.Fatal(err)
	}
	transition, ok := command.Update()
	if !ok || transition.Binding != b || transition.Source != caller.Session || transition.DeviceLabel != "Personal laptop" {
		t.Fatal("wrong update")
	}
	next, err := transition.Successor.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	vector, _ := next.Authority.Bindings()
	oldVector, _ := original.Authority.Bindings()
	if next.Version != original.Version+1 || vector.Session.Version != next.Version {
		t.Fatal("CAS not advanced")
	}
	next.Version, vector.Session.Version = original.Version, oldVector.Session.Version
	next.Authority, err = session.NewAuthoritySnapshot(vector)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := next.Authority.Bindings()
	if a != oldVector {
		t.Fatal("other authority changed")
	}
	next.Authority = original.Authority
	if next != original {
		t.Fatal("security state or activity changed")
	}
	request, err := service.PrepareUpdate(caller, command)
	if err != nil || request.Validate(service, clock.now) != nil || !request.ValidUntil().Equal(caller.ValidUntil()) {
		t.Fatal("original custody lost", err)
	}
	clock.now = caller.ValidUntil()
	if request.Validate(service, clock.now) == nil {
		t.Fatal("expired update accepted")
	}
}

func updateBinding(s session.SessionSpec) identity.CommandBinding {
	b := issueBinding(s)
	op := session.UpdateOperation()
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	return b
}

func TestUpdateLabelsBoundsAndClosedVariants(t *testing.T) {
	s := sessionSpec(t)
	source, err := session.NewSession(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, label := range []string{"", "Phone", strings.Repeat("x", 128), strings.Repeat("é", 64), "ノートパソコン"} {
		c, err := session.NewUpdateCommand(updateBinding(s), source, label)
		if err != nil {
			t.Fatal("valid label rejected", err)
		}
		u, ok := c.Update()
		if !ok || u.DeviceLabel != label {
			t.Fatal("label changed")
		}
		if _, ok := c.Issue(); ok {
			t.Fatal("update projected as issue")
		}
		if _, ok := c.Rotation(); ok {
			t.Fatal("update projected as rotation")
		}
		if _, ok := c.RevokeOne(); ok {
			t.Fatal("update projected as one")
		}
		if _, ok := c.RevokeFamily(); ok {
			t.Fatal("update projected as family")
		}
		if _, ok := c.RevokeSet(); ok {
			t.Fatal("update projected as set")
		}
		u.DeviceLabel, u.Binding.UserID, u.Successor = "replacement", "foreign", session.Session{}
		retained, _ := c.Update()
		if retained.DeviceLabel != label || retained.Binding.UserID != s.UserID || retained.Successor == (session.Session{}) {
			t.Fatal("projection mutation escaped")
		}
	}
	for _, label := range []string{strings.Repeat("x", 129), strings.Repeat("é", 65), "\xff", "\x00", "line\nfeed", "tab\t", "\u0085", "\u007f"} {
		c, err := session.NewUpdateCommand(updateBinding(s), source, label)
		if !errors.Is(err, session.ErrInvalidSessionCommand) {
			t.Fatal("malformed label admitted")
		}
		if _, ok := c.Update(); ok {
			t.Fatal("partial invalid command")
		}
	}
	variants := []session.SessionCommand{{}}
	issue, _ := session.NewIssueCommand(issueBinding(s), source)
	oneBinding := issueBinding(s)
	oneOp := session.RevokeOneOperation()
	oneBinding.OperationID, oneBinding.SchemaID = oneOp.OperationID, oneOp.SchemaID
	one, _ := session.NewRevokeOneCommand(oneBinding, source)
	familyBinding := issueBinding(s)
	familyOp := session.RevokeFamilyOperation()
	familyBinding.OperationID, familyBinding.SchemaID, familyBinding.RecordID = familyOp.OperationID, familyOp.SchemaID, s.FamilyID
	family, _ := session.NewRevokeFamilyCommand(familyBinding, s.FamilyVersion)
	set, _ := session.NewRevokeOtherCommand(setBinding(s, false), source, 100)
	variants = append(variants, issue, one, family, set)
	_, p, _, _, _, _ := rotationFixture(t)
	rotationRequest, _ := p.Request()
	rotation, _ := rotationRequest.Command()
	variants = append(variants, rotation)
	for _, c := range variants {
		if _, ok := c.Update(); ok {
			t.Fatal("other variant projected as update")
		}
		if !errors.Is(c.ValidateUpdateAt(s.IssuedAt), session.ErrInvalidSessionCommand) {
			t.Fatal("wrong variant validated")
		}
	}
}

func TestUpdateRejectsMisboundActorsSchemaAndVersionOverflow(t *testing.T) {
	s := sessionSpec(t)
	source, _ := session.NewSession(s)
	for _, mutate := range []func(*identity.CommandBinding){
		func(b *identity.CommandBinding) { b.TenantID = "foreign" },
		func(b *identity.CommandBinding) { b.UserID = "foreign" },
		func(b *identity.CommandBinding) { b.ActorID = "foreign" },
		func(b *identity.CommandBinding) { b.ActorKind = authorization.SubjectServiceAccount },
		func(b *identity.CommandBinding) { b.RecordID = s.FamilyID },
		func(b *identity.CommandBinding) { b.OperationID = session.RotateOperation().OperationID },
		func(b *identity.CommandBinding) { b.SchemaID = "foreign" },
		func(b *identity.CommandBinding) { b.SchemaVersion++ },
		func(b *identity.CommandBinding) { b.PolicyVersion = 0 },
		func(b *identity.CommandBinding) { b.CommandID = "invalid" },
	} {
		b := updateBinding(s)
		mutate(&b)
		if _, err := session.NewUpdateCommand(b, source, "label"); !errors.Is(err, session.ErrInvalidSessionCommand) {
			t.Fatal("misbound command admitted")
		}
	}
	s.Version = ^uint64(0)
	vector, _ := s.Authority.Bindings()
	vector.Session.Version = s.Version
	s.Authority, _ = session.NewAuthoritySnapshot(vector)
	source, err := session.NewSession(s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = session.NewUpdateCommand(updateBinding(s), source, ""); !errors.Is(err, session.ErrInvalidSessionCommand) {
		t.Fatal("version wrapped")
	}
	if _, err = session.NewUpdateCommand(identity.CommandBinding{}, session.Session{}, ""); !errors.Is(err, session.ErrInvalidSessionCommand) {
		t.Fatal("zero accepted")
	}
}

func TestUpdateRequiresOriginalSelfCustodyWithoutRenewingFreshness(t *testing.T) {
	service, input, clock, observed, cfg, reader := validationFixture(t)
	spec, _ := observed.Session.Bindings()
	lifetimeConfig := config()
	lifetimeConfig.FreshFor = 15 * time.Minute
	spec.Remember, _ = session.ResolveRememberPolicy(session.PersistentSession, lifetimeConfig)
	observed.Session, _ = session.NewSession(spec)
	policy, _ := spec.Remember.Bindings()
	clock.now = spec.IssuedAt.Add(policy.FreshFor + time.Second)
	// Ordinary metadata is allowed after login freshness expires, while the
	// authoritative source read and session lifetime are still valid.
	observed.ReadStartedAt, observed.ValidUntil = clock.now, clock.now.Add(20*time.Second)
	caller, err := service.Get(context.Background(), input)
	if err != nil || !caller.Authenticated {
		t.Fatal(err)
	}
	command, err := session.NewUpdateCommand(updateBinding(spec), caller.Session, "My device")
	if err != nil {
		t.Fatal(err)
	}
	request, err := service.PrepareUpdate(caller, command)
	if err != nil || request.Transport() != session.CredentialCookie {
		t.Fatal("safe metadata demanded reauthentication", err)
	}
	copy := request
	clock.now = clock.now.Add(time.Second)
	again, err := service.PrepareUpdate(caller, command)
	if err != nil || !again.ValidUntil().Equal(request.ValidUntil()) || !copy.ValidUntil().Equal(request.ValidUntil()) {
		t.Fatal("copy renewed admission")
	}
	foreign, _ := session.NewSessionService(reader, cfg)
	if _, err = foreign.PrepareUpdate(caller, command); !errors.Is(err, session.ErrUnauthenticated) {
		t.Fatal("foreign reader admitted")
	}
	if request.Validate(foreign, clock.now) == nil {
		t.Fatal("foreign reader validated custody")
	}
	forged := session.GetResult{Authenticated: true, Session: caller.Session}
	if _, err = service.PrepareUpdate(forged, command); !errors.Is(err, session.ErrUnauthenticated) {
		t.Fatal("fabricated caller admitted")
	}
	modified := caller
	modified.Authenticated = false
	if _, err = service.PrepareUpdate(modified, command); !errors.Is(err, session.ErrUnauthenticated) {
		t.Fatal("modified caller admitted")
	}
	changed := spec
	changed.LastActivityAt = changed.LastActivityAt.Add(time.Second)
	other, _ := session.NewSession(changed)
	modified = caller
	modified.Session = other
	if _, err = service.PrepareUpdate(modified, command); !errors.Is(err, session.ErrUnauthenticated) {
		t.Fatal("public replacement admitted")
	}
	otherCommand, _ := session.NewUpdateCommand(updateBinding(changed), other, "My device")
	if _, err = service.PrepareUpdate(caller, otherCommand); !errors.Is(err, session.ErrUnauthenticated) {
		t.Fatal("same-ID record substituted")
	}
	if _, err = service.PrepareUpdate(caller, session.SessionCommand{}); !errors.Is(err, session.ErrInvalidSessionCommand) {
		t.Fatal("zero command admitted")
	}
	clock.now = caller.ValidUntil()
	if _, err = service.PrepareUpdate(caller, command); !errors.Is(err, session.ErrUnauthenticated) {
		t.Fatal("expired preparation admitted")
	}
	if request.Validate(service, clock.now) == nil || copy.Validate(service, clock.now) == nil {
		t.Fatal("exclusive deadline extended")
	}
	if request.Validate(service, observed.ReadStartedAt.Add(-time.Second)) == nil {
		t.Fatal("backward clock accepted")
	}
}

func TestUpdateBearerConservationRedactionAndConcurrentCopies(t *testing.T) {
	_, p, _, clock, service, caller := rotationTransportFixture(t, session.CredentialBearer)
	rotationRequest, _ := p.Request()
	rotateCommand, _ := rotationRequest.Command()
	rotation, _ := rotateCommand.Rotation()
	original, _ := rotation.Source.Bindings()
	command, err := session.NewUpdateCommand(updateBinding(original), caller.Session, "private label")
	if err != nil {
		t.Fatal(err)
	}
	request, err := service.PrepareUpdate(caller, command)
	if err != nil || request.Transport() != session.CredentialBearer {
		t.Fatal("bearer converted", err)
	}
	u, _ := command.Update()
	for _, v := range []any{command, u, request} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
			out := fmt.Sprintf(format, v)
			if strings.Contains(out, u.DeviceLabel) || strings.Contains(out, string(original.UserID)) {
				t.Fatal("diagnostic disclosure")
			}
		}
		if _, err := json.Marshal(v); !errors.Is(err, session.ErrSecretSerialization) {
			t.Fatal("implicit JSON export")
		}
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			c, ok := request.Command()
			projected, valid := c.Update()
			if !ok || !valid || projected.DeviceLabel != "private label" || request.Validate(service, clock.now) != nil {
				t.Error("concurrent immutable custody")
			}
		})
	}
	wg.Wait()
	var zero session.UpdateCommandRequest
	if _, ok := zero.Command(); ok || zero.Transport() != 0 || !zero.ValidUntil().IsZero() || zero.Validate(service, clock.now) == nil {
		t.Fatal("zero request usable")
	}
	var absent *session.SessionService
	if _, err := absent.PrepareUpdate(caller, command); !errors.Is(err, session.ErrInvalidInput) {
		t.Fatal("nil service accepted")
	}
	if _, err := u.MarshalText(); !errors.Is(err, session.ErrSecretSerialization) {
		t.Fatal("implicit label text export")
	}
	if _, err := request.MarshalText(); !errors.Is(err, session.ErrSecretSerialization) {
		t.Fatal("implicit request text export")
	}
	clock.panicNow = true
	failed, err := service.PrepareUpdate(caller, command)
	if !errors.Is(err, session.ErrUnavailable) {
		t.Fatal("clock panic escaped")
	}
	if _, ok := failed.Command(); ok {
		t.Fatal("clock failure returned custody")
	}
}
