package session_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func setBinding(s session.SessionSpec, all bool) identity.CommandBinding {
	b := issueBinding(s)
	op := session.RevokeOtherOperation()
	if all {
		op = session.RevokeAllOperation()
	}
	b.OperationID, b.SchemaID, b.SchemaVersion, b.RecordID = op.OperationID, op.SchemaID, op.SchemaVersion, s.SessionID
	return b
}

func TestRevokeSetCommandBindsExactOwnerSourceDispositionAndBounds(t *testing.T) {
	s := sessionSpec(t)
	record, e := session.NewSession(s)
	if e != nil {
		t.Fatal(e)
	}
	for _, all := range []bool{false, true} {
		for _, include := range []bool{false, true} {
			b := setBinding(s, all)
			var command session.SessionCommand
			if all {
				command, e = session.NewRevokeAllCommand(b, record, include, 100)
			} else {
				command, e = session.NewRevokeOtherCommand(b, record, 100)
			}
			if e != nil {
				t.Fatal(e)
			}
			projection, ok := command.RevokeSet()
			if !ok || projection.Binding != b || projection.Caller != record || projection.MaximumSessions != 100 || projection.IncludeCurrent != (all && include) {
				t.Fatal("set projection")
			}
			if _, ok := command.Issue(); ok {
				t.Fatal("set became issuance")
			}
			if _, ok := command.RevokeOne(); ok {
				t.Fatal("set became one")
			}
			if _, ok := command.RevokeFamily(); ok {
				t.Fatal("set became family")
			}
			projection.IncludeCurrent = !projection.IncludeCurrent
			again, _ := command.RevokeSet()
			if again.IncludeCurrent != (all && include) {
				t.Fatal("mutable projection escaped")
			}
		}
	}
	for _, limit := range []uint32{0, 100001} {
		if _, e := session.NewRevokeOtherCommand(setBinding(s, false), record, limit); !errors.Is(e, session.ErrInvalidSessionCommand) {
			t.Fatal("invalid limit")
		}
	}
	for _, mode := range []string{"tenant", "user", "actor", "actor-kind", "record", "operation"} {
		b := setBinding(s, false)
		switch mode {
		case "tenant":
			b.TenantID = "foreign"
		case "user":
			b.UserID = "foreign"
		case "actor":
			b.ActorID = "foreign"
		case "actor-kind":
			b.ActorKind = authorization.SubjectKind("service")
		case "record":
			b.RecordID = string(s.UserID)
		case "operation":
			b.OperationID = "identity.session.revoke-all"
		}
		if _, e := session.NewRevokeOtherCommand(b, record, 10); !errors.Is(e, session.ErrInvalidSessionCommand) {
			t.Fatal("misbound command", mode)
		}
	}
	if _, ok := (session.SessionCommand{}).RevokeSet(); ok {
		t.Fatal("zero command")
	}
}

func TestRevokeSetCustodyPreservesProvenanceFreshnessAndOriginalDeadline(t *testing.T) {
	service, input, clock, observed, config, reader := validationFixture(t)
	caller, e := service.Get(context.Background(), input)
	if e != nil || !caller.Authenticated {
		t.Fatal(e)
	}
	spec, _ := observed.Session.Bindings()
	command, e := session.NewRevokeOtherCommand(setBinding(spec, false), observed.Session, 100)
	if e != nil {
		t.Fatal(e)
	}
	request, e := service.PrepareRevokeSet(caller, command)
	if e != nil {
		t.Fatal(e)
	}
	if request.Caller() != caller.Session || !request.ValidUntil().Equal(caller.ValidUntil()) {
		t.Fatal("custody changed")
	}
	other, e := session.NewSessionService(reader, config)
	if e != nil {
		t.Fatal(e)
	}
	if request.Validate(other, clock.now) == nil {
		t.Fatal("foreign composition admitted")
	}
	if _, e = other.PrepareRevokeSet(caller, command); e == nil {
		t.Fatal("foreign admission prepared")
	}
	if _, e = service.PrepareRevokeSet(session.GetResult{Authenticated: true, Session: caller.Session}, command); e == nil {
		t.Fatal("forged projection admitted")
	}
	copied := request
	clock.now = caller.ValidUntil()
	if copied.Validate(service, clock.now) == nil || request.Validate(service, clock.now) == nil {
		t.Fatal("copied custody renewed")
	}
	if request.Validate(service, spec.IssuedAt.Add(-time.Second)) == nil {
		t.Fatal("backward clock")
	}
	for _, v := range []any{request, copied} {
		if !strings.Contains(fmt.Sprintf("%#v", v), "redacted") {
			t.Fatal("custody disclosure")
		}
		if _, e = json.Marshal(v); !errors.Is(e, session.ErrSecretSerialization) {
			t.Fatal("custody serialization")
		}
	}
	if _, e = request.MarshalText(); !errors.Is(e, session.ErrSecretSerialization) {
		t.Fatal("custody text disclosure")
	}
}

func TestRevokeSetRejectsNonfreshOrSubstitutedCaller(t *testing.T) {
	service, input, clock, observed, _, _ := validationFixture(t)
	spec, _ := observed.Session.Bindings()
	policy, e := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: 24 * time.Hour, IdleTTL: 24 * time.Hour, RefreshAfter: 12 * time.Hour, FreshFor: 15 * time.Minute})
	if e != nil {
		t.Fatal(e)
	}
	spec.Remember = policy
	observed.Session, e = session.NewSession(spec)
	if e != nil {
		t.Fatal(e)
	}
	clock.now = spec.IssuedAt.Add(time.Hour)
	observed.ReadStartedAt, observed.ValidUntil = clock.now, clock.now.Add(20*time.Second)
	caller, e := service.Get(context.Background(), input)
	if e != nil || !caller.Authenticated {
		t.Fatal("nonfresh authentication fixture", e)
	}
	command, e := session.NewRevokeOtherCommand(setBinding(spec, false), observed.Session, 100)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = service.PrepareRevokeSet(caller, command); !errors.Is(e, session.ErrFreshnessRequired) {
		t.Fatal("nonfresh bulk revocation admitted", e)
	}
	clock.now = spec.IssuedAt.Add(time.Minute)
	observed.ReadStartedAt, observed.ValidUntil = clock.now, clock.now.Add(20*time.Second)
	caller, e = service.Get(context.Background(), input)
	if e != nil || !caller.Authenticated {
		t.Fatal(e)
	}
	spec.LastActivityAt = spec.LastActivityAt.Add(time.Second)
	substitute, e := session.NewSession(spec)
	if e != nil {
		t.Fatal(e)
	}
	command, e = session.NewRevokeOtherCommand(setBinding(spec, false), substitute, 100)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = service.PrepareRevokeSet(caller, command); e == nil {
		t.Fatal("same-ID source replacement admitted")
	}
}

func TestRevokeSetFreshnessShortensAdmissionAndExpiresExclusively(t *testing.T) {
	service, input, clock, observed, _, _ := validationFixture(t)
	spec, _ := observed.Session.Bindings()
	policy, e := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: 24 * time.Hour, IdleTTL: 24 * time.Hour, RefreshAfter: 12 * time.Hour, FreshFor: 15 * time.Minute})
	if e != nil {
		t.Fatal(e)
	}
	spec.Remember = policy
	observed.Session, e = session.NewSession(spec)
	if e != nil {
		t.Fatal(e)
	}
	boundary := spec.Authentication.Proof.IssuedAt.Add(15 * time.Minute)
	clock.now = boundary.Add(-5 * time.Second)
	observed.ReadStartedAt, observed.ValidUntil = clock.now, clock.now.Add(20*time.Second)
	caller, e := service.Get(context.Background(), input)
	if e != nil || !caller.Authenticated {
		t.Fatal(e)
	}
	command, e := session.NewRevokeOtherCommand(setBinding(spec, false), observed.Session, 100)
	if e != nil {
		t.Fatal(e)
	}
	request, e := service.PrepareRevokeSet(caller, command)
	if e != nil || !request.ValidUntil().Equal(boundary) || !caller.ValidUntil().After(boundary) {
		t.Fatal("freshness did not narrow authority deadline", e)
	}
	if request.Validate(service, boundary.Add(-time.Nanosecond)) != nil {
		t.Fatal("early freshness expiry")
	}
	clock.now = boundary
	if !errors.Is(request.Validate(service, boundary), session.ErrFreshnessRequired) {
		t.Fatal("inclusive freshness boundary")
	}
	if _, e = service.PrepareRevokeSet(caller, command); !errors.Is(e, session.ErrFreshnessRequired) {
		t.Fatal("repreparation renewed freshness", e)
	}
}
