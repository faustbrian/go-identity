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
	"github.com/faustbrian/go-identity/session"
)

func TestRevokeRequestRetainsOriginalCallerWithoutRenewingAdmission(t *testing.T) {
	service, get, clock, observed, _, _ := validationFixture(t)
	caller, err := service.Get(context.Background(), get)
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := observed.Session.Bindings()
	b := issueBinding(spec)
	op := session.RevokeOneOperation()
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	command, err := session.NewRevokeOneCommand(b, observed.Session)
	if err != nil {
		t.Fatal(err)
	}
	request, err := service.PrepareRevokeOne(caller, command)
	if err != nil {
		t.Fatal(err)
	}
	projection, ok := request.Command()
	target, targetOK := projection.RevokeOne()
	if !ok || !targetOK || target.Binding != b || target.Session != caller.Session || request.Caller() != caller.Session || !request.ValidUntil().Equal(caller.ValidUntil()) {
		t.Fatal("original input lost")
	}
	copied := request
	clock.now = clock.now.Add(time.Second)
	if request.Validate(service, clock.now) != nil || copied.Validate(service, clock.now) != nil {
		t.Fatal("valid original admission denied")
	}
	clock.now = caller.ValidUntil()
	if !errors.Is(request.Validate(service, clock.now), session.ErrUnauthenticated) || !errors.Is(copied.Validate(service, clock.now), session.ErrUnauthenticated) {
		t.Fatal("copied admission renewed")
	}
	if _, err := service.PrepareRevokeOne(caller, command); !errors.Is(err, session.ErrUnauthenticated) {
		t.Fatal("expired caller prepared")
	}
	if request.Validate(service, spec.IssuedAt) == nil {
		t.Fatal("backward time accepted")
	}
	for _, v := range []any{request, copied} {
		for _, verb := range []string{"%v", "%#v", "%x"} {
			if got := fmt.Sprintf(verb, v); !strings.Contains(got, "redacted") || strings.Contains(got, string(spec.UserID)) {
				t.Fatal("request exposed")
			}
		}
		if _, err := json.Marshal(v); err == nil {
			t.Fatal("request serialized")
		}
	}
	if _, err := request.MarshalText(); err == nil {
		t.Fatal("request text serialized")
	}
}

func TestRevokeRequestBindsSourceAndIndependentTargetWithoutFreshLogin(t *testing.T) {
	service, get, clock, observed, _, _ := validationFixture(t)
	spec, _ := observed.Session.Bindings()
	policy, err := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: 24 * time.Hour, IdleTTL: 24 * time.Hour, RefreshAfter: 12 * time.Hour, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	spec.Remember = policy
	observed.Session, err = session.NewSession(spec)
	if err != nil {
		t.Fatal(err)
	}
	clock.now = spec.IssuedAt.Add(time.Hour)
	observed.ReadStartedAt, observed.ValidUntil = clock.now, clock.now.Add(20*time.Second)
	caller, err := service.Get(context.Background(), get)
	if err != nil || !caller.Authenticated {
		t.Fatal("nonfresh valid caller missing", err)
	}
	life, _ := caller.Session.Lifetime(clock.now)
	if life.Fresh {
		t.Fatal("fixture still fresh")
	}
	for _, mode := range []string{"sibling", "tenant", "user", "audience", "actor", "actor-kind", "same-id-record"} {
		t.Run(mode, func(t *testing.T) {
			targetSpec := spec
			targetSpec.SessionID = "sibling"
			switch mode {
			case "tenant":
				targetSpec.TenantID = "foreign"
				targetSpec.Authentication.Proof.Tenant = "foreign"
			case "user":
				targetSpec.UserID = "foreign"
				targetSpec.Authentication.Proof.Subject = "foreign"
			case "audience":
				targetSpec.Audience = "foreign"
				targetSpec.Authentication.Proof.Audience = "foreign"
			case "same-id-record":
				targetSpec.SessionID = spec.SessionID
				targetSpec.LastActivityAt = spec.LastActivityAt.Add(time.Second)
			}
			target, err := session.NewSession(targetSpec)
			if err != nil {
				t.Fatal(err)
			}
			b := issueBinding(targetSpec)
			op := session.RevokeOneOperation()
			b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
			if mode == "actor" {
				b.ActorID = "foreign"
			}
			if mode == "actor-kind" {
				b.ActorKind = authorization.SubjectServiceAccount
			}
			command, err := session.NewRevokeOneCommand(b, target)
			if err != nil {
				t.Fatal(err)
			}
			request, err := service.PrepareRevokeOne(caller, command)
			if mode != "sibling" {
				if err == nil {
					t.Fatal("cross-scope target admitted")
				}
				return
			}
			if err != nil || request.Validate(service, clock.now) != nil || request.Caller() != caller.Session {
				t.Fatal("independent target lost source", err)
			}
			projected, _ := request.Command()
			retained, _ := projected.RevokeOne()
			if retained.Session != target || retained.Session == request.Caller() {
				t.Fatal("source substituted for target")
			}
		})
	}
	clock.panicNow = true
	b := issueBinding(spec)
	op := session.RevokeOneOperation()
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	command, _ := session.NewRevokeOneCommand(b, observed.Session)
	if _, err := service.PrepareRevokeOne(caller, command); !errors.Is(err, session.ErrUnavailable) {
		t.Fatal("clock panic escaped", err)
	}
}

func TestRevokeRequestRejectsForgedOrForeignComposition(t *testing.T) {
	service, get, clock, observed, config, reader := validationFixture(t)
	caller, _ := service.Get(context.Background(), get)
	spec, _ := observed.Session.Bindings()
	b := issueBinding(spec)
	op := session.RevokeOneOperation()
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	command, _ := session.NewRevokeOneCommand(b, observed.Session)
	foreign, _ := session.NewSessionService(reader, config)
	request, _ := service.PrepareRevokeOne(caller, command)
	if request.Validate(foreign, clock.now) == nil || request.Validate(nil, clock.now) == nil {
		t.Fatal("foreign expected composition accepted")
	}
	if _, err := foreign.PrepareRevokeOne(caller, command); err == nil {
		t.Fatal("foreign preparation accepted")
	}
	for _, forged := range []session.GetResult{{}, {Authenticated: true, Session: caller.Session}, {Authenticated: true, Session: caller.Session, NeedsRefresh: caller.NeedsRefresh, RefreshEligibleAt: caller.RefreshEligibleAt}} {
		if _, err := service.PrepareRevokeOne(forged, command); err == nil {
			t.Fatal("public reconstruction admitted")
		}
	}
	mutated := caller
	mutated.NeedsRefresh = !caller.NeedsRefresh
	if _, err := service.PrepareRevokeOne(mutated, command); err == nil {
		t.Fatal("substituted caller admitted")
	}
	if _, err := service.PrepareRevokeOne(caller, session.SessionCommand{}); err == nil {
		t.Fatal("zero command admitted")
	}
	if (session.RevokeOneRequest{}).Validate(service, clock.now) == nil {
		t.Fatal("zero request admitted")
	}
	if _, ok := (session.RevokeOneRequest{}).Command(); ok {
		t.Fatal("zero command projection")
	}
	if (session.RevokeOneRequest{}).Caller() != (session.Session{}) || !(session.RevokeOneRequest{}).ValidUntil().IsZero() {
		t.Fatal("zero request carries admission")
	}
	var nilService *session.SessionService
	if _, err := nilService.PrepareRevokeOne(caller, command); err == nil {
		t.Fatal("nil service admitted")
	}
}
