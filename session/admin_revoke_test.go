package session_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func TestAdminSessionRevokeCustodyBindsAdministratorAndDistinctTarget(t *testing.T) {
	service, request, clock, observed, config, reader := validationFixture(t)
	spec, primary, factor := mfaMagicLinkSession(t)
	base, _ := observed.Session.Bindings()
	spec.Lookup = base.Lookup
	spec.Authentication = base.Authentication
	proof, _ := primary.Bindings()
	spec.Authentication.Proof.Purpose = "identity.password.mfa-primary"
	spec.Authentication.Proof.ID = auth.ProofID(factor.PrimaryCommandID)
	spec.Authentication.Proof.IssuedAt = proof.AuthenticatedAt
	spec.Authentication.Proof.ExpiresAt = proof.ValidUntil
	mfa, err := session.NewMFAAuthentication(factor)
	if err != nil {
		t.Fatal(err)
	}
	key, err := session.NewCSRFKey(1, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	token, err := session.NewCSRFToken()
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := token.Digest(key, session.CSRFBinding{TenantID: spec.TenantID, SessionID: spec.SessionID, SessionVersion: spec.Version})
	if err != nil {
		t.Fatal(err)
	}
	observed.Session, err = session.NewSessionWithPasswordMFAAndCSRF(spec, mfa, csrf)
	if err != nil {
		t.Fatal(err)
	}
	observed.Current = spec.Authority
	caller, err := service.Get(context.Background(), request)
	if err != nil || !caller.Authenticated {
		t.Fatal("positive password/TOTP admission missing", err)
	}
	command := issueBinding(spec)
	command.OperationID = "identity.admin.session-revoke"
	command.SchemaID = "session-admin-revoke-one"
	command.UserID = "target-user"
	command.RecordID = "target-session"
	prepared, err := service.PrepareAdminSessionRevoke(caller, command, token, key)
	if err != nil {
		t.Fatal("an administrator must be able to target another user", err)
	}
	bound, ok := prepared.Binding()
	if !ok || bound != command || prepared.Caller() != caller.Session || !prepared.ValidUntil().Equal(caller.ValidUntil()) {
		t.Fatal("actor, target, or original observation cutoff was lost")
	}
	if _, err := json.Marshal(prepared); err == nil {
		t.Fatal("private authority custody serialized")
	}
	foreign, err := session.NewSessionService(reader, config)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Validate(foreign, clock.now) == nil {
		t.Fatal("foreign observation owner accepted")
	}
	for _, change := range []func(){
		func() { command.ActorID = "spoofed-actor" },
		func() { command.OperationID = "identity.session.revoke-one" },
		func() { command.TenantID = "foreign-tenant" },
		func() { caller = session.GetResult{Authenticated: true, Session: caller.Session} },
	} {
		originalCommand, originalCaller := command, caller
		change()
		if _, err := service.PrepareAdminSessionRevoke(caller, command, token, key); err == nil {
			t.Fatal("misbound request admitted")
		}
		command, caller = originalCommand, originalCaller
	}
	if _, err := service.PrepareAdminSessionRevoke(caller, command, session.CSRFToken{}, key); !errors.Is(err, session.ErrCSRFDenied) {
		t.Fatal("missing original synchronizer admitted", err)
	}
	t.Run("exact policy then admission then execution", func(t *testing.T) {
		var authorized, admitted, executed int
		policy := adminRevokePolicy(func(_ context.Context, d authorization.DecisionContext) (authorization.Decision, error) {
			if d.Request.Subject.ID != "user-a" || d.Request.Resource.ID != "target-user" || d.Request.Resource.Type != "identity.user" || d.Request.Action != "identity.admin.session-revoke" || d.PolicyRevision != 1 {
				t.Fatal("policy received the wrong actor, target or operation")
			}
			authorized++
			return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
		})
		writer := adminRevokeWriter(func(_ context.Context, r session.AdminSessionRevocation) (session.AdminSessionRevokeResult, error) {
			executed++
			b, ok := r.Binding()
			if authorized != 1 || admitted != 1 || !ok || b != command || r.Validate(service, clock.now) != nil {
				t.Fatal("writer entered without the admitted original command")
			}
			return session.AdminSessionRevokeResult{Revoked: true, Version: 2}, nil
		})
		admin, err := session.NewAdminRevokeService(service, writer, session.AdminRevokeConfig{Authorization: policy, PolicyID: command.PolicyID, PolicyRevision: 1, CSRFKey: key, MaximumDuration: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		r := session.AdminSessionRevokeRequest{TenantID: command.TenantID, TargetSubjectID: "target-user", SessionID: command.RecordID, CommandID: command.CommandID, CorrelationID: command.CorrelationID, Credential: request.Credential, CSRF: token}
		got, err := admin.AdminSessionRevokeWithAdmission(context.Background(), r, func(_ context.Context, actor identity.UserID) error {
			if actor != "user-a" || authorized != 1 || executed != 0 {
				t.Fatal("admission ran out of order or for the wrong actor")
			}
			admitted++
			return nil
		})
		if err != nil || !got.Revoked || got.Version != 2 || executed != 1 {
			t.Fatal("correctly authorized command did not execute exactly once", err)
		}
		r.ActorID = "spoofed-actor"
		if _, err := admin.AdminSessionRevoke(context.Background(), r); err == nil || authorized != 1 || executed != 1 {
			t.Fatal("spoofing reached policy or execution", err)
		}
		r.ActorID = "user-a"
		deny := adminRevokePolicy(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
			return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, nil
		})
		admin, err = session.NewAdminRevokeService(service, writer, session.AdminRevokeConfig{Authorization: deny, PolicyID: command.PolicyID, PolicyRevision: 1, CSRFKey: key, MaximumDuration: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := admin.AdminSessionRevokeWithAdmission(context.Background(), r, func(context.Context, identity.UserID) error {
			t.Fatal("denied target reached quota admission")
			return nil
		}); err == nil || executed != 1 {
			t.Fatal("denied target reached execution", err)
		}
	})
	clock.now = caller.ValidUntil()
	if prepared.Validate(service, clock.now) == nil {
		t.Fatal("original exclusive deadline accepted")
	}
}

type adminRevokeWriter func(context.Context, session.AdminSessionRevocation) (session.AdminSessionRevokeResult, error)

func (f adminRevokeWriter) ExecuteAdminSessionRevoke(ctx context.Context, r session.AdminSessionRevocation) (session.AdminSessionRevokeResult, error) {
	return f(ctx, r)
}

type adminRevokePolicy func(context.Context, authorization.DecisionContext) (authorization.Decision, error)

func (f adminRevokePolicy) Decide(ctx context.Context, d authorization.DecisionContext) (authorization.Decision, error) {
	return f(ctx, d)
}
