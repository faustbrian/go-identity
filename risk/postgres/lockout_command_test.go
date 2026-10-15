package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
)

type lockoutTestPolicy struct{ deny bool }

type nilLockoutPolicy map[string]bool

func (nilLockoutPolicy) Decide(_ context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
	return authorization.Decision{Outcome: authorization.Allow, Revision: dc.PolicyRevision}, nil
}

func TestLockoutConfigurationRejectsTypedNilPolicy(t *testing.T) {
	c := lockoutMutationConfig(t)
	c.LockoutMutations.Authorization = nilLockoutPolicy(nil)
	if _, err := NewRepository(c); err == nil {
		t.Fatal("typed-nil authorization dependency accepted")
	}
}

func (p lockoutTestPolicy) Decide(_ context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
	if p.deny {
		return authorization.Decision{Outcome: authorization.Deny, Revision: dc.PolicyRevision}, nil
	}
	return authorization.Decision{Outcome: authorization.Allow, Revision: dc.PolicyRevision}, nil
}

func lockoutMutationConfig(t *testing.T) Config {
	t.Helper()
	c := protectedConfig(t)
	c.EnforceLockouts = true
	c.LockoutMutations = &LockoutMutationConfig{Authorization: lockoutTestPolicy{}, PolicyID: "risk-policy", PolicyRevision: 9, AuthorityNamespace: "identity-admin", MaximumLockoutDuration: time.Hour, AdmissionTTL: 10 * time.Second, MaximumDuration: time.Second, SigningKeys: map[uint32][32]byte{1: {1}}, CurrentSigningKeyVersion: 1}
	return c
}

func lockoutInput(t *testing.T, mode risk.LockoutMode, version uint64) LockoutCommandRequest {
	t.Helper()
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	op := LockoutOperation(mode)
	b := identity.CommandBinding{CommandID: id, TenantID: "native-lockout", UserID: "subject", ActorID: "administrator", ActorKind: authorization.SubjectUser, RecordID: string(id), OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: "risk-policy", PolicyVersion: 3, CorrelationID: string(id)}
	dc := authorization.DecisionContext{PolicyRevision: 9, CorrelationID: b.CorrelationID, Request: authorization.Request{Tenant: "native-lockout", Action: authorization.Action(op.OperationID), Subject: authorization.Subject{ID: "administrator", Kind: authorization.SubjectUser}, Resource: authorization.Resource{Type: "identity.user", ID: "subject"}}}
	// Match the counter-only protected integration profile. Lockout digests bind
	// the concrete operation as well as its CredentialMutation policy class.
	r := LockoutCommandRequest{Binding: b, Scope: dc, Request: risk.LockoutRequest{Scope: risk.Context{Tenant: "native-lockout", Operation: "identity.username.update", Attempt: string(id)}, Subject: risk.Subject{User: "subject", Session: "session", Network: "2001:db8::1"}, Actor: "administrator", Mode: mode, ExpectedVersion: version}, AuthorityVersion: 1}
	if mode == risk.StartLockout {
		r.Request.Duration = time.Minute
	}
	return r
}

func TestLockoutCommandRequiresCurrentPolicyAndAuthenticatesEveryField(t *testing.T) {
	r, err := NewRepository(lockoutMutationConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	in := lockoutInput(t, risk.StartLockout, 0)
	at := time.Now().UTC().Truncate(time.Microsecond)
	c, err := r.PrepareLockoutCommand(context.Background(), in, at)
	if err != nil {
		t.Fatal(err)
	}
	s, ok := c.Feature()
	if !ok || s.Operation != LockoutOperation(risk.StartLockout) {
		t.Fatal("native lockout command missing")
	}
	if _, err := r.restoreLockout(c); err != nil {
		t.Fatal(err)
	}
	for i := range s.Fields {
		changed, _ := c.Feature()
		f := &changed.Fields[i]
		switch f.Value.Kind {
		case identity.FeatureText:
			f.Value.Text += "x"
		case identity.FeatureBytes:
			f.Value.Bytes[0] ^= 1
		case identity.FeatureUint64:
			f.Value.Uint64++
		case identity.FeatureTime:
			f.Value.Time = f.Value.Time.Add(time.Microsecond)
		}
		forged, e := identity.NewFeatureCommand(changed)
		if e == nil {
			if _, e = r.restoreLockout(forged); e == nil {
				t.Fatal("forged field accepted", f.Name)
			}
		}
	}
	bad := in
	bad.Scope.Request.Subject.ID = "other-admin"
	if _, err = r.PrepareLockoutCommand(context.Background(), bad, at); err == nil {
		t.Fatal("foreign actor admitted")
	}
	bad = in
	bad.Request.Scope.Operation = "identity.mfa.recovery-use"
	if _, err = r.PrepareLockoutCommand(context.Background(), bad, at); err == nil {
		t.Fatal("recovery route restricted")
	}
	deny := lockoutMutationConfig(t)
	deny.LockoutMutations.Authorization = lockoutTestPolicy{deny: true}
	d, _ := NewRepository(deny)
	if _, err = d.PrepareLockoutCommand(context.Background(), in, at); !errors.As(err, new(identity.ForbiddenError)) {
		t.Fatal("policy denial lost", err)
	}
	if _, err := r.ApplyFeature(context.Background(), identitypostgres.Work{}, c); err == nil {
		t.Fatal("unowned Work granted mutation")
	}
}
